#!/bin/bash
#
# End to end test: real YOURLS + MariaDB + a mock OpenID Connect provider (RS256).
#
# Requirements: docker, php (CLI), curl, tar.
#
#     bash tests/e2e/run.sh
#
# The script downloads YOURLS into a temporary directory, installs this plugin
# into it, and drives a full Single Sign-On login over HTTP. Containers are
# removed at the end.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK="${TMPDIR:-/tmp}/icc-oidc-e2e"
APP="${WORK}/app"
YOURLS_VERSION="${YOURLS_VERSION:-1.10.6}"
DB_PORT=33067
WEB_PORT=8088
IDP_PORT=8089

PASS=0
FAIL=0

ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

check() {
    if printf '%s' "$2" | grep -q -- "$3"; then
        ok "$1"
    else
        bad "$1"
        echo "       expected: $3"
        echo "       actual:   $(printf '%s' "$2" | head -c 300)"
    fi
}

cleanup() {
    kill "${IDP_PID:-0}" >/dev/null 2>&1
    docker rm -f icc-yo-web icc-yo-db >/dev/null 2>&1
}

trap cleanup EXIT

echo "ICC OpenID Connect Client - end to end test (YOURLS ${YOURLS_VERSION})"
echo "--------------------------------------------------------------------"

# --- Workspace ---------------------------------------------------------------
rm -rf "${WORK}"
mkdir -p "${WORK}" "${WORK}/idp"

curl -sSL --max-time 180 "https://github.com/YOURLS/YOURLS/archive/refs/tags/${YOURLS_VERSION}.tar.gz" -o "${WORK}/yourls.tar.gz"
tar xzf "${WORK}/yourls.tar.gz" -C "${WORK}"
mv "${WORK}/YOURLS-${YOURLS_VERSION}" "${APP}"

mkdir -p "${APP}/user/plugins/icc-openid-client"
cp "${REPO_DIR}/plugin.php" "${REPO_DIR}/manifest.json" "${APP}/user/plugins/icc-openid-client/"
cp -r "${REPO_DIR}/includes" "${APP}/user/plugins/icc-openid-client/"

cat > "${APP}/user/config.php" <<'PHP'
<?php
define( 'YOURLS_DB_USER', 'yourls' );
define( 'YOURLS_DB_PASS', 'yourls' );
define( 'YOURLS_DB_NAME', 'yourls' );
define( 'YOURLS_DB_HOST', '127.0.0.1:33067' );
define( 'YOURLS_DB_PREFIX', 'yourls_' );
define( 'YOURLS_SITE', 'http://127.0.0.1:8088' );
define( 'YOURLS_HOURS_OFFSET', 0 );
define( 'YOURLS_LANG', '' );
define( 'YOURLS_UNIQUE_URLS', true );
define( 'YOURLS_PRIVATE', true );
define( 'YOURLS_COOKIEKEY', 'e2e-test-cookie-key-0123456789abcdef' );
$yourls_user_passwords = array( 'admin' => 'adminpass' );
define( 'YOURLS_DEBUG', false );
define( 'YOURLS_URL_CONVERT', 64 );
$yourls_reserved_URL = array( 'porn', 'sex', 'fuck' );
PHP

# --- PHP image with pdo_mysql ------------------------------------------------
if ! docker image inspect icc-yourls-php >/dev/null 2>&1; then
    docker build -t icc-yourls-php "${SCRIPT_DIR}" > "${WORK}/build.log" 2>&1 \
        || { bad 'could not build the PHP image'; tail -5 "${WORK}/build.log"; exit 1; }
fi

# --- MariaDB -----------------------------------------------------------------
docker run -d --name icc-yo-db -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=yourls \
    -e MARIADB_USER=yourls -e MARIADB_PASSWORD=yourls -p "127.0.0.1:${DB_PORT}:3306" mariadb:11 >/dev/null

for i in $(seq 1 60); do
    docker exec icc-yo-db mariadb -uyourls -pyourls -e 'SELECT 1' yourls >/dev/null 2>&1 && break
    sleep 1
done

if docker exec icc-yo-db mariadb -uyourls -pyourls -e 'SELECT 1' yourls >/dev/null 2>&1; then
    ok 'MariaDB ready'
else
    bad 'MariaDB did not start'
    exit 1
fi

# --- Mock identity provider --------------------------------------------------
rm -f "${WORK}/idp/key.pem" "${WORK}/idp/jwks.json" "${WORK}/idp/nonce.txt"
YOURLS_APP_DIR="${APP}" IDP_WORK_DIR="${WORK}/idp" php -S "127.0.0.1:${IDP_PORT}" "${SCRIPT_DIR}/idp-router.php" > "${WORK}/idp.log" 2>&1 &
IDP_PID=$!
sleep 1

check 'mock IdP serves a discovery document' \
    "$(curl -s "http://127.0.0.1:${IDP_PORT}/realms/mock/.well-known/openid-configuration")" \
    'authorization_endpoint'

# --- YOURLS bootstrap and configuration --------------------------------------
BOOT=$(docker run --rm --network host -e YOURLS_APP_DIR=/app -v "${APP}:/app" -v "${SCRIPT_DIR}:/io" \
    icc-yourls-php php /io/yourls-cli.php setup 2>&1)
check 'YOURLS tables created and plugin configured' "${BOOT}" 'plugin configured'

# --- Web server --------------------------------------------------------------
docker run -d --name icc-yo-web --network host -e YOURLS_APP_DIR=/app -v "${APP}:/app" -v "${SCRIPT_DIR}:/io" \
    -w /app icc-yourls-php php -S "127.0.0.1:${WEB_PORT}" /io/yourls-router.php >/dev/null

for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${WEB_PORT}/admin/index.php" 2>/dev/null)
    [ "${code}" != '000' ] && break
    sleep 1
done

cli() {
    docker run --rm --network host -e YOURLS_APP_DIR=/app -v "${APP}:/app" -v "${SCRIPT_DIR}:/io" \
        icc-yourls-php php /io/yourls-cli.php "$@" 2>&1
}

# --- 1. Login screen shows the SSO button ------------------------------------
cli option icc_oidc_login_type button >/dev/null
LOGIN=$(curl -s -c "${WORK}/c1.txt" "http://127.0.0.1:${WEB_PORT}/admin/index.php")
check 'login page renders the SSO button' "${LOGIN}" 'icc-oidc-login-button'
check 'SSO button links to the provider' "${LOGIN}" 'response_type=code'
check 'redirect URI points at the YOURLS callback' "${LOGIN}" 'icc_oidc%3Dcallback'

# --- 2. Full authorization code flow -----------------------------------------
cli option icc_oidc_login_type auto >/dev/null
rm -f "${WORK}/c2.txt"

FIRST=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -c "${WORK}/c2.txt" \
    "http://127.0.0.1:${WEB_PORT}/admin/index.php")
check 'unauthenticated admin request is redirected to the provider' "${FIRST}" \
    "302 http://127.0.0.1:${IDP_PORT}/realms/mock/protocol/openid-connect/auth"

FINAL=$(curl -s -L -c "${WORK}/c2.txt" -b "${WORK}/c2.txt" -o "${WORK}/admin.html" \
    -w '%{http_code} %{url_effective}' "http://127.0.0.1:${WEB_PORT}/admin/index.php")
check 'authorization code flow lands back on the admin page' "${FINAL}" \
    "200 http://127.0.0.1:${WEB_PORT}/admin/index.php"

if grep -q 'Logout' "${WORK}/admin.html"; then
    ok 'admin interface shows an authenticated session'
else
    bad 'admin interface is not authenticated'
fi

if grep -q 'yourls_' "${WORK}/c2.txt"; then
    ok 'YOURLS session cookie was stored'
else
    bad 'no YOURLS session cookie'
fi

STORE=$(cli show)
check 'SSO account provisioned from the claims' "${STORE}" '"ssouser"'
check 'subject, email and display name stored' "${STORE}" '"email":"ssouser@example.com"'
check 'successful login written to the debug log' "${STORE}" 'login-success'

# --- 3. Second login with the same identity ----------------------------------
SECOND=$(curl -s -L -c "${WORK}/c3.txt" -b "${WORK}/c3.txt" -o "${WORK}/admin2.html" \
    -w '%{http_code}' "http://127.0.0.1:${WEB_PORT}/admin/index.php")
check 'second login reuses the provisioned account' "${SECOND}" '200'
check 'still a single SSO account' "$(cli show | grep -c '"subject":"mock-user-1"')" '1'

# --- 4. Tampered state is rejected -------------------------------------------
check 'forged state is rejected' \
    "$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:${WEB_PORT}/?icc_oidc=callback&code=whatever&state=forged")" \
    'icc_oidc_error=state-not-found'

check 'login page shows a friendly error message' \
    "$(curl -s "http://127.0.0.1:${WEB_PORT}/admin/index.php?icc_oidc_error=state-not-found")" \
    'no longer valid'

# --- 5. Logout ends the IdP session ------------------------------------------
LOGOUT=$(curl -s -o /dev/null -w '%{redirect_url}' -b "${WORK}/c2.txt" "http://127.0.0.1:${WEB_PORT}/?icc_oidc=logout")
check 'logout redirects to the provider end session endpoint' "${LOGOUT}" 'protocol/openid-connect/logout'
check 'logout sends id_token_hint' "${LOGOUT}" 'id_token_hint='

# --- 6. Settings page --------------------------------------------------------
SETTINGS=$(curl -s -b "${WORK}/c2.txt" "http://127.0.0.1:${WEB_PORT}/admin/plugins.php?page=icc_openid_client")
check 'settings page renders' "${SETTINGS}" 'Client Settings'
check 'settings page lists the provisioned SSO user' "${SETTINGS}" 'ssouser'

# --- Summary -----------------------------------------------------------------
echo '--------------------------------------------------------------------'
echo "E2E result: ${PASS} passed, ${FAIL} failed"

exit $([ "${FAIL}" -eq 0 ] && echo 0 || echo 1)
