<?php
/**
 * Security regression tests for the OpenID Connect login flow.
 *
 * Covers what was backported from oidc-wp/openid-connect-generic 3.11.4:
 *  - the state is bound to the browser that started the login;
 *  - the state stays single use and time limited;
 *  - PKCE (S256) is generated, sent and exchanged;
 *  - the browser binding degrades gracefully when no cookie can be set.
 *
 * No framework, no network and no database: the YOURLS functions used by the
 * plugin are replaced by in memory test doubles.
 *
 * Usage: php tests/security-login-flow.php
 *
 * @package   ICC_OpenID_Client
 * @category  Tests
 * @author    Ivan Carlos
 * @license   MIT
 */

// Progress output must not mark the headers as sent.
ob_start();

define('YOURLS_ABSPATH', dirname(__DIR__) . '/');
define('YOURLS_COOKIEKEY', 'test-cookie-key');

$GLOBALS['icc_test_options'] = array();
$GLOBALS['icc_test_failures'] = 0;
$GLOBALS['icc_test_checks'] = 0;

/**
 * Test double: read a stored option.
 *
 * @param string $name    Option name.
 * @param mixed  $default Default value.
 *
 * @return mixed
 */
function yourls_get_option($name, $default = false)
{
    return array_key_exists($name, $GLOBALS['icc_test_options'])
        ? $GLOBALS['icc_test_options'][$name]
        : $default;
}

/**
 * Test double: store an option.
 *
 * @param string $name  Option name.
 * @param mixed  $value Value.
 *
 * @return bool
 */
function yourls_update_option($name, $value)
{
    $GLOBALS['icc_test_options'][$name] = $value;

    return true;
}

/**
 * Test double: apply a filter (nothing is hooked in this test).
 *
 * @param string $filter Filter name.
 * @param mixed  $value  Value.
 *
 * @return mixed
 */
function yourls_apply_filter($filter, $value = null)
{
    return $value;
}

/**
 * Test double: whether the site runs over HTTPS ($GLOBALS['icc_test_ssl']).
 *
 * @return bool
 */
function yourls_is_ssl()
{
    return !empty($GLOBALS['icc_test_ssl']);
}

/**
 * Test double: admin URL.
 *
 * @param string $path Path.
 *
 * @return string
 */
function yourls_admin_url($path = '')
{
    return 'https://sho.rt/admin/' . ltrim((string) $path, '/');
}

require_once dirname(__DIR__) . '/includes/functions-icc-openid-client.php';
require_once dirname(__DIR__) . '/includes/class-icc-openid-client-http.php';
require_once dirname(__DIR__) . '/includes/class-icc-openid-client-client.php';

/**
 * Record one assertion.
 *
 * @param string $label     What is being checked.
 * @param bool   $condition Result.
 *
 * @return void
 */
function icc_check($label, $condition)
{
    $GLOBALS['icc_test_checks']++;

    if ($condition) {
        echo '  ok   ' . $label . PHP_EOL;

        return;
    }

    $GLOBALS['icc_test_failures']++;
    echo '  FAIL ' . $label . PHP_EOL;
}

/**
 * Assert that a callable throws a given error code.
 *
 * @param string   $label    What is being checked.
 * @param callable $callable Call under test.
 * @param string   $code     Expected error code.
 *
 * @return void
 */
function icc_check_error($label, $callable, $code)
{
    try {
        $callable();
    } catch (ICC_OpenID_Client_Error $error) {
        icc_check($label . ' (' . $error->error_code() . ')', $error->error_code() === $code);

        return;
    }

    icc_check($label . ' (no error thrown)', false);
}

/**
 * PKCE S256 challenge, computed independently from the plugin code.
 *
 * @param string $verifier Code verifier.
 *
 * @return string
 */
function icc_expected_challenge($verifier)
{
    return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
}

/**
 * Base settings shared by the tests.
 *
 * @param array $overrides Values to override.
 *
 * @return array
 */
function icc_settings(array $overrides = array())
{
    return array_merge(array(
        'client_id'      => 'test-client',
        'client_secret'  => 'test-secret',
        'endpoint_login' => 'https://idp.example.com/authorize',
        'endpoint_token' => 'https://idp.example.com/token',
        'redirect_uri'   => 'https://sho.rt/admin/index.php?icc_oidc=callback',
    ), $overrides);
}

/**
 * Reset the simulated browser and the stored login attempts.
 *
 * @return void
 */
function icc_reset()
{
    $_COOKIE = array();
    $GLOBALS['icc_test_options'] = array();
    $GLOBALS['icc_test_ssl'] = false;
}

echo 'Security regression tests: login flow' . PHP_EOL;

// ---------------------------------------------------------------------------
// 1. The state is tied to the browser that started the login.
// ---------------------------------------------------------------------------
echo PHP_EOL . '1. browser bound state' . PHP_EOL;

icc_reset();

$client = new ICC_OpenID_Client_Client(icc_settings());
$attempt = $client->new_state('https://sho.rt/admin/index.php');
$cookie_name = $client->browser_cookie_name();
$stored = yourls_get_option(ICC_OpenID_Client_Client::STATE_OPTION);

icc_check('a state is generated', preg_match('/^[a-f0-9]{32}$/', $attempt['state']) === 1);
icc_check('the browser cookie is set when the login starts', isset($_COOKIE[$cookie_name]));
icc_check('the browser id looks like a random id', preg_match('/^[a-f0-9]{32}$/', (string) $_COOKIE[$cookie_name]) === 1);
icc_check(
    'the cookie value is never stored, only a hash of it',
    isset($stored[$attempt['state']]['browser'])
    && $stored[$attempt['state']]['browser'] !== $_COOKIE[$cookie_name]
    && strlen($stored[$attempt['state']]['browser']) === 64
);

$browser_id = $_COOKIE[$cookie_name];
$other_browser = new ICC_OpenID_Client_Client(icc_settings());

// A different browser answers the callback.
$_COOKIE[$cookie_name] = str_repeat('b', 32);

icc_check_error(
    'a response delivered to another browser is refused',
    function () use ($other_browser, $attempt) {
        $other_browser->consume_state($attempt['state']);
    },
    'state-other-browser'
);

// A browser with no cookie at all answers the callback.
unset($_COOKIE[$cookie_name]);

icc_check_error(
    'a response delivered to a browser without the cookie is refused',
    function () use ($other_browser, $attempt) {
        $other_browser->consume_state($attempt['state']);
    },
    'state-other-browser'
);

// The attempt is still pending for the right browser: a prefetch or a link
// scanner cannot cancel a login.
$_COOKIE[$cookie_name] = $browser_id;
$consumed = $client->consume_state($attempt['state']);

icc_check('the browser that started the login can still use the state', $consumed['nonce'] === $attempt['nonce']);
icc_check('the stored redirect target is returned', $consumed['redirect_to'] === 'https://sho.rt/admin/index.php');

icc_check_error(
    'the state cannot be reused once consumed',
    function () use ($client, $attempt) {
        $client->consume_state($attempt['state']);
    },
    'state-not-found'
);

// ---------------------------------------------------------------------------
// 2. A crafted or stale state is refused.
// ---------------------------------------------------------------------------
echo PHP_EOL . '2. state validation' . PHP_EOL;

icc_check_error(
    'an empty state is refused',
    function () use ($client) {
        $client->consume_state('');
    },
    'missing-authentication-state'
);

icc_check_error(
    'a malformed state is refused',
    function () use ($client) {
        $client->consume_state("' OR 1=1 --");
    },
    'state-not-found'
);

icc_check_error(
    'an unknown state is refused',
    function () use ($client) {
        $client->consume_state(str_repeat('c', 32));
    },
    'state-not-found'
);

yourls_update_option(ICC_OpenID_Client_Client::STATE_OPTION, array(
    str_repeat('d', 32) => array(
        'redirect_to'   => '',
        'nonce'         => 'stale-nonce',
        'time'          => time() - 3600,
        'browser'       => '',
        'code_verifier' => '',
    ),
));

icc_check_error(
    'an expired state is refused',
    function () use ($client) {
        $client->consume_state(str_repeat('d', 32));
    },
    'state-expired'
);

$remaining = yourls_get_option(ICC_OpenID_Client_Client::STATE_OPTION);

icc_check('an expired state is dropped from the storage', !isset($remaining[str_repeat('d', 32)]));

// ---------------------------------------------------------------------------
// 3. PKCE is off by default and works when enabled.
// ---------------------------------------------------------------------------
echo PHP_EOL . '3. PKCE' . PHP_EOL;

icc_reset();

$client = new ICC_OpenID_Client_Client(icc_settings());
$attempt = $client->new_state();
$url = $client->get_authentication_url();

icc_check('no code challenge is sent by default', strpos($url, 'code_challenge') === false);
icc_check(
    'the authorization URL still carries state and nonce',
    strpos($url, 'state=') !== false && strpos($url, 'nonce=') !== false
);

$consumed = $client->consume_state($attempt['state']);

icc_check('no code verifier is stored when PKCE is off', $consumed['code_verifier'] === '');

icc_reset();

$pkce_client = new ICC_OpenID_Client_Client(icc_settings(array('enable_pkce' => 1)));
$url = $pkce_client->get_authentication_url();

$query = array();
parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

$state = isset($query['state']) ? (string) $query['state'] : '';
$stored = yourls_get_option(ICC_OpenID_Client_Client::STATE_OPTION);
$stored_verifier = isset($stored[$state]['code_verifier'])
    ? (string) $stored[$state]['code_verifier']
    : '';

icc_check('the authorization URL carries a code challenge', isset($query['code_challenge']) && $query['code_challenge'] !== '');
icc_check('the challenge method is S256', isset($query['code_challenge_method']) && $query['code_challenge_method'] === 'S256');
icc_check('the challenge is the S256 hash of the verifier', $query['code_challenge'] === icc_expected_challenge($stored_verifier));

$consumed = $pkce_client->consume_state($state);
$verifier = $consumed['code_verifier'];

icc_check('the code verifier has a valid PKCE length', strlen($verifier) >= 43 && strlen($verifier) <= 128);
icc_check('the code verifier uses unreserved characters only', preg_match('/^[A-Za-z0-9\-._~]+$/', $verifier) === 1);
icc_check('the code verifier matches the challenge sent', $verifier !== '' && icc_expected_challenge($verifier) === $query['code_challenge']);

// The verifier is sent to the token endpoint.
$sent_body = '';

$token_client = new ICC_OpenID_Client_Client(
    icc_settings(),
    null,
    function ($method, $url, $headers, $data) use (&$sent_body) {
        $sent_body = (string) $data;

        return array('status' => 200, 'body' => '{"access_token":"token","token_type":"Bearer"}', 'headers' => array());
    }
);

$token_client->request_token('authorization-code', $verifier);

icc_check('the code verifier is exchanged at the token endpoint', strpos($sent_body, 'code_verifier=' . $verifier) !== false);

$sent_body = '';
$token_client->request_token('authorization-code');

icc_check('no code verifier is sent when there is none', strpos($sent_body, 'code_verifier') === false);

// ---------------------------------------------------------------------------
// 4. Cookie hardening: __Host- prefix over HTTPS, fail closed on mismatch.
// ---------------------------------------------------------------------------
echo PHP_EOL . '4. cookie hardening' . PHP_EOL;

icc_reset();

$plain_client = new ICC_OpenID_Client_Client(icc_settings());

icc_check('the cookie has no prefix over plain HTTP', $plain_client->browser_cookie_name() === 'icc_oidc_browser');

$GLOBALS['icc_test_ssl'] = true;
$secure_client = new ICC_OpenID_Client_Client(icc_settings());

icc_check('the cookie uses the __Host- prefix over HTTPS', $secure_client->browser_cookie_name() === '__Host-icc_oidc_browser');

$attempt = $secure_client->new_state();

icc_check('the prefixed cookie is the one that gets set', isset($_COOKIE['__Host-icc_oidc_browser']));
icc_check('the attempt is bound to the browser id', yourls_get_option(ICC_OpenID_Client_Client::STATE_OPTION)[$attempt['state']]['browser'] !== '');
icc_check('the browser that started the login can consume the state', $secure_client->consume_state($attempt['state'])['nonce'] === $attempt['nonce']);

// A cookie holding anything but a 128 bit hex id is ignored, not trusted.
$attempt = $secure_client->new_state();
$_COOKIE['__Host-icc_oidc_browser'] = '<script>alert(1)</script>';

icc_check_error(
    'a tampered cookie is refused',
    function () use ($secure_client, $attempt) {
        $secure_client->consume_state($attempt['state']);
    },
    'state-other-browser'
);

// A login started over HTTPS cannot be completed over plain HTTP (different
// cookie name, no shared cookie): the binding fails closed.
$http_client = new ICC_OpenID_Client_Client(icc_settings());
$GLOBALS['icc_test_ssl'] = false;

icc_check_error(
    'a login started over HTTPS cannot be completed over HTTP',
    function () use ($http_client, $attempt) {
        $http_client->consume_state($attempt['state']);
    },
    'state-other-browser'
);

// ---------------------------------------------------------------------------
// 5. An attempt stored before the binding existed still works.
// ---------------------------------------------------------------------------
echo PHP_EOL . '5. legacy attempt' . PHP_EOL;

icc_reset();

yourls_update_option(ICC_OpenID_Client_Client::STATE_OPTION, array(
    str_repeat('e', 32) => array(
        'redirect_to' => '',
        'nonce'       => 'legacy-nonce',
        'time'        => time(),
    ),
));

$legacy_client = new ICC_OpenID_Client_Client(icc_settings());
$consumed = $legacy_client->consume_state(str_repeat('e', 32));

icc_check('an attempt stored without a browser binding is accepted', $consumed['nonce'] === 'legacy-nonce');

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------
$failures = $GLOBALS['icc_test_failures'];
$checks = $GLOBALS['icc_test_checks'];

echo PHP_EOL . sprintf('%d checks, %d failure(s)', $checks, $failures) . PHP_EOL;

ob_end_flush();

exit($failures === 0 ? 0 : 1);

