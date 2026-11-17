# Testing

## Static checks

Every PHP file must lint cleanly:

```bash
find . -name '*.php' -not -path './.git/*' -exec php -l {} \;
```

The tree must also keep the layout YOURLS actually loads. YOURLS only reads
`user/plugins/<folder>/plugin.php` (`yourls_get_plugins()` keeps one entry per folder and only for
`plugin.php`, and `yourls_is_a_plugin_file()` rejects every other file name), so a package with a
second `Plugin Name:` header, or with the main file under another name, silently stops appearing in
`/admin/plugins.php`. `tests/validate-plugin-layout.php` guards that, together with the release
metadata:

```bash
php tests/validate-plugin-layout.php                                    # repository tree
php tests/validate-plugin-layout.php /path/to/icc-openid-connect-client # extracted package
```

It fails when:

| Check | Why it matters |
| --- | --- |
| `plugin.php` is missing, or has no `Plugin Name:` / `Version:` header | YOURLS would not list or load the plugin |
| another PHP file declares a `Plugin Name:` header | it is a file YOURLS never loads (a template or a file copied from the WordPress plugin) and it hides the real plugin in tooling that scans headers |
| the `Version:` header, `ICC_OIDC_VERSION` and `manifest.json` disagree | a release bumped in only some files reports the wrong version in `/admin/plugins.php` and in the ZIP name |
| `Requires PHP:`, `ICC_OIDC_MIN_PHP` and `composer.json` disagree | the runtime check in `plugin.php` would disable the plugin on a PHP version the metadata allows (or the opposite) |

`.github/workflows/tests.yml` runs it on PHP 8.2, 8.3 and 8.4 for every push and pull request, and
`build.yml` / `yourls-deploy.yml` run it (after `php -l` and the security script) before creating the
release ZIP, so a tag packaged months later either passes today's checks or fails the job.

## Automated tests

The plugin has no Composer or PHPUnit dependency: everything it needs at runtime is YOURLS itself.
The security sensitive part of the login flow is covered by a single self contained script that runs
offline.

```bash
php tests/security-login-flow.php
```

The script exits with `0` when every check passes and `1` otherwise, so it fits
any CI. [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) runs it on
PHP 8.2, 8.3 and 8.4 for every push to `main` and for every pull request, after
linting every PHP file with `php -l`.

`tests/security-login-flow.php` replaces the YOURLS functions the client uses
(`yourls_get_option`, `yourls_update_option`, `yourls_apply_filter`,
`yourls_is_ssl`, `yourls_admin_url`) with in memory doubles. No database, no
network and no YOURLS installation are involved, and nothing is written outside
the process.

### What is covered

| Area | Checks |
| --- | --- |
| Browser bound state | a random `state` is generated; the browser cookie is set when the login starts; only a hash of the browser id reaches the option table; a response delivered to another browser, or to a browser without the cookie, is refused; a refused response does not cancel the attempt (a prefetch or link scanner cannot break a login); a consumed state cannot be replayed |
| State validation | empty, malformed, unknown and expired states are refused; expired entries are removed from the option table |
| PKCE | no `code_challenge` is sent by default; when *Use PKCE* is enabled the challenge is the S256 hash of the stored verifier, the verifier has a valid RFC 7636 length and alphabet, and it is sent to the token endpoint |
| Cookie hardening | no prefix over plain HTTP, `__Host-` prefix over HTTPS, a tampered cookie is refused, a login started over HTTPS cannot be completed over HTTP |
| Legacy attempts | attempts stored before the browser binding existed (no `browser` value) are still accepted |

## Release package

`.github/workflows/yourls-deploy.yml` builds `icc-openid-connect-client.zip` from the release tag,
stamps the version and fails the job when the stamped tree does not pass `php -l`, the layout guard
or the security script. To inspect an asset by hand:

```bash
# The archive root must be the plugin folder and the main file must be plugin.php.
unzip -l icc-openid-connect-client.zip | head

# The packaged header must carry the release version, like manifest.json.
unzip -p icc-openid-connect-client.zip icc-openid-connect-client/plugin.php | grep -E '^(Version|Requires PHP):'
unzip -p icc-openid-connect-client.zip icc-openid-connect-client/manifest.json
```

No `.github/`, `docker/`, `docs/`, `plans/`, `tests/`, `README.md` or `LICENSE` entry may be inside the archive
(the workflow checks that too), and extracting it into `user/plugins` must leave
`user/plugins/icc-openid-connect-client/plugin.php`, so `/admin/plugins.php` lists
*ICC OpenID Connect Client* and activation succeeds.

## Manual verification

The pieces a script cannot reach are the browser side of the cookie and the
provider side of PKCE. Both take a minute to check on a staging install.

1. **Browser binding** — start a login in browser A, copy the callback URL the
   provider returns to (it contains `state=...`) and open it in browser B, where
   the plugin cookie does not exist. Browser B must get *This login attempt was
   started in another browser*, and browser A must still be able to finish its own
   login with a fresh attempt.
2. **Single use** — finish a login, then reload the callback URL from the browser
   history: it must be refused with *Unknown authentication state*.
3. **Expiry** — leave the provider login screen open for longer than the
   *Authentication state time limit* (180 seconds by default), then continue: the
   callback must be refused with *The authentication attempt expired*.
4. **PKCE** — enable *Use PKCE*, save, log in and confirm the provider accepts the
   exchange (Keycloak: *Advanced settings → Proof Key for Code Exchange Code
   Challenge Method: S256*; Entra ID, Google and Auth0 accept it by default). The
   callback URL must carry `code_challenge=...&code_challenge_method=S256`.
5. **Cookies behind a proxy** — when YOURLS runs behind a reverse proxy or a TLS
   terminating load balancer, confirm the site URL uses `https`. On HTTPS the
   cookie is named `__Host-icc_oidc_browser`; a login started over HTTPS cannot be
   completed over HTTP, which is intended: the site must not change scheme between
   the login form and the callback.
6. **Debug log** — with *Enable debug log* on, the plugin page logs
   `Login attempt stored without a browser binding` when the response headers were
   already sent and the cookie could not be set (for example a theme that prints
   output before the plugin runs). The login still works, without the binding.
