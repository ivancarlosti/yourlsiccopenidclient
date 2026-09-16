# ICC OpenID Connect Client plugin for YOURLS
Login to YOURLS with Single Sign-On using any OpenID Connect identity provider (Keycloak, Entra ID, Google, Auth0, Okta, ...) through the Authorization Code Flow. Includes a login button on the login screen, automatic SSO redirection, email domain restriction, single logout and a debug log - with no third party libraries bundled.

<!-- buttons -->
[![Stars](https://img.shields.io/github/stars/ivancarlosti/yourlsiccopenidclient?label=⭐%20Stars&color=gold&style=flat)](https://github.com/ivancarlosti/yourlsiccopenidclient/stargazers)
[![Watchers](https://img.shields.io/github/watchers/ivancarlosti/yourlsiccopenidclient?label=Watchers&style=flat&color=red)](https://github.com/sponsors/ivancarlosti)
[![Forks](https://img.shields.io/github/forks/ivancarlosti/yourlsiccopenidclient?label=Forks&style=flat&color=ff69b4)](https://github.com/sponsors/ivancarlosti)
[![Downloads](https://img.shields.io/github/downloads/ivancarlosti/yourlsiccopenidclient/total?label=Downloads&color=success)](https://github.com/ivancarlosti/yourlsiccopenidclient/releases)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ivancarlosti/yourlsiccopenidclient?label=Activity)](https://github.com/ivancarlosti/yourlsiccopenidclient/pulse)
[![GitHub Issues](https://img.shields.io/github/issues/ivancarlosti/yourlsiccopenidclient?label=Issues&color=orange)](https://github.com/ivancarlosti/yourlsiccopenidclient/issues)  
[![License](https://img.shields.io/github/license/ivancarlosti/yourlsiccopenidclient?label=License)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/ivancarlosti/yourlsiccopenidclient?label=Last%20Commit)](https://github.com/ivancarlosti/yourlsiccopenidclient/commits)
[![Security](https://img.shields.io/badge/Security-View%20Here-purple)](https://github.com/ivancarlosti/yourlsiccopenidclient/security)
[![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-2.1-4baaaa)](https://github.com/ivancarlosti/yourlsiccopenidclient?tab=coc-ov-file)
<!-- endbuttons -->

## Features
* OpenID Connect Authorization Code Flow against any compliant provider
* **ID token signature verification** with the provider JWKS (RS256, RS384, RS512, ES256, ES384, ES512) plus `iss`, `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce` and `acr` validation
* Login **button on the YOURLS login screen**, "button only" mode (no password form) or **automatic SSO** redirection
* **Single logout**: the YOURLS logout link also ends the identity provider session (`id_token_hint`, `post_logout_redirect_uri`)
* **Never stuck after a refusal**: when an identity is refused (email domain not allowed, identity not linked to a YOURLS user), the login screen explains why **and offers a link that ends the provider session**, so the visitor can sign in with another account
* **No callback URL to configure**: the plugin uses a URL YOURLS itself serves, so it keeps working when a landing page, a static `index.php` or a parked domain owns the site root - with a built-in **Test callback URL** check
* **Account handling**: signs in as the YOURLS user defined in `user/config.php` (the identity claim is matched against the login name, no account is ever created)
* **Email domain restriction** (domains or full addresses) and configurable claim mapping (identity, nickname, display name, email)
* **Quick Setup**: import every endpoint from the provider discovery document
* **Debug log** with a viewer
* Settings can be overridden with `OIDC_*` constants in `user/config.php`
* No third party libraries: JWT/JWKS validation uses `ext-openssl` only

## Inspiration
* Project inspired by [ICC.gg Sign-In for OpenID Connect](https://github.com/ivancarlosti/wordpressiccopenidclient), the same plugin for WordPress.

## Instructions
* Download the release ZIP `icc-openid-connect-client.zip`
* Extract it into the YOURLS path `/user/plugins` &mdash; the archive unpacks the folder `icc-openid-connect-client` containing `plugin.php`, `manifest.json` and the `includes` folder
* Activate the plugin in `/admin/plugins.php` page of your YOURLS installation
* Access the `OpenID Connect` page from the admin menu
* Paste your provider discovery URL (for example `https://sso.example.com/realms/myrealm/.well-known/openid-configuration`) and click **Load configuration**
* Fill in the Client ID / Client Secret, register the **Redirect URI** and the **Post logout redirect URI** shown in the Notes section at your identity provider and save
* Nothing else has to be configured: the callback URL is a URL YOURLS itself serves (`<your YOURLS admin URL>?icc_oidc=callback`), so it works even when another application (a landing page, a static `index.php`, a parked domain) owns the site root. The **Test callback URL** button in the Notes section sends a forged callback to it and reports what answered. If your YOURLS admin area is protected by extra authentication, define `OIDC_REDIRECT_URI` in `user/config.php` with an alternative URL YOURLS serves.

## Provider setup (Keycloak example)
1. Keycloak admin console &raquo; **Clients** &raquo; **Create client**
    * Client type `OpenID Connect`, Client authentication **On** (confidential client), Standard flow **On**
    * **Valid redirect URIs**: the Redirect URI displayed by the plugin, e.g. `https://sho.rt/admin/index.php?icc_oidc=callback` (a wildcard such as `https://sho.rt/*` works too)
    * **Valid post logout redirect URIs**: the Post logout redirect URI displayed by the plugin, e.g. `https://sho.rt/admin/index.php`
    * Web origins: leave empty
2. Copy the **Client secret** from the *Credentials* tab into the plugin settings
3. Keep the default `email` client scope enabled so the email claim (and the domain restriction) works
4. Discovery URL: `https://sso.example.com/realms/<realm>/.well-known/openid-configuration`
5. Issuer: `https://sso.example.com/realms/<realm>` (the discovery import fills it in)

The same procedure applies to Entra ID, Google, Auth0, Okta and other providers: create a confidential web client, register the redirect URI and paste the discovery URL.


## Settings

### Client Settings
| Setting | Description |
|---|---|
| Login Type | `button` (button on the login form), `button_only` (button only, password form hidden), `auto` (redirect straight to the identity provider) |
| Login Button Text | Text of the SSO button (default *Login with Single Sign-On*) |
| Login Button Logo URL | Optional image displayed before the button text |
| Client ID / Client Secret | Credentials of the confidential client registered at the provider |
| OpenID Scope | Space separated scopes, default `openid profile email` |
| Login / Token / Userinfo / Logout / JWKS Endpoint URL | Endpoints of the provider (filled in by the discovery import) |
| Issuer | Expected `iss` claim; derived from the login endpoint when empty |
| JWKS Cache TTL | How long signing keys are cached (default 3600 seconds) |
| ACR Values | Optional authentication context requested from the provider |
| HTTP Request Timeout | Timeout for provider requests (default 5 seconds) |
| Disable SSL Verify | Development only: ignored unless `YOURLS_DEBUG` is on |
| Allow Internal IdP | Allows HTTP and private network endpoints (local development) |

### User Settings
| Setting | Description |
|---|---|
| Identity Key | Claim matched against the YOURLS login from `user/config.php` (`preferred_username`, `sub`, `email`, or a nested path) |
| Nickname Key | Claim used as the nickname |
| Email Formatting | Claim string used to build the email address, e.g. `{email}` |
| Display Name Formatting | Optional, e.g. `{given_name} {family_name}` |
| Email Domain Restriction | Space separated allowed domains or full addresses; empty allows all |

YOURLS is a single account system, so the plugin never creates users: the OpenID Connect identity is matched to the login name of a user from `user/config.php`, and a single configured user is used when the claim does not match. The last identity used for each user is listed on the plugin page and can be forgotten there (the `config.php` user itself is never changed).

### Authorization Settings
| Setting | Description |
|---|---|
| State Time Limit | Lifetime of a login attempt (default 180 seconds) |
| Redirect Back to Origin Page | Return the user to the page they started from |
| Redirect to IdP on logout | Ends the identity provider session when logging out |

The callback URL is **not** a setting: the plugin always uses a URL served by YOURLS itself (`<your YOURLS admin URL>?icc_oidc=callback`), and the logout URL is derived from it. The Notes section of the plugin page displays both, plus the post logout redirect URI, and offers a **Test callback URL** button that sends a forged callback to the redirect URI to confirm YOURLS answers it. To force another URL (for example when `/admin/` is protected), define the constant below.
| Enable Logging / Log Limit | Keep a debug log (with viewer) and how many entries to keep |

### Configuration constants
Any setting can be forced from `user/config.php` (constant values win over stored settings and are shown read-only in the admin page):

```php
define( 'OIDC_CLIENT_ID', 'yourls' );
define( 'OIDC_CLIENT_SECRET', 'your-client-secret' );
define( 'OIDC_ENDPOINT_LOGIN_URL', 'https://sso.example.com/realms/myrealm/protocol/openid-connect/auth' );
define( 'OIDC_ENDPOINT_TOKEN_URL', 'https://sso.example.com/realms/myrealm/protocol/openid-connect/token' );
define( 'OIDC_ENDPOINT_USERINFO_URL', 'https://sso.example.com/realms/myrealm/protocol/openid-connect/userinfo' );
define( 'OIDC_ENDPOINT_JWKS_URL', 'https://sso.example.com/realms/myrealm/protocol/openid-connect/certs' );
define( 'OIDC_ISSUER', 'https://sso.example.com/realms/myrealm' );
define( 'OIDC_LOGIN_TYPE', 'auto' );
define( 'OIDC_EMAIL_DOMAIN_RESTRICTION', 'example.com partner.org' );
define( 'OIDC_REDIRECT_URI', 'https://sho.rt/yourls-loader.php?icc_oidc=callback' ); // only when the default callback URL cannot be used
```

## How it works
1. The user is sent to the provider authorization endpoint with a random `state` and `nonce` (stored server side, single use, time limited).
2. The provider returns an authorization code to `https://your-yourls/admin/index.php?icc_oidc=callback` (or to `OIDC_REDIRECT_URI` when it is defined), which the plugin handles *before* YOURLS runs its own authentication.
3. The code is exchanged for tokens; the **ID token signature is verified against the provider JWKS** (cached, refreshed on key rotation) and its claims are validated (`iss`, `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce`, `acr`).
4. `userinfo` is requested when configured, and its subject must match the ID token.
5. The identity is mapped to a YOURLS user from `user/config.php`: a known identity reuses its user, otherwise the identity claim is matched against the login name, and a single configured user is used when the claim does not match. No account is ever created, and an unlinked identity is refused when several users exist.
6. YOURLS' own session cookie is stored, so the rest of YOURLS works unchanged.

Plugins can hook into the flow: `icc_oidc_authentication_url_params`, `icc_oidc_login_button_text`, `icc_oidc_logout_link_text`, `icc_oidc_error_needs_logout`, `icc_oidc_user_login_test`, `icc_oidc_redirect_after_login`, `icc_oidc_user_update`, `icc_oidc_update_user_using_current_claim`, `icc_oidc_before_login`, `icc_oidc_user_logged_in`, `icc_oidc_login_error`, `icc_oidc_logout`.

## Notes and limitations
* YOURLS has no user directory and this plugin never creates accounts: Single Sign-On signs in as a user from `user/config.php`, and the identity used for each login is remembered in a plugin option (listed on the plugin page, where it can also be forgotten). Local password login keeps working, which is useful as a recovery path.
* A refused identity is a dead end without a way out: because the visitor would keep coming back from the identity provider as the same account, the login screen shows the reason **and a "Log out of Single Sign-On and use another account" link** (for *email domain not allowed*, *unlinked identity*, *account not allowed* and inconsistent user data). The link ends the provider session, so the next attempt asks for credentials again. It is only shown when a logout endpoint is configured, its text can be changed with the `icc_oidc_logout_link_text` filter, and `icc_oidc_error_needs_logout` can decide when it appears.
* YOURLS' privacy setting (`YOURLS_PRIVATE` in `config.php`) is what forces authentication; the plugin works with it and never disables it.
* Refresh tokens are not used: YOURLS keeps its own session cookie, so the last ID token is stored only to be sent as `id_token_hint` on logout.
* HTTPS is required in production, and the provider endpoints must be reachable over the public internet unless *Allow Internal IdP* is enabled.
* The callback has to be answered by YOURLS itself, which is why the plugin uses a YOURLS served URL by default: a landing page, a parked domain page or a static `index.php` owning the site root would answer the provider response and no login (and no error message) would ever happen. If `/admin/` is protected by extra authentication (web server auth, IP allow list, WAF), define `OIDC_REDIRECT_URI` in `user/config.php` with another URL YOURLS serves (for example `https://sho.rt/yourls-loader.php?icc_oidc=callback`) and register it at the provider.
* The **Notes** section of the plugin page displays the effective **Redirect URI**, the **Logout URL** and the **Post logout redirect URI**, warns when the redirect URI does not point at the YOURLS installation, and offers a **Test callback URL** button that sends a forged callback to the redirect URI and reports whether YOURLS (or something else) answered it.
* A redirect URI stored by version 2.x is **ignored** (only the `OIDC_REDIRECT_URI` constant can change the callback URL): the plugin page reports the leftover value and offers to remove it, so a value pointing at a URL YOURLS does not serve can never silently break the login.

## Upgrading from 2.x
Version 3.0 removes the *Redirect URI Override* setting and uses a YOURLS served callback URL by default (`<your YOURLS admin URL>?icc_oidc=callback`), so no configuration is needed even when another application owns the site root. After upgrading:

1. Open **OpenID Connect** and copy the **Redirect URI** and the **Post logout redirect URI** from the Notes section.
2. Register both at your identity provider (the previous `https://your-yourls/?icc_oidc=callback` no longer has to be registered; keeping it is harmless).
3. Click **Test callback URL** to confirm YOURLS answers the new URL, then log in once.
4. Any redirect URI value left behind by version 2.x is ignored; the plugin page reports it and the button **Remove the leftover redirect URI** deletes it.
5. If your YOURLS admin area is protected by extra authentication, define `OIDC_REDIRECT_URI` (see above) and register that URL instead.

## Requirements
* YOURLS 1.8.2+ (tested with YOURLS 1.10.x)
* PHP 7.4+ with `ext-openssl`
* HTTPS in production

## Screenshots

<img width="2036" height="1978" alt="Settings page" src="https://github.com/user-attachments/assets/1c7b614a-abdf-4578-9919-2e0c93b4031e" />

<!-- footer -->
---

## 🧑‍💻 Consulting and technical support
* For personal support and queries, please submit a new issue to have it addressed.
* For commercial related questions, please [**contact me**][ivancarlos] for consulting costs.

[cc]: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project
[contributing]: https://docs.github.com/en/articles/setting-guidelines-for-repository-contributors
[security]: https://github.com/ivancarlosti/yourlsiccopenidclient/security
[support]: https://github.com/ivancarlosti/yourlsiccopenidclient/issues
[it]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository#configuring-the-template-chooser
[prt]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository
[funding]: https://github.com/sponsors/ivancarlosti
[ivancarlos]: https://ivancarlos.me

