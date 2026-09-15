<?php
/**
 * Authentication flow: callback handling, login, logout and auto SSO.
 *
 * @package   ICC_OpenID_Client
 * @category  Authentication
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * ICC_OpenID_Client_Auth class.
 */
class ICC_OpenID_Client_Auth
{
    /**
     * Query parameter used to reach the plugin endpoints.
     */
    const QUERY_VAR = 'icc_oidc';

    /**
     * Query parameter carrying an error code back to the login screen.
     */
    const ERROR_VAR = 'icc_oidc_error';

    /**
     * Plugin settings.
     *
     * @var array
     */
    protected $settings;

    /**
     * Logger.
     *
     * @var ICC_OpenID_Client_Logger
     */
    protected $logger;

    /**
     * User store.
     *
     * @var ICC_OpenID_Client_Store
     */
    protected $store;

    /**
     * Optional HTTP transport (used by tests).
     *
     * @var callable|null
     */
    protected $http;

    /**
     * Protocol client (lazy).
     *
     * @var ICC_OpenID_Client_Client|null
     */
    protected $client;

    /**
     * @param array|null                  $settings Plugin settings (defaults to stored settings).
     * @param ICC_OpenID_Client_Logger|null $logger Logger.
     * @param callable|null               $http     Optional HTTP transport.
     * @param ICC_OpenID_Client_Store|null $store   Optional user store.
     */
    public function __construct($settings = null, $logger = null, $http = null, $store = null)
    {
        $this->settings = is_array($settings) ? $settings : icc_oidc_get_all();
        $this->logger = $logger !== null ? $logger : new ICC_OpenID_Client_Logger();
        $this->http = $http;
        $this->store = $store !== null ? $store : new ICC_OpenID_Client_Store($this->logger);
    }

    /**
     * Handle requests and register hooks. Called once on "plugins_loaded".
     *
     * The callback/logout endpoints must be served before YOURLS runs its own
     * authentication, which is why they are handled here.
     *
     * @param callable|null $http Optional HTTP transport (used by tests).
     *
     * @return ICC_OpenID_Client_Auth
     */
    public static function bootstrap($http = null)
    {
        $auth = new self(null, null, $http);

        $auth->handle_request();

        yourls_add_action('require_auth', array($auth, 'handle_require_auth'));
        yourls_add_filter('logout_link', array($auth, 'handle_logout_link'));

        return $auth;
    }

    /**
     * Get a setting.
     *
     * @param string $key     Setting key.
     * @param mixed  $default Default value.
     *
     * @return mixed
     */
    protected function setting($key, $default = '')
    {
        return isset($this->settings[$key]) ? $this->settings[$key] : $default;
    }

    /**
     * Get (and lazily build) the protocol client.
     *
     * @return ICC_OpenID_Client_Client
     */
    public function client()
    {
        if ($this->client === null) {
            $this->client = new ICC_OpenID_Client_Client($this->settings, $this->logger, $this->http);
        }

        return $this->client;
    }

    /**
     * Route plugin endpoint requests.
     *
     * @return bool True when a plugin endpoint was handled.
     */
    public function handle_request()
    {
        $action = isset($_GET[self::QUERY_VAR]) ? (string) $_GET[self::QUERY_VAR] : '';

        // Also accept the callback when the marker is missing (custom redirect URI).
        if ($action === '' && isset($_GET['code'], $_GET['state'])) {
            $action = 'callback';
        }

        if ($action === 'callback') {
            $this->handle_callback();

            return true;
        }

        if ($action === 'logout') {
            $this->handle_logout();

            return true;
        }

        return false;
    }

    /**
     * Is the plugin configured well enough to attempt a login?
     *
     * @return bool
     */
    protected function is_configured()
    {
        return trim((string) $this->setting('endpoint_login')) !== ''
            && trim((string) $this->setting('client_id')) !== ''
            && trim((string) $this->setting('client_secret')) !== '';
    }

    /**
     * Human readable message for an error code.
     *
     * @param string $code Error code.
     *
     * @return string
     */
    public static function error_message($code)
    {
        $messages = array(
            'not-configured'               => 'Single Sign-On is not configured yet. Please contact the administrator.',
            'login-endpoint-missing'       => 'Single Sign-On is not configured yet. Please contact the administrator.',
            'state-not-found'              => 'This login attempt is no longer valid. Please try again.',
            'state-expired'                => 'This login attempt expired. Please try again.',
            'missing-authentication-state' => 'The identity provider response was incomplete. Please try again.',
            'missing-authentication-code'  => 'The identity provider response was incomplete. Please try again.',
            'invalid-signature'            => 'The identity provider token could not be verified.',
            'no-matching-key'              => 'The identity provider signing key could not be found.',
            'jwks-not-configured'          => 'The identity provider signing keys are not configured.',
            'jwks-fetch-failed'            => 'The identity provider signing keys could not be retrieved.',
            'jwks-invalid'                 => 'The identity provider returned invalid signing keys.',
            'unsupported-alg'              => 'The identity provider uses an unsupported token algorithm.',
            'token-expired'                => 'The identity provider token expired. Please try again.',
            'invalid-nonce'                => 'This login attempt could not be validated. Please try again.',
            'invalid-aud'                  => 'The identity provider token is not valid for this site.',
            'invalid-iss'                  => 'The identity provider token was issued by an unexpected issuer.',
            'invalid-azp'                  => 'The identity provider token is not valid for this site.',
            'email-domain-not-allowed'     => 'Your email address is not allowed to sign in here.',
            'email-domain-no-email'        => 'Your identity provider account has no email address.',
            'incorrect-user-claim'         => 'The identity provider returned inconsistent user data.',
            'cannot-authorize'             => 'Your account is not allowed to sign in here.',
            'user-not-linked'              => 'Your identity is not linked to a YOURLS user. Please contact the administrator.',
            'userinfo-request-failed'      => 'The identity provider user information could not be retrieved.',
            'token-request-failed'         => 'The identity provider refused the login. Please try again.',
            'http-request-failed'          => 'The identity provider could not be reached.',
            'url-local-host'               => 'The identity provider endpoint is not allowed.',
            'url-not-https'                => 'The identity provider endpoint must use HTTPS.',
            'invalid-url'                  => 'The identity provider endpoint is invalid.',
        );

        if (isset($messages[$code])) {
            return $messages[$code];
        }

        return 'Single Sign-On failed (' . $code . '). Please try again or contact the administrator.';
    }

    /**
     * Redirect back to the login screen with an error code (never leaks IdP text).
     *
     * @param string $code Error code.
     *
     * @return void
     */
    protected function redirect_with_error($code)
    {
        $target = function_exists('yourls_admin_url')
            ? yourls_admin_url('index.php')
            : rtrim(icc_oidc_site_url(), '/') . '/admin/';

        $separator = strpos($target, '?') === false ? '?' : '&';
        $url = $target . $separator . self::ERROR_VAR . '=' . rawurlencode($code);

        yourls_redirect($url, 302);

        die();
    }

    /**
     * Redirect to the YOURLS admin interface (or the page the user came from).
     *
     * @param string $redirect_to Requested target.
     *
     * @return void
     */
    protected function redirect_after_login($redirect_to = '')
    {
        $default = function_exists('yourls_admin_url')
            ? yourls_admin_url('index.php')
            : rtrim(icc_oidc_site_url(), '/') . '/admin/';

        $target = $default;

        if (
            $this->setting('redirect_user_back')
            && trim((string) $redirect_to) !== ''
            && $this->is_local_url($redirect_to)
        ) {
            $target = (string) $redirect_to;
        }

        /**
         * Filter the post login redirect target.
         *
         * @param string $target      Target URL.
         * @param string $default     Default target.
         * @param string $redirect_to Requested target.
         */
        $target = yourls_apply_filter('icc_oidc_redirect_after_login', $target, $default, $redirect_to);

        if (!$this->is_local_url($target)) {
            $target = $default;
        }

        $this->logger->log('Redirecting to ' . $target, 'redirect');

        yourls_redirect($target, 302);

        die();
    }

    /**
     * Is a URL pointing at this YOURLS installation?
     *
     * @param string $url URL to test.
     *
     * @return bool
     */
    protected function is_local_url($url)
    {
        $site = parse_url(icc_oidc_site_url());
        $target = parse_url((string) $url);

        if (!is_array($site) || !is_array($target) || empty($site['host']) || empty($target['host'])) {
            return false;
        }

        return strtolower($site['host']) === strtolower($target['host']);
    }

    /**
     * Current request URL (used as the SSO "redirect back" target).
     *
     * @return string
     */
    protected function current_url()
    {
        if (empty($_SERVER['REQUEST_URI'])) {
            return '';
        }

        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : '';

        if ($host === '') {
            return '';
        }

        return $scheme . '://' . $host . (string) $_SERVER['REQUEST_URI'];
    }

    /**
     * Handle the identity provider callback: exchange the code and log the user in.
     *
     * @return void
     */
    public function handle_callback()
    {
        if (!$this->is_configured()) {
            $this->logger->log('Callback received but the plugin is not configured.', 'login-error');
            $this->redirect_with_error('not-configured');
        }

        $client = $this->client();

        try {
            $code = $client->get_authentication_code($_GET);
            $state = isset($_GET['state']) ? (string) $_GET['state'] : '';
            $attempt = $client->consume_state($state);

            $token_response = $client->request_token($code);
            $id_token_claim = $client->get_id_token_claim(
                $token_response,
                $attempt['nonce'] !== '' ? $attempt['nonce'] : null
            );

            $user_claim = $client->get_user_claim($token_response);

            if (!is_array($user_claim) || empty($user_claim)) {
                $user_claim = $id_token_claim;
            }

            $this->validate_user_claim($user_claim, $id_token_claim);

            $login = $this->resolve_user($id_token_claim, $user_claim);
            $id_token = isset($token_response['id_token']) ? (string) $token_response['id_token'] : '';

            $this->login_user($login, $id_token);

            $this->redirect_after_login($attempt['redirect_to']);
        } catch (ICC_OpenID_Client_Error $error) {
            $this->logger->log('Login failed: ' . $error->error_code() . ' - ' . $error->getMessage(), 'login-error');

            yourls_do_action('icc_oidc_login_error', $error);

            $this->redirect_with_error($error->error_code());
        }
    }

    /**
     * Auto SSO: send unauthenticated visitors to the identity provider.
     *
     * Hooked to "require_auth", which YOURLS triggers on admin pages (and on the
     * API, which is deliberately skipped so signature authentication keeps working).
     *
     * @return void
     */
    public function handle_require_auth()
    {
        if ((string) $this->setting('login_type') !== 'auto') {
            return;
        }

        if (function_exists('yourls_is_API') && yourls_is_API()) {
            return;
        }

        if (!function_exists('yourls_cookie_name') || isset($_COOKIE[yourls_cookie_name()])) {
            // Already authenticated (or YOURLS too old to expose its cookie name).
            return;
        }

        // Never loop: a plugin request or an error page shows the login form instead.
        if (isset($_GET[self::ERROR_VAR]) || isset($_GET[self::QUERY_VAR])) {
            return;
        }

        if (!$this->is_configured()) {
            return;
        }

        try {
            $url = $this->client()->get_authentication_url($this->current_url());
        } catch (ICC_OpenID_Client_Error $error) {
            $this->logger->log('Auto login skipped: ' . $error->error_code(), 'auto-login');

            return;
        }

        $this->logger->log('Redirecting to the identity provider', 'auto-login');

        yourls_redirect($url, 302);

        die();
    }

    /**
     * End the YOURLS session and, when configured, the identity provider session.
     *
     * @return void
     */
    public function handle_logout()
    {
        if (function_exists('yourls_verify_nonce') && isset($_GET['nonce'])) {
            yourls_verify_nonce('icc_oidc_logout', $_GET['nonce']);
        }

        $login = $this->current_user_from_cookie();
        $id_token = '';

        if ($login !== '') {
            $user = ICC_OpenID_Client_Store::get($login);

            if (is_array($user) && !empty($user['last_id_token'])) {
                $id_token = (string) $user['last_id_token'];
            }
        }

        yourls_store_cookie('');
        yourls_do_action('icc_oidc_logout', $login);

        $this->logger->log('Logout for ' . ($login !== '' ? $login : 'unknown user'), 'logout');

        $target = '';

        if ($this->setting('redirect_on_logout')) {
            $target = $this->client()->get_end_session_url($id_token);
        }

        if ($target === '') {
            $target = function_exists('yourls_admin_url')
                ? yourls_admin_url('index.php')
                : rtrim(icc_oidc_site_url(), '/') . '/';
        }

        yourls_redirect($target, 302);

        die();
    }

    /**
     * Point the YOURLS logout link at the identity provider (RP initiated logout).
     *
     * @param string $link Logout link HTML.
     *
     * @return string
     */
    public function handle_logout_link($link)
    {
        if (trim((string) $this->setting('endpoint_end_session')) === '' || !$this->setting('redirect_on_logout')) {
            return $link;
        }

        if (
            !function_exists('yourls_nonce_url')
            || !function_exists('yourls_admin_url')
            || !function_exists('yourls_add_query_arg')
        ) {
            return $link;
        }

        $replacement = yourls_nonce_url('icc_oidc_logout', icc_oidc_logout_url());

        $original = yourls_nonce_url(
            'admin_logout',
            yourls_add_query_arg(array('action' => 'logout'), yourls_admin_url('index.php')),
            'nonce',
            'logout'
        );

        // The link is HTML escaped, so try the raw and the escaped forms.
        $swapped = str_replace($original, $replacement, $link);

        if ($swapped === $link) {
            $swapped = str_replace(
                htmlspecialchars($original, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars($replacement, ENT_QUOTES, 'UTF-8'),
                $link
            );
        }

        return $swapped;
    }

    /**
     * Find the user the current request is authenticated as (by cookie value).
     *
     * Needed because YOURLS defines YOURLS_USER only after authentication, which
     * happens after this plugin has already been given the chance to act.
     *
     * @return string Login name, or an empty string.
     */
    protected function current_user_from_cookie()
    {
        global $yourls_user_passwords;

        if (!function_exists('yourls_cookie_name') || !function_exists('yourls_cookie_value')) {
            return '';
        }

        if (!isset($_COOKIE[yourls_cookie_name()]) || !is_array($yourls_user_passwords)) {
            return '';
        }

        $cookie = (string) $_COOKIE[yourls_cookie_name()];

        foreach ($yourls_user_passwords as $login => $password) {
            if (hash_equals(yourls_cookie_value($login), $cookie)) {
                return (string) $login;
            }
        }

        return '';
    }

    /**
     * Validate the user claim before a user is logged in.
     *
     * @param array $user_claim     User claim (userinfo, or the ID token claims).
     * @param array $id_token_claim Verified ID token claims.
     *
     * @return bool
     *
     * @throws ICC_OpenID_Client_Error When the claim must not be trusted.
     */
    protected function validate_user_claim($user_claim, $id_token_claim)
    {
        if (!is_array($user_claim)) {
            throw new ICC_OpenID_Client_Error('invalid-user-claim', 'The identity provider returned an invalid user claim.');
        }

        if (isset($user_claim['error'])) {
            $message = isset($user_claim['error_description'])
                ? (string) $user_claim['error_description']
                : (string) $user_claim['error'];

            throw new ICC_OpenID_Client_Error('invalid-user-claim', $message);
        }

        // Per spec, the userinfo "sub" must be identical to the ID token "sub".
        if (
            empty($id_token_claim['sub'])
            || empty($user_claim['sub'])
            || (string) $user_claim['sub'] !== (string) $id_token_claim['sub']
        ) {
            throw new ICC_OpenID_Client_Error(
                'incorrect-user-claim',
                'The userinfo subject does not match the ID token subject.'
            );
        }

        /**
         * Allow plugins to refuse a login based on the user claim.
         *
         * @param bool  $allowed    Whether the user may log in.
         * @param array $user_claim User claim.
         */
        $allowed = yourls_apply_filter('icc_oidc_user_login_test', true, $user_claim);

        if (!$allowed) {
            throw new ICC_OpenID_Client_Error('cannot-authorize', 'Login refused by a plugin filter.');
        }

        $this->validate_email_domain($user_claim);

        return true;
    }

    /**
     * Map an authenticated IdP user to a YOURLS account.
     *
     * YOURLS is a single account system: users live in user/config.php and this
     * plugin never creates them. The identity is therefore resolved, in order, to
     * a known identity, to a config.php login matching the identity claim, or to
     * the only configured user.
     *
     * @param array $id_token_claim Verified ID token claims.
     * @param array $user_claim     User claim.
     *
     * @return string YOURLS login.
     *
     * @throws ICC_OpenID_Client_Error When no account can be used.
     */
    protected function resolve_user($id_token_claim, $user_claim)
    {
        $subject = isset($id_token_claim['sub']) ? (string) $id_token_claim['sub'] : '';

        if ($subject === '') {
            throw new ICC_OpenID_Client_Error('no-subject-identity', 'The ID token has no subject identity.');
        }

        $username = $this->get_username_from_claim($user_claim, $subject);

        $data = array(
            'subject'     => $subject,
            'email'       => $this->get_email_from_claim($user_claim),
            'nickname'    => $this->get_nickname_from_claim($user_claim, $username),
            'displayname' => $this->get_displayname_from_claim($user_claim, $username),
        );

        // 1) Identity already known: keep using the YOURLS account it was linked to.
        $known = ICC_OpenID_Client_Store::find_login_by_subject($subject);

        if ($known !== null && $known !== '') {
            if ($this->is_config_login($known)) {
                $this->store->save($known, $data);
                yourls_do_action('icc_oidc_update_user_using_current_claim', $known, $user_claim);

                return $known;
            }

            // The account was renamed or removed in config.php: drop the stale
            // mapping and resolve the identity again below.
            $this->store->remove($known);
            $this->logger->log('Discarded a stale identity mapping for "' . $known . '"', 'user-unlink');
        }

        // 2) Match the identity claim against the logins defined in config.php.
        $login = $this->match_config_login($username);

        // 3) Single account installations: the IdP user is the YOURLS user.
        if ($login === '') {
            $logins = $this->config_logins();

            if (count($logins) === 1) {
                $login = (string) $logins[0];
            }
        }

        if ($login === '') {
            throw new ICC_OpenID_Client_Error(
                'user-not-linked',
                'The identity "' . $username . '" is not linked to a YOURLS account.'
            );
        }

        $this->store->save($login, $data);
        yourls_do_action('icc_oidc_user_update', $login);
        $this->logger->log('OpenID Connect identity linked to the YOURLS user ' . $login, 'user-link');

        return $login;
    }

    /**
     * Logins defined in user/config.php.
     *
     * @return array List of login names.
     */
    protected function config_logins()
    {
        global $yourls_user_passwords;

        if (!is_array($yourls_user_passwords)) {
            return array();
        }

        $logins = array();

        foreach ($yourls_user_passwords as $login => $password) {
            if (is_string($login) && $login !== '') {
                $logins[] = $login;
            }
        }

        return $logins;
    }

    /**
     * Is a login defined in user/config.php?
     *
     * @param string $login YOURLS login.
     *
     * @return bool
     */
    protected function is_config_login($login)
    {
        $login = (string) $login;

        foreach ($this->config_logins() as $configured) {
            if (strcasecmp($configured, $login) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Match the identity claim against the logins defined in config.php.
     *
     * @param string $username Claim based user name.
     *
     * @return string The matching login, or an empty string.
     */
    protected function match_config_login($username)
    {
        $username = trim((string) $username);

        if ($username === '') {
            return '';
        }

        foreach ($this->config_logins() as $login) {
            if (strcasecmp($login, $username) === 0) {
                return $login;
            }
        }

        return '';
    }

    /**
     * Sanitize a claim value so it can be used as a YOURLS login.
     *
     * @param string $value Raw value.
     *
     * @return string
     */
    protected function sanitize_login($value)
    {
        $value = (string) $value;
        $clean = preg_replace('/[\x00-\x20\x7F]/u', '', $value);

        if (!is_string($clean)) {
            // Invalid UTF-8: fall back to a byte oriented cleanup.
            $clean = preg_replace('/[\x00-\x20\x7F]/', '', $value);
        }

        if (!is_string($clean)) {
            $clean = '';
        }

        if (function_exists('mb_substr')) {
            $clean = mb_substr($clean, 0, 64, 'UTF-8');
        } else {
            $clean = substr($clean, 0, 64);
        }

        return trim($clean);
    }

    /**
     * Log the user in: set YOURLS_USER and store the YOURLS auth cookie.
     *
     * @param string $login    YOURLS login.
     * @param string $id_token Last ID token (kept for the logout hint).
     *
     * @return void
     */
    protected function login_user($login, $id_token = '')
    {
        yourls_set_user($login);
        yourls_do_action('icc_oidc_before_login', $login);

        yourls_store_cookie($login);

        $this->store->record_login($login, $id_token);

        $this->logger->log('Successful SSO login: ' . $login, 'login-success');

        yourls_do_action('icc_oidc_user_logged_in', $login);
    }

    /**
     * Validate the user's email against the configured allow list.
     *
     * Entries may be domains ("company.com", "@company.com") or full addresses.
     *
     * @param array $user_claim User claim.
     *
     * @return bool
     *
     * @throws ICC_OpenID_Client_Error When the email is not allowed.
     */
    protected function validate_email_domain($user_claim)
    {
        $restrictions = trim((string) $this->setting('email_domain_restriction'));

        if ($restrictions === '') {
            return true;
        }

        $email = strtolower(trim((string) $this->get_email_from_claim($user_claim)));

        if ($email === '' || strpos($email, '@') === false) {
            throw new ICC_OpenID_Client_Error(
                'email-domain-no-email',
                'Unable to determine an email address to validate against the restriction list.'
            );
        }

        $parts = explode('@', $email);
        $domain = trim((string) end($parts));
        $entries = preg_split('/[\s,]+/', strtolower($restrictions));
        $matched = false;

        foreach ((array) $entries as $entry) {
            $entry = trim($entry);

            if ($entry === '') {
                continue;
            }

            if (strpos($entry, '@') !== false) {
                if ($email === $entry) {
                    $matched = true;
                    break;
                }

                continue;
            }

            if ($domain === ltrim($entry, '@')) {
                $matched = true;
                break;
            }
        }

        if (!$matched) {
            $this->logger->log('Email "' . $email . '" is not in the restriction list', 'email-domain-restriction');

            throw new ICC_OpenID_Client_Error(
                'email-domain-not-allowed',
                'Email "' . $email . '" is not allowed for login.'
            );
        }

        return true;
    }

    /**
     * Build the email address from the configured format.
     *
     * @param array $user_claim User claim.
     *
     * @return string
     */
    protected function get_email_from_claim($user_claim)
    {
        $format = trim((string) $this->setting('email_format'));

        if ($format === '') {
            $format = '{email}';
        }

        $email = trim($this->format_claim_string($format, $user_claim));

        if ($email === '') {
            $email = $this->claim_value($user_claim, 'email');
        }

        return $email;
    }

    /**
     * Build the YOURLS login from the configured identity claim.
     *
     * @param array  $user_claim User claim.
     * @param string $fallback   Value to use when no claim matches.
     *
     * @return string
     */
    protected function get_username_from_claim($user_claim, $fallback = '')
    {
        $key = trim((string) $this->setting('identity_key'));

        if ($key === '') {
            $key = 'preferred_username';
        }

        $candidates = array($key, 'preferred_username', 'nickname', 'upn', 'email', 'name');

        foreach ($candidates as $candidate) {
            $value = $this->claim_value($user_claim, $candidate);

            if ($value === '') {
                continue;
            }

            if (strpos($value, '@') !== false) {
                $parts = explode('@', $value);
                $value = (string) $parts[0];
            }

            $clean = $this->sanitize_login($value);

            if ($clean !== '') {
                return $clean;
            }
        }

        return $this->sanitize_login($fallback);
    }

    /**
     * Nickname from the configured claim.
     *
     * @param array  $user_claim User claim.
     * @param string $fallback   Fallback value.
     *
     * @return string
     */
    protected function get_nickname_from_claim($user_claim, $fallback = '')
    {
        $key = trim((string) $this->setting('nickname_key'));

        if ($key === '') {
            $key = 'preferred_username';
        }

        $value = $this->claim_value($user_claim, $key);

        if ($value === '') {
            $value = $this->claim_value($user_claim, 'nickname');
        }

        return $value !== '' ? $value : $fallback;
    }

    /**
     * Display name from the configured format.
     *
     * @param array  $user_claim User claim.
     * @param string $fallback   Fallback value.
     *
     * @return string
     */
    protected function get_displayname_from_claim($user_claim, $fallback = '')
    {
        $format = trim((string) $this->setting('displayname_format'));

        if ($format !== '') {
            $value = trim($this->format_claim_string($format, $user_claim));

            if ($value !== '') {
                return $value;
            }
        }

        $value = $this->claim_value($user_claim, 'name');

        return $value !== '' ? $value : $fallback;
    }

    /**
     * Read a claim value, supporting nested paths such as "realm_access.roles".
     *
     * @param array  $claims Claim array.
     * @param string $key    Claim name or dotted path.
     *
     * @return string First scalar value, or an empty string.
     */
    protected function claim_value($claims, $key)
    {
        if (!is_array($claims) || $key === '') {
            return '';
        }

        $value = $claims;

        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !isset($value[$segment])) {
                return '';
            }

            $value = $value[$segment];
        }

        if (is_array($value)) {
            foreach ($value as $item) {
                if (is_scalar($item) && trim((string) $item) !== '') {
                    return trim((string) $item);
                }
            }

            return '';
        }

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        return '';
    }

    /**
     * Replace {claim} placeholders in a format string.
     *
     * @param string $format Format string, e.g. "{given_name} {family_name}".
     * @param array  $claims Claim array.
     *
     * @return string
     */
    protected function format_claim_string($format, $claims)
    {
        $result = preg_replace_callback(
            '/\{([a-zA-Z0-9_.\-]+)\}/',
            function ($matches) use ($claims) {
                return $this->claim_value($claims, $matches[1]);
            },
            (string) $format
        );

        if (!is_string($result)) {
            return '';
        }

        return trim(preg_replace('/\s+/', ' ', $result));
    }
}
