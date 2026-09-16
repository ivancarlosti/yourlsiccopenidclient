<?php
/**
 * Global plugin helper functions, defaults and settings accessors.
 *
 * ICC OpenID Connect Client - YOURLS OpenID Connect SSO plugin.
 *
 * @package   ICC_OpenID_Client
 * @category  General
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * Error object used across the plugin.
 *
 * YOURLS has no WP_Error equivalent, so we extend the native Exception with a
 * string error code (Exception::$code is an integer and cannot hold codes such
 * as "invalid-aud").
 */
class ICC_OpenID_Client_Error extends Exception
{
    /**
     * String error code.
     *
     * @var string
     */
    protected $error_code;

    /**
     * Extra data related to the error.
     *
     * @var mixed
     */
    protected $data;

    /**
     * @param string $error_code String error code.
     * @param string $message    Human readable message.
     * @param mixed  $data       Optional extra data.
     */
    public function __construct($error_code, $message = '', $data = null)
    {
        parent::__construct($message !== '' ? $message : (string) $error_code, 0);
        $this->error_code = (string) $error_code;
        $this->data = $data;
    }

    /**
     * @return string
     */
    public function error_code()
    {
        return $this->error_code;
    }

    /**
     * @return mixed
     */
    public function data()
    {
        return $this->data;
    }
}

/**
 * Default settings values.
 *
 * @return array
 */
function icc_oidc_defaults()
{
    return array(
        // Client settings.
        'login_type'               => 'button',
        'login_button_text'        => '',
        'login_button_logo_url'    => '',
        'client_id'                => '',
        'client_secret'            => '',
        'scope'                    => 'openid profile email',
        'endpoint_login'           => '',
        'endpoint_userinfo'        => '',
        'endpoint_token'           => '',
        'endpoint_end_session'     => '',
        'endpoint_jwks'            => '',
        'issuer'                   => '',
        'jwks_cache_ttl'           => 3600,
        'acr_values'               => '',
        'identity_key'             => 'preferred_username',
        'nickname_key'             => 'preferred_username',
        'email_format'             => '{email}',
        'displayname_format'       => '',
        'state_time_limit'         => 180,
        'http_request_timeout'     => 5,
        'no_sslverify'             => 0,
        'allow_internal_idp'       => 0,
        'redirect_uri'             => '',

        // User settings.
        'email_domain_restriction' => '',
        'redirect_user_back'       => 0,
        'redirect_on_logout'       => 1,

        // Log settings.
        'enable_logging'           => 0,
        'log_limit'                => 1000,
    );
}

/**
 * Settings that can be defined as constants in user/config.php.
 *
 * @return array option key => constant name
 */
function icc_oidc_constant_map()
{
    return array(
        'client_id'                => 'OIDC_CLIENT_ID',
        'client_secret'            => 'OIDC_CLIENT_SECRET',
        'endpoint_login'           => 'OIDC_ENDPOINT_LOGIN_URL',
        'endpoint_token'           => 'OIDC_ENDPOINT_TOKEN_URL',
        'endpoint_userinfo'        => 'OIDC_ENDPOINT_USERINFO_URL',
        'endpoint_jwks'            => 'OIDC_ENDPOINT_JWKS_URL',
        'endpoint_end_session'     => 'OIDC_ENDPOINT_LOGOUT_URL',
        'issuer'                   => 'OIDC_ISSUER',
        'scope'                    => 'OIDC_CLIENT_SCOPE',
        'login_type'               => 'OIDC_LOGIN_TYPE',
        'login_button_text'        => 'OIDC_LOGIN_BUTTON_TEXT',
        'login_button_logo_url'    => 'OIDC_LOGIN_BUTTON_LOGO_URL',
        'email_domain_restriction' => 'OIDC_EMAIL_DOMAIN_RESTRICTION',
        'redirect_user_back'       => 'OIDC_REDIRECT_USER_BACK',
        'redirect_on_logout'       => 'OIDC_REDIRECT_ON_LOGOUT',
        'acr_values'               => 'OIDC_ACR_VALUES',
        'identity_key'             => 'OIDC_IDENTITY_KEY',
        'nickname_key'             => 'OIDC_NICKNAME_KEY',
        'email_format'             => 'OIDC_EMAIL_FORMAT',
        'displayname_format'       => 'OIDC_DISPLAYNAME_FORMAT',
        'state_time_limit'         => 'OIDC_STATE_TIME_LIMIT',
        'jwks_cache_ttl'           => 'OIDC_JWKS_CACHE_TTL',
        'http_request_timeout'     => 'OIDC_HTTP_TIMEOUT',
        'no_sslverify'             => 'OIDC_NO_SSLVERIFY',
        'allow_internal_idp'       => 'OIDC_ALLOW_INTERNAL_IDP',
        'redirect_uri'             => 'OIDC_REDIRECT_URI',
        'enable_logging'           => 'OIDC_ENABLE_LOGGING',
        'log_limit'                => 'OIDC_LOG_LIMIT',
    );
}

/**
 * Plugin option name for a settings key.
 *
 * @param string $key Settings key.
 *
 * @return string
 */
function icc_oidc_option_name($key)
{
    return 'icc_oidc_' . $key;
}

/**
 * Get a plugin setting: constant override first, then stored option, then default.
 *
 * @param string $key Settings key.
 *
 * @return mixed
 */
function icc_oidc_get($key)
{
    $map = icc_oidc_constant_map();

    if (isset($map[$key]) && defined($map[$key])) {
        return constant($map[$key]);
    }

    // The redirect URI is not a stored setting: this plugin always uses a URL
    // served by YOURLS itself, or the OIDC_REDIRECT_URI constant. A value left
    // behind by version 2.x is deliberately ignored, because it may point at a
    // URL that is not served by YOURLS (for example the site root of a landing
    // page), which silently breaks the login. The leftover is reported on the
    // plugin page, where it can also be removed.
    if ($key === 'redirect_uri') {
        return '';
    }

    $defaults = icc_oidc_defaults();
    $default = isset($defaults[$key]) ? $defaults[$key] : '';

    $stored = yourls_get_option(icc_oidc_option_name($key));

    if ($stored === false || $stored === null) {
        return $default;
    }

    if (isset($defaults[$key]) && is_int($defaults[$key])) {
        return intval($stored);
    }

    return $stored;
}

/**
 * Is a settings value defined as a constant (and therefore read-only in the UI)?
 *
 * @param string $key Settings key.
 *
 * @return bool
 */
function icc_oidc_is_constant($key)
{
    $map = icc_oidc_constant_map();

    return isset($map[$key]) && defined($map[$key]);
}

/**
 * Get all settings as an associative array.
 *
 * @return array
 */
function icc_oidc_get_all()
{
    $values = array();

    foreach (icc_oidc_defaults() as $key => $default) {
        $values[$key] = icc_oidc_get($key);
    }

    return $values;
}

/**
 * Escape text for HTML output (YOURLS 1.8+ has yourls_esc_html()).
 *
 * @param string $text Text to escape.
 *
 * @return string
 */
function icc_oidc_esc_html($text)
{
    if (function_exists('yourls_esc_html')) {
        return yourls_esc_html($text);
    }

    return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
}

/**
 * Escape text for an HTML attribute.
 *
 * @param string $text Text to escape.
 *
 * @return string
 */
function icc_oidc_esc_attr($text)
{
    if (function_exists('yourls_esc_attr')) {
        return yourls_esc_attr($text);
    }

    return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
}

/**
 * Escape a URL for HTML output.
 *
 * @param string $url URL to escape.
 *
 * @return string
 */
function icc_oidc_esc_url($url)
{
    if (function_exists('yourls_esc_url')) {
        return yourls_esc_url($url);
    }

    return htmlspecialchars((string) $url, ENT_QUOTES, 'UTF-8');
}

/**
 * Is YOURLS running in debug mode?
 *
 * Used to gate the "Disable SSL verification" option, which must never be
 * available in production.
 *
 * @return bool
 */
function icc_oidc_debug_enabled()
{
    if (defined('YOURLS_DEBUG') && YOURLS_DEBUG) {
        return true;
    }

    $env = getenv('YOURLS_ENV');

    return $env === 'local' || $env === 'development';
}


/**
 * Base URL of the YOURLS installation (with trailing slash).
 *
 * @return string
 */
function icc_oidc_site_url()
{
    if (function_exists('yourls_get_yourls_site')) {
        return yourls_get_yourls_site();
    }

    if (function_exists('yourls_site_url')) {
        return yourls_site_url(false);
    }

    return defined('YOURLS_SITE') ? YOURLS_SITE : '';
}

/**
 * Is a URL pointing at this YOURLS installation?
 *
 * @param string $url URL to test.
 *
 * @return bool
 */
function icc_oidc_is_local_url($url)
{
    $site = parse_url(icc_oidc_site_url());
    $target = parse_url((string) $url);

    if (!is_array($site) || !is_array($target) || empty($site['host']) || empty($target['host'])) {
        return false;
    }

    return strtolower($site['host']) === strtolower($target['host']);
}

/**
 * Default OpenID Connect callback URL.
 *
 * The provider response has to be answered by YOURLS itself. The plugin serves
 * the callback during "plugins_loaded", before YOURLS runs its own
 * authentication, so the YOURLS login page is a safe callback target even when
 * another application (a landing page, a static index.php, a parked domain)
 * owns the site root. This is why no configuration is needed.
 *
 * @return string
 */
function icc_oidc_default_redirect_uri()
{
    if (function_exists('yourls_admin_url')) {
        return yourls_admin_url('index.php') . '?icc_oidc=callback';
    }

    return rtrim(icc_oidc_site_url(), '/') . '/admin/index.php?icc_oidc=callback';
}

/**
 * Set or replace query parameters of an absolute URL.
 *
 * @param string $url  Absolute URL.
 * @param array  $args Parameters to set.
 *
 * @return string The URL with the parameters set, or an empty string when the
 *                URL is not an absolute HTTP(S) URL.
 */
function icc_oidc_add_query_args($url, array $args)
{
    $parts = parse_url((string) $url);

    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        return '';
    }

    $query = array();

    if (isset($parts['query'])) {
        parse_str($parts['query'], $query);
    }

    foreach ($args as $key => $value) {
        $query[$key] = $value;
    }

    $result = $parts['scheme'] . '://' . $parts['host'];

    if (!empty($parts['port'])) {
        $result .= ':' . intval($parts['port']);
    }

    $result .= isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';

    return $result . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
}

/**
 * Effective redirect URI: a configured entry point wins, else the default.
 *
 * @param string $configured Configured callback URL (OIDC_REDIRECT_URI constant, or empty).
 * @param string $default    Default callback URL (a URL YOURLS serves).
 *
 * @return string
 */
function icc_oidc_resolve_redirect_uri($configured, $default)
{
    $configured = trim((string) $configured);

    if ($configured === '' || !icc_oidc_is_local_url($configured)) {
        return (string) $default;
    }

    return $configured;
}

/**
 * Effective redirect URI (OIDC_REDIRECT_URI when configured, else the default).
 *
 * The value is returned verbatim: it has to match, byte for byte, the redirect
 * URI registered at the identity provider.
 *
 * @return string
 */
function icc_oidc_redirect_uri()
{
    return icc_oidc_resolve_redirect_uri(icc_oidc_get('redirect_uri'), icc_oidc_default_redirect_uri());
}

/**
 * URL of a plugin endpoint ("callback", "logout").
 *
 * The effective redirect URI is the single point of truth: both endpoints always
 * live on the same entry point, so a URL YOURLS serves answers the callback and
 * the logout link alike.
 *
 * @param string $action Endpoint action ("callback" or "logout").
 *
 * @return string
 */
function icc_oidc_endpoint_url($action)
{
    $action = (string) $action;

    // Keep in sync with ICC_OpenID_Client_Auth::QUERY_VAR.
    $marker = 'icc_oidc';

    $url = icc_oidc_add_query_args(icc_oidc_redirect_uri(), array($marker => $action));

    if ($url === '') {
        // Only reachable when neither the configured value nor the default is an
        // absolute URL, which cannot happen through the configuration.
        $url = rtrim(icc_oidc_site_url(), '/') . '/?' . $marker . '=' . $action;
    }

    return $url;
}

/**
 * URL used to start the logout flow (clears the cookie, then ends the IdP session).
 *
 * @return string
 */
function icc_oidc_logout_url()
{
    return icc_oidc_endpoint_url('logout');
}

/**
 * Is the given URL using HTTPS?
 *
 * @param string $url URL to check.
 *
 * @return bool
 */
function icc_oidc_is_https($url)
{
    $parts = parse_url((string) $url);

    if (!is_array($parts) || empty($parts['scheme'])) {
        return false;
    }

    return strtolower($parts['scheme']) === 'https';
}

/**
 * Issuer URL derived from an endpoint URL (scheme + host + non default port).
 *
 * @param string $endpoint_url Endpoint URL.
 *
 * @return string
 */
function icc_oidc_issuer_from_endpoint($endpoint_url)
{
    $parts = parse_url((string) $endpoint_url);

    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        return (string) $endpoint_url;
    }

    $issuer = $parts['scheme'] . '://' . $parts['host'];

    if (!empty($parts['port'])) {
        $default_ports = array('http' => 80, 'https' => 443);

        if (!isset($default_ports[$parts['scheme']]) || intval($parts['port']) !== $default_ports[$parts['scheme']]) {
            $issuer .= ':' . intval($parts['port']);
        }
    }

    $path = isset($parts['path']) ? rtrim($parts['path'], '/') : '';

    // Strip well known OpenID Connect endpoint paths to get back to the issuer.
    $stripped = preg_replace('#/(protocol/openid-connect|oauth2|oidc)(/.*)?$#', '', $path);

    if (is_string($stripped) && $stripped !== '/' && $stripped !== '') {
        $issuer .= $stripped;
    }

    return $issuer;
}


/**
 * Is a host part of the local/private network?
 *
 * Wraps yourls_host_is_local() (YOURLS 1.10.5+) with a fallback implementation
 * so the plugin also works on YOURLS 1.8/1.9.
 *
 * @param string $host Hostname or IP address.
 *
 * @return bool
 */
function icc_oidc_host_is_local($host)
{
    $host = strtolower(trim((string) $host, '[]'));

    if ($host === '') {
        return true;
    }

    if (function_exists('yourls_host_is_local')) {
        return (bool) yourls_host_is_local($host);
    }

    if ($host === 'localhost' || substr($host, -6) === '.local') {
        return true;
    }

    // IP literal: check it directly.
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    $resolved = @gethostbynamel($host);

    if (!is_array($resolved) || empty($resolved)) {
        // The host cannot be resolved here: it cannot be reached either, so it is
        // not treated as an internal endpoint (this also covers IPv6-only hosts).
        return false;
    }

    foreach ($resolved as $address) {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }
    }

    return false;
}

/**
 * Register the plugin autoloader.
 *
 * ICC_OpenID_Client_JWT  ->  includes/class-icc-openid-client-jwt.php
 *
 * @param string $class Class name.
 *
 * @return void
 */
function icc_oidc_autoload($class)
{
    $prefix = 'ICC_OpenID_Client_';

    if (strpos($class, $prefix) !== 0) {
        return;
    }

    $name = substr($class, strlen($prefix));
    $file = dirname(__FILE__) . '/class-icc-openid-client-' . strtolower(str_replace('_', '-', $name)) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
}

spl_autoload_register('icc_oidc_autoload');

