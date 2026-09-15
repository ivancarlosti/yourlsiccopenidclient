<?php
/**
 * OpenID Connect protocol client (Authorization Code Flow).
 *
 * Talks to the identity provider: builds the authorization URL, stores and
 * validates the CSRF state, exchanges the code for tokens, verifies the ID
 * token, requests userinfo and builds the RP initiated logout URL.
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
 * ICC_OpenID_Client_Client class.
 */
class ICC_OpenID_Client_Client
{
    /**
     * Option storing pending login attempts (state => data).
     */
    const STATE_OPTION = 'icc_oidc_states';

    /**
     * Plugin settings.
     *
     * @var array
     */
    protected $settings;

    /**
     * Optional logger.
     *
     * @var object|null
     */
    protected $logger;

    /**
     * HTTP transport: function($method, $url, $headers, $data, $options).
     *
     * @var callable|null
     */
    protected $http;

    /**
     * @param array       $settings Plugin settings.
     * @param object|null $logger   Optional logger.
     * @param callable    $http     Optional HTTP transport.
     */
    public function __construct(array $settings, $logger = null, $http = null)
    {
        $defaults = function_exists('icc_oidc_defaults') ? icc_oidc_defaults() : array();
        $this->settings = array_merge($defaults, $settings);
        $this->logger = $logger;
        $this->http = $http;
    }

    /**
     * Get a settings value.
     *
     * @param string $key     Setting key.
     * @param mixed  $default Default value.
     *
     * @return mixed
     */
    public function setting($key, $default = '')
    {
        return isset($this->settings[$key]) ? $this->settings[$key] : $default;
    }

    /**
     * Write a message to the log.
     *
     * @param string $message Message.
     * @param string $type    Log type.
     *
     * @return void
     */
    protected function log($message, $type = 'client')
    {
        if (is_object($this->logger) && method_exists($this->logger, 'log')) {
            $this->logger->log($message, $type);
        }
    }

    /**
     * Whether internal/private IdP endpoints are allowed.
     *
     * @return bool
     */
    protected function allow_internal_idp()
    {
        return (bool) $this->setting('allow_internal_idp', 0);
    }

    /**
     * Whether SSL certificate verification is enabled.
     *
     * @return bool
     */
    protected function ssl_verify()
    {
        if (!$this->setting('no_sslverify', 0)) {
            return true;
        }

        // Never disable certificate validation outside development.
        if (!function_exists('icc_oidc_debug_enabled') || !icc_oidc_debug_enabled()) {
            $this->log('SSL verification disabled setting ignored: YOURLS_DEBUG is off.', 'ssl-verify');

            return true;
        }

        $this->log('SSL verification disabled: development mode only, never use in production.', 'ssl-verify');

        return false;
    }

    /**
     * Perform a guarded HTTP request.
     *
     * @param string $method  GET or POST.
     * @param string $url     Target URL.
     * @param array  $headers Headers to send.
     * @param mixed  $data    Query parameters (GET) or encoded body (POST).
     *
     * @return array array('status' => int, 'body' => string)
     *
     * @throws ICC_OpenID_Client_Error When the URL is not allowed or the request fails.
     */
    public function http_request($method, $url, $headers = array(), $data = array())
    {
        ICC_OpenID_Client_HTTP::guard_url($url, $this->allow_internal_idp());

        $options = ICC_OpenID_Client_HTTP::default_options(
            $this->setting('http_request_timeout', 5),
            $this->ssl_verify()
        );

        $start = microtime(true);

        if (is_callable($this->http)) {
            $response = call_user_func($this->http, strtoupper($method), $url, $headers, $data, $options);
        } else {
            $response = ICC_OpenID_Client_HTTP::request($method, $url, $headers, $data, $options);
        }

        $this->log(sprintf('%s %s (%d ms)', strtoupper($method), $url, round((microtime(true) - $start) * 1000)), 'http');

        return $response;
    }

    /**
     * Decode a JSON response body, surfacing IdP errors.
     *
     * @param array  $response HTTP response.
     * @param string $context  Context used in error messages.
     *
     * @return array
     *
     * @throws ICC_OpenID_Client_Error When the body is not valid JSON or contains an error.
     */
    protected function decode_json_body($response, $context)
    {
        $body = isset($response['body']) ? (string) $response['body'] : '';
        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw new ICC_OpenID_Client_Error('invalid-json-response', 'Invalid JSON response from ' . $context . '.');
        }

        if (isset($decoded['error'])) {
            $description = isset($decoded['error_description']) ? (string) $decoded['error_description'] : (string) $decoded['error'];

            throw new ICC_OpenID_Client_Error((string) $decoded['error'], $description, $decoded);
        }

        return $decoded;
    }

    /**
     * Create a new login attempt: a random state plus a random nonce.
     *
     * Both values are stored server side so the callback can be tied to the
     * browser that started the flow (CSRF + replay protection).
     *
     * @param string $redirect_to Local URL to send the user to after login.
     *
     * @return array array('state' => string, 'nonce' => string)
     */
    public function new_state($redirect_to = '')
    {
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $time = time();
        $limit = intval($this->setting('state_time_limit', 180));

        if ($limit <= 0) {
            $limit = 180;
        }

        $states = yourls_get_option(self::STATE_OPTION);
        $states = is_array($states) ? $states : array();

        // Drop expired attempts.
        foreach ($states as $key => $value) {
            if (!is_array($value) || !isset($value['time']) || intval($value['time']) < $time - $limit) {
                unset($states[$key]);
            }
        }

        $states[$state] = array(
            'redirect_to' => (string) $redirect_to,
            'nonce'       => $nonce,
            'time'        => $time,
        );

        yourls_update_option(self::STATE_OPTION, $states);

        return array('state' => $state, 'nonce' => $nonce);
    }

    /**
     * Validate and consume a state value (single use).
     *
     * @param string $state State received from the IdP.
     *
     * @return array array('redirect_to' => string, 'nonce' => string, 'time' => int)
     *
     * @throws ICC_OpenID_Client_Error When the state is unknown or expired.
     */
    public function consume_state($state)
    {
        $state = trim((string) $state);
        $limit = intval($this->setting('state_time_limit', 180));

        if ($limit <= 0) {
            $limit = 180;
        }

        if ($state === '') {
            throw new ICC_OpenID_Client_Error('missing-authentication-state', 'The authentication response has no state.');
        }

        $states = yourls_get_option(self::STATE_OPTION);
        $states = is_array($states) ? $states : array();

        if (!isset($states[$state]) || !is_array($states[$state])) {
            throw new ICC_OpenID_Client_Error('state-not-found', 'Unknown authentication state, please try again.');
        }

        $entry = $states[$state];

        // Always remove the state: it cannot be reused.
        unset($states[$state]);
        yourls_update_option(self::STATE_OPTION, $states);

        if (!isset($entry['time']) || intval($entry['time']) < time() - $limit) {
            throw new ICC_OpenID_Client_Error('state-expired', 'The authentication attempt expired, please try again.');
        }

        return array(
            'redirect_to' => isset($entry['redirect_to']) ? (string) $entry['redirect_to'] : '',
            'nonce'       => isset($entry['nonce']) ? (string) $entry['nonce'] : '',
            'time'        => isset($entry['time']) ? intval($entry['time']) : 0,
        );
    }

    /**
     * Get the authorization code from a callback request.
     *
     * @param array $request Request data ($_GET).
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the code is missing or the IdP returned an error.
     */
    public function get_authentication_code($request)
    {
        if (isset($request['error'])) {
            $description = isset($request['error_description'])
                ? (string) $request['error_description']
                : (string) $request['error'];

            throw new ICC_OpenID_Client_Error((string) $request['error'], $description, $request);
        }

        if (!isset($request['code']) || trim((string) $request['code']) === '') {
            throw new ICC_OpenID_Client_Error('missing-authentication-code', 'The authentication response has no authorization code.');
        }

        return (string) $request['code'];
    }

    /**
     * Build the authorization URL the user is sent to.
     *
     * @param string $redirect_to Local URL to return to after login.
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the login endpoint is not configured.
     */
    public function get_authentication_url($redirect_to = '')
    {
        $endpoint = trim((string) $this->setting('endpoint_login'));

        if ($endpoint === '') {
            throw new ICC_OpenID_Client_Error('login-endpoint-missing', 'No login endpoint configured.');
        }

        $attempt = $this->new_state($redirect_to);

        $params = array(
            'response_type' => 'code',
            'scope'         => (string) $this->setting('scope', 'openid profile email'),
            'client_id'     => (string) $this->setting('client_id'),
            'state'         => $attempt['state'],
            'nonce'         => $attempt['nonce'],
            'redirect_uri'  => $this->get_redirect_uri(),
        );

        $acr_values = trim((string) $this->setting('acr_values'));

        if ($acr_values !== '') {
            $params['acr_values'] = $acr_values;
        }

        /**
         * Filter the authorization request parameters before the URL is built.
         *
         * @param array  $params      Query parameters.
         * @param string $redirect_to Post login redirect target.
         * @param object $client      Client instance.
         */
        if (function_exists('yourls_apply_filter')) {
            $params = yourls_apply_filter('icc_oidc_authentication_url_params', $params, $redirect_to, $this);
        }

        $separator = strpos($endpoint, '?') === false ? '?' : '&';

        return $endpoint . $separator . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Redirect URI registered at the identity provider.
     *
     * @return string
     */
    public function get_redirect_uri()
    {
        $configured = trim((string) $this->setting('redirect_uri'));

        if ($configured !== '') {
            return $configured;
        }

        if (function_exists('icc_oidc_default_redirect_uri')) {
            return icc_oidc_default_redirect_uri();
        }

        return '';
    }

    /**
     * Exchange an authorization code for tokens.
     *
     * @param string $code Authorization code.
     *
     * @return array Token response.
     *
     * @throws ICC_OpenID_Client_Error When the endpoint is not configured or the exchange fails.
     */
    public function request_token($code)
    {
        $endpoint = trim((string) $this->setting('endpoint_token'));

        if ($endpoint === '') {
            throw new ICC_OpenID_Client_Error('token-endpoint-missing', 'No token endpoint configured.');
        }

        $params = array(
            'grant_type'    => 'authorization_code',
            'code'          => (string) $code,
            'client_id'     => (string) $this->setting('client_id'),
            'client_secret' => (string) $this->setting('client_secret'),
            'redirect_uri'  => $this->get_redirect_uri(),
        );

        $scope = trim((string) $this->setting('scope'));

        if ($scope !== '') {
            $params['scope'] = $scope;
        }

        $acr_values = trim((string) $this->setting('acr_values'));

        if ($acr_values !== '') {
            $params['acr_values'] = $acr_values;
        }

        $headers = array(
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept'       => 'application/json',
        );

        // Some identity providers behind a reverse proxy need an explicit Host header.
        $host_header = $this->host_header($endpoint);

        if ($host_header !== '') {
            $headers['Host'] = $host_header;
        }

        $response = $this->http_request('POST', $endpoint, $headers, ICC_OpenID_Client_HTTP::encode_body($params));

        // Identity providers report failures as JSON even with a 4xx status, so
        // surface their error instead of a generic HTTP failure.
        $decoded = json_decode(isset($response['body']) ? (string) $response['body'] : '', true);

        if (is_array($decoded) && isset($decoded['error'])) {
            return $this->decode_json_body($response, 'the token endpoint');
        }

        if (intval($response['status']) !== 200) {
            throw new ICC_OpenID_Client_Error(
                'token-request-failed',
                'Token request failed with HTTP status ' . intval($response['status']) . '.'
            );
        }

        return $this->decode_json_body($response, 'the token endpoint');
    }

    /**
     * Host header value (host + non default port) for an endpoint URL.
     *
     * @param string $url Endpoint URL.
     *
     * @return string
     */
    protected function host_header($url)
    {
        $parts = parse_url($url);

        if (!is_array($parts) || empty($parts['host'])) {
            return '';
        }

        $host = $parts['host'];

        if (!empty($parts['port'])) {
            $host .= ':' . intval($parts['port']);
        }

        return $host;
    }

    /**
     * Request the userinfo endpoint.
     *
     * The spec allows GET and POST; identity providers differ, so POST is tried
     * when the GET response is not valid JSON.
     *
     * @param string $access_token Access token.
     *
     * @return array User claim.
     *
     * @throws ICC_OpenID_Client_Error When the endpoint is not configured or the request fails.
     */
    public function request_userinfo($access_token)
    {
        $endpoint = trim((string) $this->setting('endpoint_userinfo'));

        if ($endpoint === '') {
            throw new ICC_OpenID_Client_Error('userinfo-endpoint-missing', 'No userinfo endpoint configured.');
        }

        $headers = array(
            'Authorization' => 'Bearer ' . $access_token,
            'Accept'        => 'application/json',
        );

        $host_header = $this->host_header($endpoint);

        if ($host_header !== '') {
            $headers['Host'] = $host_header;
        }

        $response = $this->http_request('GET', $endpoint, $headers);

        if (intval($response['status']) !== 200 || !is_array(json_decode($response['body'], true))) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';

            $response = $this->http_request('POST', $endpoint, $headers, '');
        }

        if (intval($response['status']) !== 200) {
            throw new ICC_OpenID_Client_Error(
                'userinfo-request-failed',
                'Userinfo request failed with HTTP status ' . intval($response['status']) . '.'
            );
        }

        return $this->decode_json_body($response, 'the userinfo endpoint');
    }

    /**
     * Get the user claim: from userinfo when configured, else from the ID token.
     *
     * @param array $token_response Token response.
     *
     * @return array
     *
     * @throws ICC_OpenID_Client_Error When the claim cannot be retrieved.
     */
    public function get_user_claim($token_response)
    {
        if (
            trim((string) $this->setting('endpoint_userinfo')) === ''
            || empty($token_response['access_token'])
        ) {
            return array();
        }

        return $this->request_userinfo($token_response['access_token']);
    }

    /**
     * Validate the token response and return the verified ID token claims.
     *
     * @param array       $token_response Token endpoint response.
     * @param string|null $nonce          Nonce stored with the login attempt.
     *
     * @return array
     *
     * @throws ICC_OpenID_Client_Error When the ID token is missing or invalid.
     */
    public function get_id_token_claim($token_response, $nonce = null)
    {
        if (empty($token_response['id_token']) || !is_string($token_response['id_token'])) {
            throw new ICC_OpenID_Client_Error('no-identity-token', 'The token response has no "id_token".');
        }

        if (!empty($token_response['token_type']) && strcasecmp((string) $token_response['token_type'], 'Bearer') !== 0) {
            throw new ICC_OpenID_Client_Error(
                'invalid-token-type',
                'Unsupported token type: ' . $token_response['token_type'] . '.'
            );
        }

        $issuer = trim((string) $this->setting('issuer'));

        if ($issuer === '') {
            $issuer = icc_oidc_issuer_from_endpoint($this->setting('endpoint_login'));
        }

        $validator = new ICC_OpenID_Client_JWT(
            $this->setting('endpoint_jwks'),
            $this->setting('client_id'),
            $issuer,
            $this->setting('jwks_cache_ttl'),
            $this->allow_internal_idp(),
            $this->logger,
            $this->http,
            $this->setting('http_request_timeout', 5),
            $this->ssl_verify()
        );

        return $validator->validate_id_token($token_response['id_token'], $nonce);
    }

    /**
     * Build the RP initiated logout URL (or an empty string when not configured).
     *
     * @param string $id_token Last ID token, used as "id_token_hint".
     *
     * @return string
     */
    public function get_end_session_url($id_token = '')
    {
        $endpoint = trim((string) $this->setting('endpoint_end_session'));

        if ($endpoint === '') {
            return '';
        }

        $params = array();

        $client_id = trim((string) $this->setting('client_id'));

        if ($client_id !== '') {
            $params['client_id'] = $client_id;
        }

        if ($id_token !== '') {
            $params['id_token_hint'] = $id_token;
        }

        $redirect = $this->post_logout_redirect_uri();

        if ($redirect !== '') {
            $params['post_logout_redirect_uri'] = $redirect;
        }

        $separator = strpos($endpoint, '?') === false ? '?' : '&';

        return $endpoint . $separator . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Where the identity provider sends the user after ending the session.
     *
     * @return string
     */
    public function post_logout_redirect_uri()
    {
        if (function_exists('icc_oidc_site_url')) {
            return rtrim(icc_oidc_site_url(), '/') . '/';
        }

        return '';
    }

    /**
     * Fetch and validate an OpenID Connect discovery document.
     *
     * @param string $url Discovery document URL.
     *
     * @return array Discovery document.
     *
     * @throws ICC_OpenID_Client_Error When the document cannot be fetched or is incomplete.
     */
    public function discover($url)
    {
        $url = trim((string) $url);

        if ($url === '') {
            throw new ICC_OpenID_Client_Error('empty-discovery-url', 'Please enter a discovery URL.');
        }

        $response = $this->http_request('GET', $url, array('Accept' => 'application/json'));

        if (intval($response['status']) !== 200) {
            throw new ICC_OpenID_Client_Error(
                'discovery-fetch-failed',
                'Unable to fetch the discovery document: HTTP status ' . intval($response['status']) . '.'
            );
        }

        $document = json_decode($response['body'], true);

        if (!is_array($document)) {
            throw new ICC_OpenID_Client_Error('discovery-invalid-json', 'The discovery document is not valid JSON.');
        }

        foreach (array('authorization_endpoint', 'token_endpoint', 'jwks_uri') as $field) {
            if (empty($document[$field])) {
                throw new ICC_OpenID_Client_Error(
                    'discovery-missing-fields',
                    'The discovery document is missing the required "' . $field . '" value.'
                );
            }
        }

        $this->log('Loaded configuration from ' . $url, 'discovery');

        return $document;
    }

    /**
     * Map a discovery document to plugin settings keys.
     *
     * @param array $document Discovery document.
     *
     * @return array Settings key => value.
     */
    public function map_discovery_to_settings(array $document)
    {
        $map = array(
            'authorization_endpoint'         => 'endpoint_login',
            'token_endpoint'                 => 'endpoint_token',
            'userinfo_endpoint'              => 'endpoint_userinfo',
            'end_session_endpoint'           => 'endpoint_end_session',
            'jwks_uri'                       => 'endpoint_jwks',
            'issuer'                         => 'issuer',
        );

        $values = array();

        foreach ($map as $document_key => $setting_key) {
            if (!empty($document[$document_key]) && is_string($document[$document_key])) {
                $values[$setting_key] = $document[$document_key];
            }
        }

        return $values;
    }
}
