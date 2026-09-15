<?php
/**
 * Thin HTTP wrapper around the YOURLS HTTP helpers.
 *
 * Keeps every outbound request in one place so that timeouts, SSL verification
 * and SSRF protection are applied consistently.
 *
 * @package   ICC_OpenID_Client
 * @category  HTTP
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * ICC_OpenID_Client_HTTP class.
 */
class ICC_OpenID_Client_HTTP
{
    /**
     * Perform a request and return a normalized response.
     *
     * @param string $method  HTTP method, GET or POST.
     * @param string $url     Target URL.
     * @param array  $headers Extra request headers.
     * @param mixed  $data    Query parameters (GET) or encoded body (POST).
     * @param array  $options Request options (timeout, verify...).
     *
     * @return array array('status' => int, 'body' => string, 'headers' => array)
     *
     * @throws ICC_OpenID_Client_Error When the request fails.
     */
    public static function request($method, $url, $headers = array(), $data = array(), $options = array())
    {
        $method = strtoupper($method) === 'POST' ? 'POST' : 'GET';
        $options = array_merge(self::default_options(), $options);

        if ($method === 'POST') {
            $response = yourls_http_post($url, $headers, $data, $options);
        } else {
            $response = yourls_http_get($url, $headers, $data, $options);
        }

        // The YOURLS helper returns a string error message when the request fails.
        if (is_string($response)) {
            throw new ICC_OpenID_Client_Error('http-request-failed', $response);
        }

        if (!is_object($response) || !isset($response->status_code)) {
            throw new ICC_OpenID_Client_Error('http-invalid-response', 'Invalid HTTP response from ' . $url);
        }

        return array(
            'status'  => intval($response->status_code),
            'body'    => isset($response->body) ? (string) $response->body : '',
            'headers' => isset($response->headers) && is_object($response->headers) ? (array) $response->headers : array(),
        );
    }

    /**
     * Default request options.
     *
     * @param int  $timeout Request timeout in seconds.
     * @param bool $verify  Whether to verify the remote SSL certificate.
     *
     * @return array
     */
    public static function default_options($timeout = 5, $verify = true)
    {
        $options = array(
            'timeout'          => intval($timeout) > 0 ? intval($timeout) : 5,
            'follow_redirects' => true,
            'redirects'        => 3,
        );

        if ($verify === false) {
            $options['verify'] = false;
        }

        return $options;
    }

    /**
     * Encode a value as an application/x-www-form-urlencoded body.
     *
     * @param array $data Data to encode.
     *
     * @return string
     */
    public static function encode_body(array $data)
    {
        return http_build_query($data, '', '&');
    }

    /**
     * Validate a remote URL before requesting it.
     *
     * Blocks non HTTP(S) schemes, plain HTTP (unless internal IdPs are allowed)
     * and hosts on the local/private network, to avoid SSRF from configuration
     * values that a lower privileged user may be able to influence.
     *
     * @param string $url            URL to validate.
     * @param bool   $allow_internal Whether internal/private endpoints are allowed.
     *
     * @return string The validated URL.
     *
     * @throws ICC_OpenID_Client_Error When the URL must not be requested.
     */
    public static function guard_url($url, $allow_internal = false)
    {
        $parts = parse_url((string) $url);

        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new ICC_OpenID_Client_Error('invalid-url', 'Invalid URL: ' . $url);
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new ICC_OpenID_Client_Error('invalid-url-scheme', 'Unsupported URL scheme: ' . $scheme);
        }

        if ($allow_internal) {
            return $url;
        }

        if ($scheme !== 'https') {
            throw new ICC_OpenID_Client_Error('url-not-https', 'Only HTTPS endpoints are allowed: ' . $url);
        }

        if (icc_oidc_host_is_local($parts['host'])) {
            throw new ICC_OpenID_Client_Error(
                'url-local-host',
                'The endpoint host resolves to a local/private address: ' . $parts['host']
            );
        }

        return $url;
    }
}
