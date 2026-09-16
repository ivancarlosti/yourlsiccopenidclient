<?php
/**
 * JWT / JWKS validation without third party dependencies.
 *
 * Signatures are verified with ext-openssl (openssl_verify) and claims are
 * validated here, so no vendored JWT library is required.
 *
 * Supported: RS256, RS384, RS512, ES256, ES384, ES512.
 * PS* needs phpseclib and EdDSA needs ext-sodium; unsupported algorithms are
 * rejected instead of being silently accepted.
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
 * ICC_OpenID_Client_JWT class.
 */
class ICC_OpenID_Client_JWT
{
    /**
     * Allowed clock skew, in seconds.
     */
    const LEEWAY = 60;

    /**
     * JWKS cache option name.
     */
    const CACHE_OPTION = 'icc_oidc_jwks_cache';

    /**
     * Supported signature algorithms.
     *
     * @var array
     */
    protected static $supported_algs = array(
        'RS256' => array('kty' => 'RSA', 'hash' => 'sha256'),
        'RS384' => array('kty' => 'RSA', 'hash' => 'sha384'),
        'RS512' => array('kty' => 'RSA', 'hash' => 'sha512'),
        'ES256' => array('kty' => 'EC', 'hash' => 'sha256', 'crv' => 'P-256', 'size' => 32),
        'ES384' => array('kty' => 'EC', 'hash' => 'sha384', 'crv' => 'P-384', 'size' => 48),
        'ES512' => array('kty' => 'EC', 'hash' => 'sha512', 'crv' => 'P-521', 'size' => 66),
    );

    /** @var string JWKS endpoint URL. */
    protected $jwks_uri;

    /** @var string Expected audience (OAuth client ID). */
    protected $client_id;

    /** @var string Expected issuer. */
    protected $issuer;

    /** @var int JWKS cache lifetime, in seconds. */
    protected $cache_ttl;

    /** @var bool Whether internal/private IdP endpoints are allowed. */
    protected $allow_internal_idp;

    /** @var object|null Optional logger exposing log($message, $type). */
    protected $logger;

    /** @var callable|null HTTP transport: function($method, $url, $headers, $data, $options). */
    protected $http;

    /** @var int Request timeout, in seconds. */
    protected $timeout = 5;

    /** @var bool Whether to verify remote SSL certificates. */
    protected $ssl_verify = true;

    /**
     * @param string      $jwks_uri           JWKS endpoint URL.
     * @param string      $client_id          Expected audience.
     * @param string      $issuer             Expected issuer.
     * @param int         $cache_ttl          JWKS cache lifetime in seconds.
     * @param bool        $allow_internal_idp Allow internal/private endpoints.
     * @param object|null $logger             Optional logger.
     * @param callable    $http               Optional HTTP transport.
     * @param int         $timeout            Request timeout in seconds.
     * @param bool        $ssl_verify         Verify remote certificates.
     */
    public function __construct(
        $jwks_uri,
        $client_id,
        $issuer,
        $cache_ttl,
        $allow_internal_idp,
        $logger = null,
        $http = null,
        $timeout = 5,
        $ssl_verify = true
    ) {
        $this->jwks_uri = (string) $jwks_uri;
        $this->client_id = (string) $client_id;
        $this->issuer = (string) $issuer;
        $this->cache_ttl = intval($cache_ttl) > 0 ? intval($cache_ttl) : 3600;
        $this->allow_internal_idp = (bool) $allow_internal_idp;
        $this->logger = $logger;
        $this->http = $http;
        $this->timeout = intval($timeout) > 0 ? intval($timeout) : 5;
        $this->ssl_verify = (bool) $ssl_verify;
    }

    /**
     * List of supported algorithms.
     *
     * @return array
     */
    public static function supported_algorithms()
    {
        return array_keys(self::$supported_algs);
    }

    /**
     * Write a message to the log.
     *
     * @param string $message Message.
     * @param string $type    Log type.
     *
     * @return void
     */
    protected function log($message, $type = 'jwt')
    {
        if (is_object($this->logger) && method_exists($this->logger, 'log')) {
            $this->logger->log($message, $type);
        }
    }

    /**
     * Strict base64url decoding.
     *
     * @param string $input Base64url encoded string.
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the input is not valid base64url.
     */
    protected function base64url_decode($input)
    {
        $input = (string) $input;

        if ($input === '') {
            throw new ICC_OpenID_Client_Error('invalid-base64url', 'Empty base64url value.');
        }

        if (preg_match('/[^A-Za-z0-9_-]/', $input)) {
            throw new ICC_OpenID_Client_Error('invalid-base64url', 'Invalid base64url characters.');
        }

        $remainder = strlen($input) % 4;

        if ($remainder === 1) {
            throw new ICC_OpenID_Client_Error('invalid-base64url', 'Invalid base64url length.');
        }

        if ($remainder > 0) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($input, '-_', '+/'), true);

        if ($decoded === false) {
            throw new ICC_OpenID_Client_Error('invalid-base64url', 'Unable to decode base64url value.');
        }

        return $decoded;
    }

    /**
     * Decode a JSON segment of a JWT.
     *
     * @param string $segment Base64url encoded JSON.
     *
     * @return array
     *
     * @throws ICC_OpenID_Client_Error When the segment is not a JSON object.
     */
    protected function decode_json_segment($segment)
    {
        $decoded = json_decode($this->base64url_decode($segment), true);

        if (!is_array($decoded)) {
            throw new ICC_OpenID_Client_Error('invalid-jwt-segment', 'JWT segment is not a JSON object.');
        }

        return $decoded;
    }

    /**
     * Split a compact JWS into its three parts.
     *
     * @param string $jwt Compact JWS.
     *
     * @return array array(string $header, string $payload, string $signature)
     *
     * @throws ICC_OpenID_Client_Error When the token is not a compact JWS.
     */
    public function split($jwt)
    {
        $parts = explode('.', (string) $jwt);

        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new ICC_OpenID_Client_Error('malformed-jwt', 'Malformed JWT: expected a compact JWS with 3 parts.');
        }

        return $parts;
    }

    /**
     * Parse and validate the JWT header.
     *
     * The algorithm is taken from the header but must be part of the allowlist,
     * so a token can never select its own verification method.
     *
     * @param string $jwt Compact JWS.
     *
     * @return array
     *
     * @throws ICC_OpenID_Client_Error When the header is invalid or unsupported.
     */
    public function parse_header($jwt)
    {
        $parts = $this->split($jwt);
        $header = $this->decode_json_segment($parts[0]);

        if (empty($header['alg']) || !is_string($header['alg'])) {
            throw new ICC_OpenID_Client_Error('missing-alg', 'JWT header has no "alg" value.');
        }

        if ($header['alg'] === 'none' || !isset(self::$supported_algs[$header['alg']])) {
            throw new ICC_OpenID_Client_Error(
                'unsupported-alg',
                'Unsupported JWT algorithm: ' . $header['alg'] . ' (supported: ' . implode(', ', self::supported_algorithms()) . ')'
            );
        }

        // We understand no JOSE extensions: a "crit" header must be rejected (RFC 7515, 4.1.11).
        if (!empty($header['crit'])) {
            throw new ICC_OpenID_Client_Error('unsupported-crit', 'JWT uses unsupported critical header parameters.');
        }

        return $header;
    }


    /**
     * Perform a guarded HTTP GET against a plugin controlled endpoint.
     *
     * @param string $url     URL to request.
     * @param array  $headers Extra headers.
     *
     * @return array array('status' => int, 'body' => string)
     *
     * @throws ICC_OpenID_Client_Error When the URL is not allowed or the request fails.
     */
    protected function http_get($url, $headers = array())
    {
        ICC_OpenID_Client_HTTP::guard_url($url, $this->allow_internal_idp);

        $options = ICC_OpenID_Client_HTTP::default_options($this->timeout, $this->ssl_verify);

        if (is_callable($this->http)) {
            return call_user_func($this->http, 'GET', $url, $headers, array(), $options);
        }

        return ICC_OpenID_Client_HTTP::request('GET', $url, $headers, array(), $options);
    }

    /**
     * Fetch the JWKS from the identity provider, using a cached copy when fresh.
     *
     * @param bool $force Skip the cache and fetch again.
     *
     * @return array The JWKS document.
     *
     * @throws ICC_OpenID_Client_Error When no JWKS can be retrieved.
     */
    public function get_jwks($force = false)
    {
        if (trim($this->jwks_uri) === '') {
            throw new ICC_OpenID_Client_Error(
                'jwks-not-configured',
                'No JWKS endpoint configured: ID token signatures cannot be verified.'
            );
        }

        if (!$force) {
            $cached = yourls_get_option(self::CACHE_OPTION);

            if (
                is_array($cached)
                && isset($cached['url'], $cached['expires'], $cached['jwks'])
                && $cached['url'] === $this->jwks_uri
                && intval($cached['expires']) > time()
                && is_array($cached['jwks'])
            ) {
                return $cached['jwks'];
            }
        }

        $response = $this->http_get($this->jwks_uri, array('Accept' => 'application/json'));

        if (intval($response['status']) !== 200) {
            throw new ICC_OpenID_Client_Error(
                'jwks-fetch-failed',
                'Unable to fetch JWKS: HTTP status ' . intval($response['status'])
            );
        }

        $jwks = json_decode($response['body'], true);

        if (!is_array($jwks) || empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new ICC_OpenID_Client_Error('jwks-invalid', 'Invalid JWKS document (missing "keys").');
        }

        yourls_update_option(
            self::CACHE_OPTION,
            array(
                'url'     => $this->jwks_uri,
                'expires' => time() + $this->cache_ttl,
                'jwks'    => $jwks,
            )
        );

        $this->log('Fetched JWKS from ' . $this->jwks_uri, 'jwks-fetch');

        return $jwks;
    }

    /**
     * Select the JWKS keys that may have signed a token.
     *
     * @param array $jwks   JWKS document.
     * @param array $header JWT header.
     *
     * @return array List of candidate keys.
     *
     * @throws ICC_OpenID_Client_Error When no key matches.
     */
    protected function select_keys($jwks, $header)
    {
        $alg = self::$supported_algs[$header['alg']];
        $kid = isset($header['kid']) ? (string) $header['kid'] : '';
        $candidates = array();

        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new ICC_OpenID_Client_Error('jwks-invalid', 'JWKS document contains no keys.');
        }

        foreach ($jwks['keys'] as $key) {
            if (!is_array($key) || empty($key['kty'])) {
                continue;
            }

            if ($key['kty'] !== $alg['kty']) {
                continue;
            }

            if (!empty($key['use']) && $key['use'] !== 'sig') {
                continue;
            }

            if (!empty($key['alg']) && $key['alg'] !== $header['alg']) {
                continue;
            }

            if ($kid !== '' && isset($key['kid']) && (string) $key['kid'] !== '') {
                if ((string) $key['kid'] === $kid) {
                    // Exact key ID match: highest priority.
                    array_unshift($candidates, $key);
                    continue;
                }

                continue;
            }

            $candidates[] = $key;
        }

        if (empty($candidates)) {
            throw new ICC_OpenID_Client_Error('no-matching-key', 'No JWKS key matches the token header (kid/alg/kty).');
        }

        return $candidates;
    }


    /**
     * Encode an ASN.1 DER length.
     *
     * @param int $length Length to encode.
     *
     * @return string
     */
    protected static function der_length($length)
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length = $length >> 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Encode a positive ASN.1 DER INTEGER from unsigned big-endian bytes.
     *
     * @param string $bytes Unsigned big-endian value.
     *
     * @return string
     */
    protected static function der_integer($bytes)
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        if (ord($bytes[0]) > 0x7F) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::der_length(strlen($bytes)) . $bytes;
    }

    /**
     * Encode an ASN.1 DER SEQUENCE.
     *
     * @param array $parts Encoded parts.
     *
     * @return string
     */
    protected static function der_sequence(array $parts)
    {
        $body = implode('', $parts);

        return "\x30" . self::der_length(strlen($body)) . $body;
    }

    /**
     * Encode an ASN.1 DER BIT STRING.
     *
     * @param string $bytes Bit string content.
     *
     * @return string
     */
    protected static function der_bit_string($bytes)
    {
        $body = "\x00" . $bytes;

        return "\x03" . self::der_length(strlen($body)) . $body;
    }

    /**
     * Wrap DER bytes into a PEM document.
     *
     * @param string $der   DER bytes.
     * @param string $label PEM label.
     *
     * @return string
     */
    protected static function pem($der, $label = 'PUBLIC KEY')
    {
        return "-----BEGIN " . $label . "-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END " . $label . "-----\n";
    }

    /**
     * Build a PEM public key from a JWK.
     *
     * @param array  $jwk JWK.
     * @param string $alg Token algorithm (defines the expected key type/curve).
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the key cannot be represented.
     */
    protected function jwk_to_pem($jwk, $alg)
    {
        $spec = self::$supported_algs[$alg];

        // A certificate chain may be provided instead of raw key material.
        if (!empty($jwk['x5c']) && is_array($jwk['x5c']) && isset($jwk['x5c'][0])) {
            $certificate = base64_decode(str_replace(array("\n", "\r", ' '), '', (string) $jwk['x5c'][0]), true);

            if ($certificate !== false) {
                return self::pem($certificate, 'CERTIFICATE');
            }
        }

        if ($spec['kty'] === 'RSA') {
            if (empty($jwk['n']) || empty($jwk['e'])) {
                throw new ICC_OpenID_Client_Error('invalid-jwk', 'RSA JWK is missing "n" or "e".');
            }

            $modulus = $this->base64url_decode($jwk['n']);
            $exponent = $this->base64url_decode($jwk['e']);

            $algorithm = self::der_sequence(array(
                "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", // rsaEncryption (1.2.840.113549.1.1.1)
                "\x05\x00",                                       // NULL
            ));

            $public_key = self::der_sequence(array(
                self::der_integer($modulus),
                self::der_integer($exponent),
            ));

            return self::pem(self::der_sequence(array($algorithm, self::der_bit_string($public_key))));
        }

        // EC keys.
        $curves = array(
            'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", // prime256v1 (1.2.840.10045.3.1.7)
            'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",             // secp384r1 (1.3.132.0.34)
            'P-521' => "\x06\x05\x2b\x81\x04\x00\x23",             // secp521r1 (1.3.132.0.35)
        );

        $crv = isset($jwk['crv']) ? (string) $jwk['crv'] : '';

        if ($crv !== $spec['crv']) {
            throw new ICC_OpenID_Client_Error(
                'invalid-jwk',
                'EC key curve "' . $crv . '" does not match algorithm ' . $alg . ' (expected ' . $spec['crv'] . ').'
            );
        }

        if (empty($jwk['x']) || empty($jwk['y'])) {
            throw new ICC_OpenID_Client_Error('invalid-jwk', 'EC JWK is missing "x" or "y".');
        }

        $algorithm = self::der_sequence(array(
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01", // id-ecPublicKey (1.2.840.10045.2.1)
            $curves[$crv],
        ));

        $size = isset($spec['size']) ? intval($spec['size']) : 32;

        // EC coordinates have to be exactly $size bytes (RFC 7518). Providers
        // normally pad them with leading zeros, but a coordinate without them
        // would build an invalid public key point, so pad defensively.
        $point = "\x04"
            . str_pad($this->base64url_decode($jwk['x']), $size, "\x00", STR_PAD_LEFT)
            . str_pad($this->base64url_decode($jwk['y']), $size, "\x00", STR_PAD_LEFT);

        return self::pem(self::der_sequence(array($algorithm, self::der_bit_string($point))));
    }

    /**
     * Convert a JOSE ECDSA signature (raw r || s) to DER, as expected by OpenSSL.
     *
     * @param string $signature Raw signature.
     * @param int    $size      Component size in bytes (32 for P-256, 48 for P-384, 66 for P-521).
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the signature length is wrong.
     */
    protected function jose_signature_to_der($signature, $size)
    {
        if (strlen($signature) !== $size * 2) {
            throw new ICC_OpenID_Client_Error(
                'invalid-signature-length',
                'Invalid ECDSA signature length: expected ' . ($size * 2) . ' bytes, got ' . strlen($signature) . '.'
            );
        }

        return self::der_sequence(array(
            self::der_integer(substr($signature, 0, $size)),
            self::der_integer(substr($signature, $size, $size)),
        ));
    }


    /**
     * Try to verify a signature against a list of candidate keys.
     *
     * @param string $signing_input Header.payload as received.
     * @param string $signature     Raw (decoded) signature.
     * @param array  $header        JWT header.
     * @param array  $keys          Candidate JWKs.
     *
     * @return bool True when one of the keys validates the signature.
     */
    protected function verify_with_keys($signing_input, $signature, $header, $keys)
    {
        $spec = self::$supported_algs[$header['alg']];
        $errors = array();

        foreach ($keys as $key) {
            try {
                $pem = $this->jwk_to_pem($key, $header['alg']);
            } catch (ICC_OpenID_Client_Error $error) {
                $errors[] = $error->getMessage();
                continue;
            }

            $public_key = openssl_pkey_get_public($pem);

            if ($public_key === false) {
                $errors[] = 'Unable to load public key: ' . openssl_error_string();
                continue;
            }

            $verifiable = $signature;

            if ($spec['kty'] === 'EC') {
                try {
                    $verifiable = $this->jose_signature_to_der($signature, $spec['size']);
                } catch (ICC_OpenID_Client_Error $error) {
                    $errors[] = $error->getMessage();
                    continue;
                }
            }

            $result = openssl_verify($signing_input, $verifiable, $public_key, $spec['hash']);

            if ($result === 1) {
                return true;
            }

            $errors[] = $result === 0 ? 'Signature does not match key.' : 'OpenSSL error: ' . openssl_error_string();
        }

        $this->log('Signature verification failed: ' . implode(' ', array_unique($errors)), 'jwt-signature');

        return false;
    }

    /**
     * Verify the signature of a compact JWS and return its claims.
     *
     * The JWKS is fetched (and cached) when not provided. When a signature does
     * not validate, the key set is fetched once more to cope with key rotation.
     *
     * @param string     $jwt  Compact JWS.
     * @param array|null $jwks Optional JWKS document (used by tests).
     *
     * @return array Verified claims.
     *
     * @throws ICC_OpenID_Client_Error When the token is malformed or not trusted.
     */
    public function verify_signature($jwt, $jwks = null)
    {
        $header = $this->parse_header($jwt);
        $parts = $this->split($jwt);
        $signing_input = $parts[0] . '.' . $parts[1];
        $signature = $this->base64url_decode($parts[2]);

        $key_set = is_array($jwks) ? $jwks : $this->get_jwks();

        $selection_error = null;

        try {
            $keys = $this->select_keys($key_set, $header);
        } catch (ICC_OpenID_Client_Error $error) {
            $keys = array();
            $selection_error = $error;
        }

        if (!empty($keys) && $this->verify_with_keys($signing_input, $signature, $header, $keys)) {
            return $this->decode_json_segment($parts[1]);
        }

        // Signature or key lookup failed: refresh the JWKS once (key rotation) and retry.
        if (!is_array($jwks)) {
            $fresh = $this->get_jwks(true);
            $keys = $this->select_keys($fresh, $header);

            if ($this->verify_with_keys($signing_input, $signature, $header, $keys)) {
                return $this->decode_json_segment($parts[1]);
            }
        }

        // Report the most useful error: no usable key at all, or a bad signature.
        if (!empty($selection_error)) {
            throw $selection_error;
        }

        throw new ICC_OpenID_Client_Error(
            'invalid-signature',
            'JWT signature could not be verified with the identity provider keys.'
        );
    }



    /**
     * Validate the standard claims of an ID token.
     *
     * @param array       $claims Decoded claims.
     * @param string|null $nonce  Expected nonce (null to skip the nonce check).
     *
     * @return bool True when the claims are valid.
     *
     * @throws ICC_OpenID_Client_Error When a claim is missing or invalid.
     */
    public function validate_claims($claims, $nonce = null)
    {
        if (!is_array($claims)) {
            throw new ICC_OpenID_Client_Error('invalid-claims', 'The token claims are not an array.');
        }

        // Subject identity: required, it is what links the account to the IdP user.
        if (empty($claims['sub']) || !is_string($claims['sub'])) {
            throw new ICC_OpenID_Client_Error('no-subject-identity', 'Token has no "sub" claim.');
        }

        $now = time();

        // Expiration.
        if (!isset($claims['exp']) || !is_numeric($claims['exp'])) {
            throw new ICC_OpenID_Client_Error('missing-exp', 'Token has no "exp" claim.');
        }

        if ($now - self::LEEWAY >= intval($claims['exp'])) {
            throw new ICC_OpenID_Client_Error('token-expired', 'Token has expired.');
        }

        // Issued at.
        if (!isset($claims['iat']) || !is_numeric($claims['iat'])) {
            throw new ICC_OpenID_Client_Error('missing-iat', 'Token has no "iat" claim.');
        }

        if (intval($claims['iat']) > $now + self::LEEWAY) {
            throw new ICC_OpenID_Client_Error('token-issued-in-future', 'Token "iat" claim is in the future.');
        }

        // Not before (optional).
        if (isset($claims['nbf'])) {
            if (!is_numeric($claims['nbf'])) {
                throw new ICC_OpenID_Client_Error('invalid-nbf', 'Token "nbf" claim is not numeric.');
            }

            if (intval($claims['nbf']) > $now + self::LEEWAY) {
                throw new ICC_OpenID_Client_Error('token-not-yet-valid', 'Token is not valid yet ("nbf").');
            }
        }

        // Audience.
        if (!isset($claims['aud'])) {
            throw new ICC_OpenID_Client_Error('missing-aud', 'Token has no "aud" claim.');
        }

        $audience = is_array($claims['aud']) ? $claims['aud'] : array($claims['aud']);
        $audience = array_map('strval', $audience);

        if ($this->client_id === '' || !in_array($this->client_id, $audience, true)) {
            throw new ICC_OpenID_Client_Error('invalid-aud', 'Token audience does not match the configured client ID.');
        }

        if (isset($claims['azp'])) {
            if ((string) $claims['azp'] !== $this->client_id) {
                throw new ICC_OpenID_Client_Error('invalid-azp', 'Token "azp" claim does not match the configured client ID.');
            }
        } elseif (count($audience) > 1) {
            throw new ICC_OpenID_Client_Error('missing-azp', 'Token has multiple audiences but no "azp" claim.');
        }

        // Issuer.
        $expected_issuer = trim($this->issuer);

        if ($expected_issuer !== '') {
            if (empty($claims['iss']) || !is_string($claims['iss'])) {
                throw new ICC_OpenID_Client_Error('missing-iss', 'Token has no "iss" claim.');
            }

            if (rtrim($claims['iss'], '/') !== rtrim($expected_issuer, '/')) {
                throw new ICC_OpenID_Client_Error(
                    'invalid-iss',
                    'Token issuer "' . $claims['iss'] . '" does not match the configured issuer "' . $expected_issuer . '".'
                );
            }
        }

        // Nonce, when this login attempt started with one.
        if ($nonce !== null) {
            if (empty($claims['nonce']) || !is_string($claims['nonce']) || !hash_equals((string) $nonce, $claims['nonce'])) {
                throw new ICC_OpenID_Client_Error('invalid-nonce', 'Token nonce does not match this login attempt.');
            }
        }

        return true;
    }

    /**
     * Verify and validate an ID token in one step.
     *
     * @param string      $id_token Compact JWS.
     * @param string|null $nonce    Expected nonce.
     * @param array|null  $jwks     Optional JWKS document (used by tests).
     *
     * @return array Validated claims.
     *
     * @throws ICC_OpenID_Client_Error When the token is invalid.
     */
    public function validate_id_token($id_token, $nonce = null, $jwks = null)
    {
        $claims = $this->verify_signature($id_token, $jwks);
        $this->validate_claims($claims, $nonce);

        return $claims;
    }
}
