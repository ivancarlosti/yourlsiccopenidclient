<?php
/**
 * Test suite for the ICC OpenID Connect Client YOURLS plugin.
 *
 * Runs without YOURLS, MySQL, PHPUnit or any other dependency:
 *
 *     php tests/run-tests.php
 *
 * The YOURLS functions used by the plugin are stubbed below so the protocol,
 * validation and flow logic can be exercised in isolation, including the
 * official RFC 7515 test vectors for RS256 and ES256.
 *
 * @package ICC_OpenID_Client
 */

// ---------------------------------------------------------------------------
// Minimal YOURLS environment
// ---------------------------------------------------------------------------

define('YOURLS_ABSPATH', dirname(__DIR__) . '/');
define('YOURLS_SITE', 'https://sho.rt');
define('YOURLS_COOKIEKEY', 'test-cookie-key');
define('ICC_OIDC_TESTING', true);

$GLOBALS['icc'] = array(
    'options'  => array(),
    'users'    => array(),   // stands for $yourls_user_passwords
    'hooks'    => array(),
    'actions'  => array(),
    'debug'    => array(),
    'cookie'   => null,
    'set_user' => null,
    'http'     => null,      // callable($method, $url, $headers, $data, $options)
    'http_log' => array(),
    'is_api'   => false,
);

class ICC_Test_Redirect extends Exception
{
    public $url;
    public $status;

    public function __construct($url, $status = 0)
    {
        parent::__construct('Redirect to ' . $url);
        $this->url = $url;
        $this->status = $status;
    }
}

class ICC_Test_Die extends Exception
{
    public $title;

    public function __construct($message = '', $title = '')
    {
        parent::__construct((string) $message);
        $this->title = $title;
    }
}

class ICC_Test_Response
{
    public $status_code;
    public $body;
    public $headers;

    public function __construct($status_code, $body, $headers = array())
    {
        $this->status_code = $status_code;
        $this->body = $body;
        $this->headers = $headers;
    }
}

// ---------------------------------------------------------------------------
// YOURLS function stubs
// ---------------------------------------------------------------------------

function yourls_get_option($name, $default = false)
{
    return array_key_exists($name, $GLOBALS['icc']['options']) ? $GLOBALS['icc']['options'][$name] : $default;
}

function yourls_update_option($name, $value)
{
    $GLOBALS['icc']['options'][$name] = $value;

    return true;
}

function yourls_delete_option($name)
{
    unset($GLOBALS['icc']['options'][$name]);

    return true;
}

function yourls_add_action($hook, $function_to_add, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['icc']['hooks'][$hook][] = $function_to_add;

    return true;
}

function yourls_add_filter($hook, $function_to_add, $priority = 10, $accepted_args = 1)
{
    return yourls_add_action($hook, $function_to_add, $priority, $accepted_args);
}

function yourls_do_action($hook)
{
    $GLOBALS['icc']['actions'][] = $hook;
}

function yourls_apply_filter($hook, $value)
{
    return $value;
}

function yourls_redirect($url, $status = 301)
{
    throw new ICC_Test_Redirect($url, $status);
}

function yourls_die($message = '', $title = '', $code = 200)
{
    throw new ICC_Test_Die($message, $title);
}

function yourls_store_cookie($user = '')
{
    $GLOBALS['icc']['cookie'] = $user;
}

function yourls_cookie_name()
{
    return 'yourls_testcookie';
}

function yourls_cookie_value($user)
{
    return 'cookie-value-' . hash('sha256', '|' . $user);
}

function yourls_set_user($user)
{
    $GLOBALS['icc']['set_user'] = $user;
}

function yourls_salt($string)
{
    return hash_hmac('sha256', $string, YOURLS_COOKIEKEY);
}

function yourls_get_yourls_site()
{
    return YOURLS_SITE . '/';
}

function yourls_site_url($echo = true, $url = '')
{
    return YOURLS_SITE . '/' . ltrim((string) $url, '/');
}

function yourls_admin_url($url = '')
{
    return YOURLS_SITE . '/admin/' . ltrim((string) $url, '/');
}

function yourls_is_API()
{
    return (bool) $GLOBALS['icc']['is_api'];
}

function yourls_debug_log($message)
{
    $GLOBALS['icc']['debug'][] = $message;

    return $message;
}

function yourls_esc_html($text)
{
    return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
}

function yourls_esc_attr($text)
{
    return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
}

function yourls_esc_url($url)
{
    return htmlspecialchars((string) $url, ENT_QUOTES, 'UTF-8');
}

function yourls_create_nonce($action, $user = false)
{
    return 'nonce-' . md5($action . '|' . (string) $user);
}

function yourls_nonce_field($action, $name = 'nonce', $user = false, $echo = true)
{
    $field = '<input type="hidden" name="' . $name . '" value="' . yourls_create_nonce($action, $user) . '" />';

    if ($echo) {
        echo $field;
    }

    return $field;
}

function yourls_nonce_url($action, $url = false, $name = 'nonce', $user = false)
{
    $url = (string) $url;
    $separator = strpos($url, '?') === false ? '?' : '&';

    return $url . $separator . $name . '=' . yourls_create_nonce($action, $user);
}

/**
 * Mirrors YOURLS' variadic yourls_add_query_arg(): both
 * yourls_add_query_arg(array $args, $uri) and yourls_add_query_arg($key, $value, $uri).
 */
function yourls_add_query_arg($param, $value = false, $url = false)
{
    if (is_array($param)) {
        $args = $param;
        $uri = $value === false ? (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '') : $value;
    } else {
        $args = array($param => $value);
        $uri = $url === false ? (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '') : $url;
    }

    $separator = strpos($uri, '?') === false ? '?' : '&';
    $pairs = array();

    foreach ($args as $key => $item) {
        $pairs[] = rawurlencode($key) . '=' . rawurlencode($item);
    }

    return $uri . $separator . implode('&', $pairs);
}

function yourls_verify_nonce($action, $nonce = false, $user = false, $return = '')
{
    return true;
}

function yourls_http_get($url, $headers = array(), $data = array(), $options = array())
{
    return icc_test_http_dispatch('GET', $url, $headers, $data, $options);
}

function yourls_http_post($url, $headers = array(), $data = array(), $options = array())
{
    return icc_test_http_dispatch('POST', $url, $headers, $data, $options);
}

/**
 * Dispatch a stubbed HTTP request through the handler configured by the test.
 */
function icc_test_http_dispatch($method, $url, $headers, $data, $options)
{
    $GLOBALS['icc']['http_log'][] = array(
        'method'  => $method,
        'url'     => $url,
        'headers' => $headers,
        'data'    => $data,
    );

    if (!is_callable($GLOBALS['icc']['http'])) {
        return 'stub: no HTTP handler configured';
    }

    $response = call_user_func($GLOBALS['icc']['http'], $method, $url, $headers, $data, $options);

    if (is_string($response)) {
        return $response;
    }

    return new ICC_Test_Response(
        isset($response['status']) ? $response['status'] : 200,
        isset($response['body']) ? $response['body'] : ''
    );
}

// ---------------------------------------------------------------------------
// Plugin under test
// ---------------------------------------------------------------------------

require_once YOURLS_ABSPATH . 'includes/functions-icc-openid-client.php';

// ---------------------------------------------------------------------------
// Tiny test harness
// ---------------------------------------------------------------------------

class ICC_Test_Assertion extends Exception
{
}

$GLOBALS['icc_tests'] = array();
$GLOBALS['icc_results'] = array('pass' => 0, 'fail' => 0, 'failures' => array());

function test($name, $callback)
{
    $GLOBALS['icc_tests'][] = array($name, $callback);
}

function icc_test_pass($name)
{
    $GLOBALS['icc_results']['pass']++;
    echo "  \033[32mPASS\033[0m " . $name . "\n";
}

function icc_test_fail($name, $message)
{
    $GLOBALS['icc_results']['fail']++;
    $GLOBALS['icc_results']['failures'][] = $name . ' -> ' . $message;
    echo "  \033[31mFAIL\033[0m " . $name . "\n         " . $message . "\n";
}

function assert_true($condition, $message = 'expected true')
{
    if (!$condition) {
        throw new ICC_Test_Assertion($message);
    }
}

function assert_false($condition, $message = 'expected false')
{
    if ($condition) {
        throw new ICC_Test_Assertion($message);
    }
}

function assert_same($expected, $actual, $message = '')
{
    if ($expected !== $actual) {
        throw new ICC_Test_Assertion(
            ($message !== '' ? $message . ': ' : '')
            . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true)
        );
    }
}

function assert_contains($needle, $haystack, $message = '')
{
    if (strpos((string) $haystack, (string) $needle) === false) {
        throw new ICC_Test_Assertion(
            ($message !== '' ? $message . ': ' : '') . 'expected to find ' . var_export($needle, true)
            . ' in ' . var_export($haystack, true)
        );
    }
}

function assert_not_contains($needle, $haystack, $message = '')
{
    if (strpos((string) $haystack, (string) $needle) !== false) {
        throw new ICC_Test_Assertion(($message !== '' ? $message . ': ' : '') . 'did not expect ' . var_export($needle, true));
    }
}

/**
 * Assert that a callback throws a given exception class.
 */
function assert_throws($class, $callback, $message = '')
{
    try {
        call_user_func($callback);
    } catch (Exception $error) {
        if ($error instanceof $class) {
            return $error;
        }

        throw new ICC_Test_Assertion(
            'expected ' . $class . ', got ' . get_class($error) . ': ' . $error->getMessage()
        );
    }

    throw new ICC_Test_Assertion('expected ' . $class . ' to be thrown' . ($message !== '' ? ' (' . $message . ')' : ''));
}

/**
 * Assert that a callback throws ICC_OpenID_Client_Error with a given error code.
 */
function assert_error_code($expected_code, $callback)
{
    $error = assert_throws('ICC_OpenID_Client_Error', $callback);

    assert_same($expected_code, $error->error_code(), 'error code');

    return $error;
}

/**
 * Reset the stubbed environment between tests.
 */
function icc_reset()
{
    $GLOBALS['icc']['options'] = array();
    $GLOBALS['icc']['hooks'] = array();
    $GLOBALS['icc']['actions'] = array();
    $GLOBALS['icc']['debug'] = array();
    $GLOBALS['icc']['cookie'] = null;
    $GLOBALS['icc']['set_user'] = null;
    $GLOBALS['icc']['http'] = null;
    $GLOBALS['icc']['http_log'] = array();
    $GLOBALS['icc']['is_api'] = false;
    $GLOBALS['yourls_user_passwords'] = array();

    $_GET = array();
    $_POST = array();
    $_COOKIE = array();
    $_REQUEST = array();
    $_SERVER = array('REQUEST_URI' => '/admin/index.php', 'HTTP_HOST' => 'sho.rt', 'HTTPS' => 'on');
}


// ---------------------------------------------------------------------------
// Helpers: base64url, JWS signing, settings and HTTP stubs
// ---------------------------------------------------------------------------

function icc_b64url($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Convert a DER ECDSA signature to the JOSE (raw r || s) representation.
 */
function icc_der_to_jose($der, $size = 32)
{
    $offset = 2;

    if (ord($der[1]) & 0x80) {
        $offset = 2 + (ord($der[1]) & 0x7F);
    }

    $jose = '';

    for ($i = 0; $i < 2; $i++) {
        if (ord($der[$offset]) !== 0x02) {
            throw new Exception('Unexpected DER structure');
        }

        $length = ord($der[$offset + 1]);
        $integer = substr($der, $offset + 2, $length);
        $offset += 2 + $length;
        $jose .= str_pad(ltrim($integer, "\x00"), $size, "\x00", STR_PAD_LEFT);
    }

    return $jose;
}

/**
 * Create an RSA key pair plus its JWK/JWKS representation.
 */
function icc_make_rsa_key($kid = 'rsa-test-key')
{
    $key = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));

    if ($key === false) {
        throw new Exception('Unable to create an RSA key: ' . openssl_error_string());
    }

    $details = openssl_pkey_get_details($key);

    $jwk = array(
        'kty' => 'RSA',
        'kid' => $kid,
        'alg' => 'RS256',
        'use' => 'sig',
        'n'   => icc_b64url($details['rsa']['n']),
        'e'   => icc_b64url($details['rsa']['e']),
    );

    return array('key' => $key, 'jwk' => $jwk, 'jwks' => array('keys' => array($jwk)));
}

/**
 * Create a P-256 EC key pair plus its JWK/JWKS representation.
 */
function icc_make_ec_key($kid = 'ec-test-key')
{
    $key = openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));

    if ($key === false) {
        throw new Exception('Unable to create an EC key: ' . openssl_error_string());
    }

    $details = openssl_pkey_get_details($key);

    $jwk = array(
        'kty' => 'EC',
        'kid' => $kid,
        'alg' => 'ES256',
        'use' => 'sig',
        'crv' => 'P-256',
        'x'   => icc_b64url($details['ec']['x']),
        'y'   => icc_b64url($details['ec']['y']),
    );

    return array('key' => $key, 'jwk' => $jwk, 'jwks' => array('keys' => array($jwk)));
}

/**
 * Sign a JWT the way an identity provider would.
 */
function icc_sign_jwt($claims, $key, $alg = 'RS256', $extra_header = array())
{
    $header = array_merge(array('alg' => $alg, 'typ' => 'JWT'), $extra_header);
    $signing_input = icc_b64url(json_encode($header)) . '.' . icc_b64url(json_encode($claims));

    $hashes = array('256' => OPENSSL_ALGO_SHA256, '384' => OPENSSL_ALGO_SHA384, '512' => OPENSSL_ALGO_SHA512);
    $suffix = substr($alg, -3);
    $hash = isset($hashes[$suffix]) ? $hashes[$suffix] : OPENSSL_ALGO_SHA256;

    if (!openssl_sign($signing_input, $signature, $key, $hash)) {
        throw new Exception('Unable to sign the test token: ' . openssl_error_string());
    }

    if (strpos($alg, 'ES') === 0) {
        $signature = icc_der_to_jose($signature, $suffix === '512' ? 66 : ($suffix === '384' ? 48 : 32));
    }

    return $signing_input . '.' . icc_b64url($signature);
}

/**
 * Load an RFC 7515 vector fixture.
 */
function icc_load_vector($name)
{
    $file = __DIR__ . '/vectors/' . $name . '.json';
    $vector = json_decode(file_get_contents($file), true);

    if (!is_array($vector)) {
        throw new Exception('Invalid vector fixture: ' . $file);
    }

    return $vector;
}

/**
 * Valid ID token claims.
 */
function icc_valid_claims(array $overrides = array())
{
    return array_merge(
        array(
            'iss'                => 'https://sso.example.com/realms/test',
            'aud'                => 'client-123',
            'sub'                => 'user-abc-123',
            'exp'                => time() + 300,
            'iat'                => time() - 10,
            'nonce'              => 'test-nonce',
            'preferred_username' => 'jdoe',
            'email'              => 'jdoe@example.com',
            'name'               => 'John Doe',
            'given_name'         => 'John',
            'family_name'        => 'Doe',
        ),
        $overrides
    );
}

/**
 * Plugin settings as they would be stored.
 */
function icc_settings(array $overrides = array())
{
    return array_merge(
        array(
            'client_id'                => 'client-123',
            'client_secret'            => 'secret-xyz',
            'scope'                    => 'openid profile email',
            'endpoint_login'           => 'https://sso.example.com/realms/test/protocol/openid-connect/auth',
            'endpoint_token'           => 'https://sso.example.com/realms/test/protocol/openid-connect/token',
            'endpoint_userinfo'        => 'https://sso.example.com/realms/test/protocol/openid-connect/userinfo',
            'endpoint_end_session'     => 'https://sso.example.com/realms/test/protocol/openid-connect/logout',
            'endpoint_jwks'            => 'https://sso.example.com/realms/test/protocol/openid-connect/certs',
            'issuer'                   => 'https://sso.example.com/realms/test',
            'login_type'               => 'button',
            'login_button_text'        => '',
            'login_button_logo_url'    => '',
            'identity_key'             => 'preferred_username',
            'nickname_key'             => 'preferred_username',
            'email_format'             => '{email}',
            'displayname_format'       => '{given_name} {family_name}',
            'email_domain_restriction' => '',
            'redirect_user_back'       => 0,
            'redirect_on_logout'       => 1,
            'redirect_uri'             => '',
            'acr_values'               => '',
            'state_time_limit'         => 180,
            'jwks_cache_ttl'           => 3600,
            'http_request_timeout'     => 5,
            'no_sslverify'             => 0,
            'allow_internal_idp'       => 0,
            'enable_logging'           => 0,
            'log_limit'                => 1000,
        ),
        $overrides
    );
}

/**
 * Build an HTTP transport stub routing by URL fragment.
 */
function icc_http_transport(array $routes)
{
    return function ($method, $url, $headers, $data, $options) use ($routes) {
        foreach ($routes as $needle => $response) {
            if (strpos($url, $needle) !== false) {
                if (is_callable($response)) {
                    return call_user_func($response, $method, $url, $headers, $data);
                }

                return $response;
            }
        }

        return array('status' => 404, 'body' => '{"error":"not_found","error_description":"no route"}');
    };
}

/**
 * JSON HTTP response.
 */
function icc_json_response($payload, $status = 200)
{
    return array('status' => $status, 'body' => json_encode($payload));
}

// ---------------------------------------------------------------------------
// JWT / JWKS validation
// ---------------------------------------------------------------------------

test('JWT: RFC 7515 A.2 RS256 vector verifies', function () {
    $vector = icc_load_vector('rfc7515-a2-rs256');
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $claims = $jwt->verify_signature($vector['jws'], array('keys' => array($vector['jwk'])));

    assert_same('joe', $claims['iss'], 'iss claim from the RFC vector');
});

test('JWT: RFC 7515 A.3 ES256 vector verifies', function () {
    $vector = icc_load_vector('rfc7515-a3-es256');
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $claims = $jwt->verify_signature($vector['jws'], array('keys' => array($vector['jwk'])));

    assert_same('joe', $claims['iss'], 'iss claim from the RFC vector');
});

test('JWT: tampered RS256 signature is rejected', function () {
    $vector = icc_load_vector('rfc7515-a2-rs256');
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);
    $tampered = substr($vector['jws'], 0, -2) . 'XY';

    assert_error_code('invalid-signature', function () use ($jwt, $tampered, $vector) {
        $jwt->verify_signature($tampered, array('keys' => array($vector['jwk'])));
    });
});

test('JWT: tampered ES256 signature is rejected', function () {
    $vector = icc_load_vector('rfc7515-a3-es256');
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);
    $tampered = substr($vector['jws'], 0, -2) . 'XY';

    assert_error_code('invalid-signature', function () use ($jwt, $tampered, $vector) {
        $jwt->verify_signature($tampered, array('keys' => array($vector['jwk'])));
    });
});

test('JWT: tampered payload is rejected', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);
    $token = icc_sign_jwt(icc_valid_claims(), $key['key']);

    $parts = explode('.', $token);
    $parts[1] = icc_b64url(json_encode(icc_valid_claims(array('sub' => 'attacker'))));

    assert_error_code('invalid-signature', function () use ($jwt, $parts, $key) {
        $jwt->verify_signature(implode('.', $parts), $key['jwks']);
    });
});

test('JWT: alg none is rejected', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $header = icc_b64url(json_encode(array('alg' => 'none')));
    $payload = icc_b64url(json_encode(icc_valid_claims()));
    $token = $header . '.' . $payload . '.';

    assert_error_code('malformed-jwt', function () use ($jwt, $token, $key) {
        $jwt->verify_signature($token, $key['jwks']);
    });
});

test('JWT: HS256 is not an allowed algorithm', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $header = icc_b64url(json_encode(array('alg' => 'HS256')));
    $payload = icc_b64url(json_encode(icc_valid_claims()));
    $signature = icc_b64url(hash_hmac('sha256', $header . '.' . $payload, 'secret', true));

    assert_error_code('unsupported-alg', function () use ($jwt, $header, $payload, $signature, $key) {
        $jwt->verify_signature($header . '.' . $payload . '.' . $signature, $key['jwks']);
    });
});

test('JWT: generated RS256 token validates with claims and nonce', function () {
    $key = icc_make_rsa_key();
    $token = icc_sign_jwt(icc_valid_claims(array('nonce' => 'nonce-42')), $key['key'], 'RS256');

    $jwt = new ICC_OpenID_Client_JWT(
        'https://sso.example.com/certs',
        'client-123',
        'https://sso.example.com/realms/test',
        3600,
        false
    );

    $validated = $jwt->validate_id_token($token, 'nonce-42', $key['jwks']);

    assert_same('user-abc-123', $validated['sub']);
});

test('JWT: generated ES256 token validates', function () {
    $key = icc_make_ec_key();
    $token = icc_sign_jwt(icc_valid_claims(), $key['key'], 'ES256');

    $jwt = new ICC_OpenID_Client_JWT(
        'https://sso.example.com/certs',
        'client-123',
        'https://sso.example.com/realms/test',
        3600,
        false
    );

    $validated = $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);

    assert_same('jdoe', $validated['preferred_username']);
});


test('JWT: key id mismatch is rejected', function () {
    $key = icc_make_rsa_key('good-key');
    $token = icc_sign_jwt(icc_valid_claims(), $key['key'], 'RS256', array('kid' => 'other-key'));

    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    assert_error_code('no-matching-key', function () use ($jwt, $token, $key) {
        $jwt->verify_signature($token, $key['jwks']);
    });
});

test('JWT: an EC key cannot satisfy an RS256 token', function () {
    $rsa = icc_make_rsa_key();
    $ec = icc_make_ec_key();
    $token = icc_sign_jwt(icc_valid_claims(), $rsa['key'], 'RS256');

    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    assert_error_code('no-matching-key', function () use ($jwt, $token, $ec) {
        $jwt->verify_signature($token, $ec['jwks']);
    });
});

test('JWT: time based claims are enforced', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $token = icc_sign_jwt(icc_valid_claims(array('exp' => time() - 120)), $key['key']);
    assert_error_code('token-expired', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $token = icc_sign_jwt(icc_valid_claims(array('nbf' => time() + 900)), $key['key']);
    assert_error_code('token-not-yet-valid', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $token = icc_sign_jwt(icc_valid_claims(array('iat' => time() + 900)), $key['key']);
    assert_error_code('token-issued-in-future', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });
});

test('JWT: missing required claims are rejected', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    $claims = icc_valid_claims();
    unset($claims['exp']);
    $token = icc_sign_jwt($claims, $key['key']);
    assert_error_code('missing-exp', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $claims = icc_valid_claims();
    unset($claims['iat']);
    $token = icc_sign_jwt($claims, $key['key']);
    assert_error_code('missing-iat', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $claims = icc_valid_claims();
    unset($claims['aud']);
    $token = icc_sign_jwt($claims, $key['key']);
    assert_error_code('missing-aud', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $token = icc_sign_jwt(icc_valid_claims(array('sub' => '')), $key['key']);
    assert_error_code('no-subject-identity', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });
});


test('JWT: audience handling (string, array, azp)', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT(
        'https://sso.example.com/certs',
        'client-123',
        'https://sso.example.com/realms/test',
        3600,
        false
    );

    $token = icc_sign_jwt(icc_valid_claims(array('aud' => 'someone-else')), $key['key']);
    assert_error_code('invalid-aud', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    // Single element array audience: accepted.
    $token = icc_sign_jwt(icc_valid_claims(array('aud' => array('client-123'))), $key['key']);
    $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);

    // Multiple audiences without azp: rejected (RFC 7519, 4.1.3).
    $token = icc_sign_jwt(icc_valid_claims(array('aud' => array('other', 'client-123'))), $key['key']);
    assert_error_code('missing-azp', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $token = icc_sign_jwt(
        icc_valid_claims(array('aud' => array('other', 'client-123'), 'azp' => 'other')),
        $key['key']
    );
    assert_error_code('invalid-azp', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $token = icc_sign_jwt(
        icc_valid_claims(array('aud' => array('other', 'client-123'), 'azp' => 'client-123')),
        $key['key']
    );
    $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
});

test('JWT: issuer and nonce are enforced', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT(
        'https://sso.example.com/certs',
        'client-123',
        'https://sso.example.com/realms/test',
        3600,
        false
    );

    $token = icc_sign_jwt(icc_valid_claims(array('iss' => 'https://evil.example.com')), $key['key']);
    assert_error_code('invalid-iss', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    // Trailing slash differences are tolerated.
    $token = icc_sign_jwt(icc_valid_claims(array('iss' => 'https://sso.example.com/realms/test/')), $key['key']);
    $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);

    $token = icc_sign_jwt(icc_valid_claims(array('nonce' => 'other-nonce')), $key['key']);
    assert_error_code('invalid-nonce', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });

    $claims = icc_valid_claims();
    unset($claims['nonce']);
    $token = icc_sign_jwt($claims, $key['key']);
    assert_error_code('invalid-nonce', function () use ($jwt, $token, $key) {
        $jwt->validate_id_token($token, 'test-nonce', $key['jwks']);
    });
});

test('JWT: malformed tokens and headers are rejected', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);

    assert_error_code('malformed-jwt', function () use ($jwt, $key) {
        $jwt->verify_signature('only.two', $key['jwks']);
    });

    assert_error_code('invalid-base64url', function () use ($jwt, $key) {
        $jwt->verify_signature('not valid base64url!!.eyJ9.abc', $key['jwks']);
    });

    $crit = icc_sign_jwt(icc_valid_claims(), $key['key'], 'RS256', array('crit' => array('exp')));
    assert_error_code('unsupported-crit', function () use ($jwt, $crit, $key) {
        $jwt->verify_signature($crit, $key['jwks']);
    });
});

test('JWKS: fetched, cached, refreshed on rotation', function () {
    icc_reset();

    $old = icc_make_rsa_key('old-key');
    $new = icc_make_rsa_key('new-key');
    $token = icc_sign_jwt(icc_valid_claims(), $new['key'], 'RS256', array('kid' => 'new-key'));

    $GLOBALS['icc']['http'] = icc_http_transport(array(
        'certs' => function () use ($old, $new) {
            static $calls = 0;
            $calls++;

            return icc_json_response($calls === 1 ? $old['jwks'] : $new['jwks']);
        },
    ));

    $jwt = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);
    $claims = $jwt->validate_id_token($token, 'test-nonce');

    assert_same('user-abc-123', $claims['sub'], 'rotated key accepted');
    assert_same(2, count($GLOBALS['icc']['http_log']), 'JWKS fetched twice (cache miss, then rotation)');

    // The cache now holds the refreshed key set: no extra HTTP request.
    $jwt2 = new ICC_OpenID_Client_JWT('https://sso.example.com/certs', 'client-123', '', 3600, false);
    $jwt2->validate_id_token($token, 'test-nonce');

    assert_same(2, count($GLOBALS['icc']['http_log']), 'cached JWKS reused');
});

test('JWKS: missing endpoint is reported', function () {
    $key = icc_make_rsa_key();
    $jwt = new ICC_OpenID_Client_JWT('', 'client-123', '', 3600, false);
    $token = icc_sign_jwt(icc_valid_claims(), $key['key']);

    assert_error_code('jwks-not-configured', function () use ($jwt, $token) {
        $jwt->verify_signature($token);
    });
});

test('HTTP guard: plain HTTP and local hosts are blocked unless allowed', function () {
    assert_error_code('url-not-https', function () {
        ICC_OpenID_Client_HTTP::guard_url('http://sso.example.com/certs', false);
    });

    assert_error_code('url-local-host', function () {
        ICC_OpenID_Client_HTTP::guard_url('https://127.0.0.1/certs', false);
    });

    assert_error_code('url-local-host', function () {
        ICC_OpenID_Client_HTTP::guard_url('https://localhost:8443/certs', false);
    });

    assert_same(
        'http://localhost:8080/realms/test/.well-known/openid-configuration',
        ICC_OpenID_Client_HTTP::guard_url('http://localhost:8080/realms/test/.well-known/openid-configuration', true),
        'internal IdP allowed when the option is on'
    );
});


// ---------------------------------------------------------------------------
// Protocol client
// ---------------------------------------------------------------------------

test('Client: authorization URL, state and nonce', function () {
    icc_reset();

    $client = new ICC_OpenID_Client_Client(icc_settings());
    $url = $client->get_authentication_url('https://sho.rt/admin/tools.php');

    assert_contains('response_type=code', $url);
    assert_contains('client_id=client-123', $url);
    assert_contains('scope=openid%20profile%20email', $url);
    assert_contains('nonce=', $url);
    assert_contains('redirect_uri=' . rawurlencode('https://sho.rt/?icc_oidc=callback'), $url);

    // The state is stored server side (single use, with the redirect target).
    $states = yourls_get_option('icc_oidc_states');
    assert_same(1, count($states), 'one pending login attempt');
    $state = key($states);
    assert_same('https://sho.rt/admin/tools.php', $states[$state]['redirect_to']);
    assert_contains('state=' . $state, $url);
});

test('Client: state is single use and expires', function () {
    icc_reset();

    $client = new ICC_OpenID_Client_Client(icc_settings());
    $url = $client->get_authentication_url();
    parse_str(parse_url($url, PHP_URL_QUERY), $query);

    $attempt = $client->consume_state($query['state']);
    assert_true(isset($attempt['nonce']) && $attempt['nonce'] !== '', 'nonce returned');

    assert_error_code('state-not-found', function () use ($client, $query) {
        $client->consume_state($query['state']);
    });

    $client->get_authentication_url();
    $states = yourls_get_option('icc_oidc_states');
    $state = key($states);
    $states[$state]['time'] = time() - 400;
    yourls_update_option('icc_oidc_states', $states);

    assert_error_code('state-expired', function () use ($client, $state) {
        $client->consume_state($state);
    });

    assert_error_code('missing-authentication-state', function () use ($client) {
        $client->consume_state('');
    });
});

test('Client: expired login attempts are pruned', function () {
    icc_reset();

    yourls_update_option('icc_oidc_states', array(
        'old-state' => array('redirect_to' => '', 'nonce' => 'old', 'time' => time() - 5000),
    ));

    $client = new ICC_OpenID_Client_Client(icc_settings());
    $client->get_authentication_url();

    $states = yourls_get_option('icc_oidc_states');

    assert_same(1, count($states), 'only the new attempt is kept');
    assert_false(isset($states['old-state']), 'expired attempt removed');
});

test('Client: token request and response parsing', function () {
    icc_reset();

    $key = icc_make_rsa_key();
    $token = icc_sign_jwt(icc_valid_claims(), $key['key']);

    $transport = icc_http_transport(array(
        'token' => function ($method, $url, $headers, $data) use ($token) {
            assert_same('POST', $method);
            assert_contains('grant_type=authorization_code', $data);
            assert_contains('code=auth-code-1', $data);
            assert_contains('client_secret=secret-xyz', $data);

            return icc_json_response(array(
                'access_token' => 'access-token-1',
                'token_type'   => 'Bearer',
                'id_token'     => $token,
            ));
        },
        'certs' => icc_json_response($key['jwks']),
    ));

    $client = new ICC_OpenID_Client_Client(icc_settings(), null, $transport);
    $response = $client->request_token('auth-code-1');

    assert_same('access-token-1', $response['access_token']);

    $claims = $client->get_id_token_claim($response, 'test-nonce');
    assert_same('jdoe', $claims['preferred_username']);
});

test('Client: identity provider token errors are surfaced', function () {
    icc_reset();

    $transport = icc_http_transport(array(
        'token' => icc_json_response(array('error' => 'invalid_grant', 'error_description' => 'Code expired'), 400),
    ));

    $client = new ICC_OpenID_Client_Client(icc_settings(), null, $transport);

    $error = assert_error_code('invalid_grant', function () use ($client) {
        $client->request_token('expired-code');
    });

    assert_contains('Code expired', $error->getMessage());
});

test('Client: userinfo GET with POST fallback', function () {
    icc_reset();

    $calls = array();

    $transport = icc_http_transport(array(
        'userinfo' => function ($method, $url, $headers, $data) use (&$calls) {
            $calls[] = $method;

            if ($method === 'GET') {
                return array('status' => 200, 'body' => '<html>not json</html>');
            }

            return icc_json_response(array('sub' => 'user-abc-123', 'email' => 'jdoe@example.com'));
        },
    ));

    $client = new ICC_OpenID_Client_Client(icc_settings(), null, $transport);
    $claim = $client->get_user_claim(array('access_token' => 'access-token-1'));

    assert_same(array('GET', 'POST'), $calls, 'GET then POST');
    assert_same('jdoe@example.com', $claim['email']);
});

test('Client: userinfo is skipped when not configured', function () {
    icc_reset();

    $client = new ICC_OpenID_Client_Client(icc_settings(array('endpoint_userinfo' => '')));

    assert_same(array(), $client->get_user_claim(array('access_token' => 'access-token-1')));
});


test('Client: discovery document import', function () {
    icc_reset();

    $document = array(
        'issuer'                 => 'https://sso.example.com/realms/test',
        'authorization_endpoint' => 'https://sso.example.com/realms/test/protocol/openid-connect/auth',
        'token_endpoint'         => 'https://sso.example.com/realms/test/protocol/openid-connect/token',
        'userinfo_endpoint'      => 'https://sso.example.com/realms/test/protocol/openid-connect/userinfo',
        'end_session_endpoint'   => 'https://sso.example.com/realms/test/protocol/openid-connect/logout',
        'jwks_uri'               => 'https://sso.example.com/realms/test/protocol/openid-connect/certs',
    );

    $client = new ICC_OpenID_Client_Client(
        icc_settings(),
        null,
        icc_http_transport(array('openid-configuration' => icc_json_response($document)))
    );

    $loaded = $client->discover('https://sso.example.com/realms/test/.well-known/openid-configuration');
    $mapped = $client->map_discovery_to_settings($loaded);

    assert_same($document['authorization_endpoint'], $mapped['endpoint_login']);
    assert_same($document['jwks_uri'], $mapped['endpoint_jwks']);
    assert_same($document['issuer'], $mapped['issuer']);
    assert_same(6, count($mapped), 'all values mapped');

    $incomplete = new ICC_OpenID_Client_Client(
        icc_settings(),
        null,
        icc_http_transport(array('openid-configuration' => icc_json_response(array('issuer' => 'x'))))
    );

    assert_error_code('discovery-missing-fields', function () use ($incomplete) {
        $incomplete->discover('https://sso.example.com/.well-known/openid-configuration');
    });

    assert_error_code('empty-discovery-url', function () use ($incomplete) {
        $incomplete->discover('');
    });
});

test('Client: end session URL and issuer derivation', function () {
    icc_reset();

    $client = new ICC_OpenID_Client_Client(icc_settings());
    $url = $client->get_end_session_url('id-token-123');

    assert_contains('id_token_hint=id-token-123', $url);
    assert_contains('client_id=client-123', $url);
    assert_contains('post_logout_redirect_uri=' . rawurlencode('https://sho.rt/'), $url);

    assert_same(
        'https://sso.example.com/realms/test',
        icc_oidc_issuer_from_endpoint('https://sso.example.com/realms/test/protocol/openid-connect/auth')
    );
    assert_same(
        'https://login.microsoftonline.com/tenant-id/v2.0',
        icc_oidc_issuer_from_endpoint('https://login.microsoftonline.com/tenant-id/v2.0/oauth2/v2.0/authorize')
    );
    assert_same(
        'https://sho.rt:8443',
        icc_oidc_issuer_from_endpoint('https://sho.rt:8443/oauth2/authorize')
    );
});

test('HTTP: YOURLS helpers are wrapped into a normalized response', function () {
    icc_reset();

    $GLOBALS['icc']['http'] = icc_http_transport(array(
        'certs' => icc_json_response(array('keys' => array())),
    ));

    $response = ICC_OpenID_Client_HTTP::request('GET', 'https://sso.example.com/certs', array('Accept' => 'application/json'));

    assert_same(200, $response['status']);
    assert_contains('"keys"', $response['body']);

    $GLOBALS['icc']['http'] = null;

    assert_error_code('http-request-failed', function () {
        ICC_OpenID_Client_HTTP::request('GET', 'https://sso.example.com/certs');
    });
});


// ---------------------------------------------------------------------------
// User store
// ---------------------------------------------------------------------------

test('Store: identities are remembered without touching config.php users', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$hash');

    $store = new ICC_OpenID_Client_Store();
    $store->save('admin', array('subject' => 'sub-1', 'email' => 'admin@example.com'));

    assert_same('phpass:$2y$hash', $GLOBALS['yourls_user_passwords']['admin'], 'config.php user untouched');
    assert_same(array('admin'), array_keys($GLOBALS['yourls_user_passwords']), 'no account is ever added');
    assert_same('admin', ICC_OpenID_Client_Store::find_login_by_subject('sub-1'));
});

test('Store: find, save, record and remove an identity', function () {
    icc_reset();

    $store = new ICC_OpenID_Client_Store();
    $store->save('jdoe', array('subject' => 'sub-1', 'email' => 'jdoe@example.com'));

    assert_same('jdoe', ICC_OpenID_Client_Store::find_login_by_subject('sub-1'));
    assert_same(null, ICC_OpenID_Client_Store::find_login_by_subject('nope'));

    $user = ICC_OpenID_Client_Store::get('jdoe');
    assert_same('sub-1', $user['subject']);
    assert_same(0, (int) $user['last_login'], 'no login recorded yet');

    $store->record_login('jdoe', 'the-id-token');
    $user = ICC_OpenID_Client_Store::get('jdoe');
    assert_same('the-id-token', $user['last_id_token']);
    assert_true(intval($user['last_login']) > 0, 'last login recorded');

    assert_true($store->remove('jdoe'), 'login removed');
    assert_same(null, ICC_OpenID_Client_Store::get('jdoe'));
    assert_false($store->remove('jdoe'), 'removing twice has nothing to remove');
});

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

test('Logger: disabled, enabled, limited and cleared', function () {
    icc_reset();

    $disabled = new ICC_OpenID_Client_Logger(0, 10);
    assert_false($disabled->log('should not be stored', 'test'), 'logging disabled');
    assert_same(array(), $disabled->get_logs());

    $logger = new ICC_OpenID_Client_Logger(1, 2);
    $logger->log('first', 'test');
    $logger->log('second', 'test');
    $logger->log('third', 'test');

    $logs = $logger->get_logs();
    assert_same(2, count($logs), 'log limit applied');
    assert_same('third', $logs[0]['message'], 'newest first');
    assert_same('second', $logs[1]['message']);

    $table = $logger->get_logs_table();
    assert_contains('third', $table);
    assert_not_contains('<script', $table);

    $logger->clear_logs();
    assert_same(array(), $logger->get_logs());
});

// ---------------------------------------------------------------------------
// Settings accessors
// ---------------------------------------------------------------------------

test('Settings: defaults, casting and options round trip', function () {
    icc_reset();

    assert_same('button', icc_oidc_get('login_type'), 'default login type');
    assert_same('openid profile email', icc_oidc_get('scope'));
    assert_same(3600, icc_oidc_get('jwks_cache_ttl'));
    assert_same('', icc_oidc_get('create_if_does_not_exist'), 'account provisioning setting is gone');
    assert_same('', icc_oidc_get('two_factor_bypass'), 'local 2FA bypass setting is gone');

    yourls_update_option('icc_oidc_jwks_cache_ttl', '900');
    assert_same(900, icc_oidc_get('jwks_cache_ttl'), 'integer setting cast');

    yourls_update_option('icc_oidc_login_button_text', 'Sign in with SSO');
    assert_same('Sign in with SSO', icc_oidc_get('login_button_text'));

    yourls_update_option('icc_oidc_login_type', 'auto');
    assert_same('auto', icc_oidc_get('login_type'));

    assert_same('https://sho.rt/?icc_oidc=callback', icc_oidc_redirect_uri(), 'default redirect URI');
    yourls_update_option('icc_oidc_redirect_uri', 'https://sho.rt/custom-callback');
    assert_same('https://sho.rt/custom-callback', icc_oidc_redirect_uri(), 'redirect URI override');

    assert_same('https://sho.rt/?icc_oidc=logout', icc_oidc_logout_url());
    assert_true(icc_oidc_is_https('https://sho.rt/'), 'https detected');
    assert_false(icc_oidc_is_https('http://sho.rt/'), 'http detected');
});



// ---------------------------------------------------------------------------
// Authentication flow
// ---------------------------------------------------------------------------

/**
 * Run a full callback for the given settings/claims and return the redirect URL.
 */
function icc_run_callback(array $settings, array $claims = array())
{
    $settings = icc_settings($settings);

    // This helper signs tokens with a freshly generated key, so any cached key
    // set from a previous callback has to go (the JWKS cache itself is covered
    // by its own test).
    yourls_delete_option('icc_oidc_jwks_cache');

    $client = new ICC_OpenID_Client_Client($settings, null, icc_http_transport(array()));
    $url = $client->get_authentication_url('https://sho.rt/admin/index.php');
    parse_str(parse_url($url, PHP_URL_QUERY), $query);

    // The signed ID token must carry the nonce of this login attempt.
    $states = yourls_get_option('icc_oidc_states');
    $nonce = isset($states[$query['state']]['nonce']) ? $states[$query['state']]['nonce'] : '';

    $key = icc_make_rsa_key();
    $token = icc_sign_jwt(icc_valid_claims(array_merge(array('nonce' => $nonce), $claims)), $key['key']);

    $transport = icc_http_transport(array(
        'token'    => icc_json_response(array(
            'access_token' => 'access-token-1',
            'token_type'   => 'Bearer',
            'id_token'     => $token,
        )),
        'userinfo' => icc_json_response(icc_valid_claims($claims)),
        'certs'    => icc_json_response($key['jwks']),
    ));

    $_GET = array(
        'icc_oidc' => 'callback',
        'code'     => 'auth-code-1',
        'state'    => $query['state'],
    );

    $auth = new ICC_OpenID_Client_Auth($settings, new ICC_OpenID_Client_Logger(0), $transport);

    try {
        $auth->handle_request();
    } catch (ICC_Test_Redirect $redirect) {
        return $redirect->url;
    }

    throw new ICC_Test_Assertion('the callback did not redirect');
}

test('Auth: successful callback signs in as the single config.php user', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    $url = icc_run_callback(array());

    assert_same('https://sho.rt/admin/index.php', $url, 'redirect target');
    assert_same('admin', $GLOBALS['icc']['set_user'], 'YOURLS user set');
    assert_same('admin', $GLOBALS['icc']['cookie'], 'auth cookie stored');

    $user = ICC_OpenID_Client_Store::get('admin');
    assert_same('user-abc-123', $user['subject'], 'subject stored');
    assert_same('jdoe@example.com', $user['email'], 'email stored');
    assert_same('John Doe', $user['displayname'], 'display name built from the format');
    assert_same(array('admin'), array_keys($GLOBALS['yourls_user_passwords']), 'no account was created');
    assert_true(in_array('icc_oidc_user_logged_in', $GLOBALS['icc']['actions'], true), 'logged in action fired');
});

test('Auth: the identity claim selects the matching config.php user', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array(
        'admin' => 'phpass:$2y$hash-1',
        'jdoe'  => 'phpass:$2y$hash-2',
    );

    $url = icc_run_callback(array());

    assert_same('https://sho.rt/admin/index.php', $url);
    assert_same('jdoe', $GLOBALS['icc']['set_user'], 'the login matching preferred_username is used');

    $user = ICC_OpenID_Client_Store::get('jdoe');
    assert_same('user-abc-123', $user['subject'], 'mapping stored for that login');
    assert_same(null, ICC_OpenID_Client_Store::get('admin'), 'no mapping for the other user');
});

test('Auth: an unknown identity is refused when several users exist', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array(
        'admin'     => 'phpass:$2y$hash-1',
        'webmaster' => 'phpass:$2y$hash-2',
    );

    $url = icc_run_callback(array(), array('preferred_username' => 'someone-else'));

    assert_contains('icc_oidc_error=user-not-linked', $url, 'identity not linked');
    assert_same(null, $GLOBALS['icc']['set_user'], 'no YOURLS user was signed in');
    assert_same(array(), ICC_OpenID_Client_Store::all(), 'nothing was stored');
});

test('Auth: second login reuses the known identity', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    icc_run_callback(array());
    icc_run_callback(array(), array('email' => 'new-address@example.com'));

    $users = ICC_OpenID_Client_Store::all();
    assert_same(1, count($users), 'still a single login mapped');
    assert_same('new-address@example.com', $users['admin']['email'], 'claims refreshed');
    assert_same('user-abc-123', $users['admin']['subject'], 'subject unchanged');
});

test('Auth: a stale identity mapping is discarded and resolved again', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    // Mapping left over from an account that no longer exists in config.php.
    $store = new ICC_OpenID_Client_Store();
    $store->save('removed-user', array('subject' => 'user-abc-123', 'email' => 'old@example.com'));

    $url = icc_run_callback(array());

    assert_same('https://sho.rt/admin/index.php', $url);
    assert_same('admin', $GLOBALS['icc']['set_user'], 'resolved to the config.php user');
    assert_same(null, ICC_OpenID_Client_Store::get('removed-user'), 'stale entry dropped');

    $user = ICC_OpenID_Client_Store::get('admin');
    assert_same('user-abc-123', $user['subject'], 'identity re-mapped');
});

test('Auth: email domain restriction refuses unwanted addresses', function () {
    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    $url = icc_run_callback(array('email_domain_restriction' => 'example.com partner.org'));
    assert_same('https://sho.rt/admin/index.php', $url, 'allowed domain');

    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    $url = icc_run_callback(array('email_domain_restriction' => 'only.example.net'));
    assert_contains('icc_oidc_error=email-domain-not-allowed', $url, 'refused domain');

    icc_reset();

    $GLOBALS['yourls_user_passwords'] = array('admin' => 'phpass:$2y$existinghash');

    $url = icc_run_callback(array('email_domain_restriction' => 'jdoe@example.com'));
    assert_same('https://sho.rt/admin/index.php', $url, 'full email entry allowed');
});

test('Auth: tampered state fails the callback', function () {
    icc_reset();

    $_GET = array('icc_oidc' => 'callback', 'code' => 'auth-code-1', 'state' => 'not-a-real-state');

    $auth = new ICC_OpenID_Client_Auth(icc_settings(), new ICC_OpenID_Client_Logger(0), icc_http_transport(array()));

    $url = null;

    try {
        $auth->handle_request();
    } catch (ICC_Test_Redirect $redirect) {
        $url = $redirect->url;
    }

    assert_contains('icc_oidc_error=state-not-found', (string) $url);
    assert_same(null, $GLOBALS['icc']['set_user'], 'nobody logged in');
});

test('Auth: auto SSO redirects only when needed', function () {
    icc_reset();

    $auth = new ICC_OpenID_Client_Auth(icc_settings(array('login_type' => 'auto')), new ICC_OpenID_Client_Logger(0));

    $redirect = null;

    try {
        $auth->handle_require_auth();
    } catch (ICC_Test_Redirect $exception) {
        $redirect = $exception->url;
    }

    assert_contains('response_type=code', (string) $redirect, 'unauthenticated request redirected');
    assert_contains('client_id=client-123', (string) $redirect);

    // Already authenticated: nothing happens.
    $_COOKIE[yourls_cookie_name()] = yourls_cookie_value('jdoe');
    $auth->handle_require_auth();
    unset($_COOKIE[yourls_cookie_name()]);

    // Coming back from an error: show the login form instead of looping.
    $_GET['icc_oidc_error'] = 'invalid-signature';
    $auth->handle_require_auth();
    unset($_GET['icc_oidc_error']);

    // API calls keep working with signature authentication.
    $GLOBALS['icc']['is_api'] = true;
    $auth->handle_require_auth();
    $GLOBALS['icc']['is_api'] = false;

    // Button modes never redirect.
    $button = new ICC_OpenID_Client_Auth(icc_settings(array('login_type' => 'button')), new ICC_OpenID_Client_Logger(0));
    $button->handle_require_auth();

    // Configuration missing: no redirect.
    $unconfigured = new ICC_OpenID_Client_Auth(
        icc_settings(array('login_type' => 'auto', 'endpoint_login' => '')),
        new ICC_OpenID_Client_Logger(0)
    );
    $unconfigured->handle_require_auth();

    assert_true(true, 'auto login guarded against loops, API calls and misconfiguration');
});

test('Auth: logout clears the cookie and ends the IdP session', function () {
    icc_reset();

    $store = new ICC_OpenID_Client_Store();
    $store->save('jdoe', array('subject' => 'sub-1', 'last_id_token' => 'stored-id-token'));

    $GLOBALS['yourls_user_passwords'] = array('jdoe' => 'phpass:x');
    $_COOKIE[yourls_cookie_name()] = yourls_cookie_value('jdoe');
    $_GET = array('icc_oidc' => 'logout');

    $auth = new ICC_OpenID_Client_Auth(icc_settings(), new ICC_OpenID_Client_Logger(0));

    $url = null;

    try {
        $auth->handle_request();
    } catch (ICC_Test_Redirect $redirect) {
        $url = $redirect->url;
    }

    assert_contains('protocol/openid-connect/logout', (string) $url);
    assert_contains('id_token_hint=stored-id-token', (string) $url);
    assert_same('', $GLOBALS['icc']['cookie'], 'YOURLS cookie cleared');
});

test('Auth: logout without single logout returns to the login page', function () {
    icc_reset();

    $_GET = array('icc_oidc' => 'logout');

    $auth = new ICC_OpenID_Client_Auth(
        icc_settings(array('endpoint_end_session' => '', 'redirect_on_logout' => 0)),
        new ICC_OpenID_Client_Logger(0)
    );

    $url = null;

    try {
        $auth->handle_request();
    } catch (ICC_Test_Redirect $redirect) {
        $url = $redirect->url;
    }

    assert_same('https://sho.rt/admin/index.php', $url);
});

test('Auth: logout link is rewritten only when single logout is configured', function () {
    icc_reset();

    $original = yourls_nonce_url(
        'admin_logout',
        yourls_add_query_arg(array('action' => 'logout'), yourls_admin_url('index.php')),
        'nonce',
        'logout'
    );
    $link = '<p>Hello <strong>jdoe</strong> (<a href="'
        . htmlspecialchars($original, ENT_QUOTES, 'UTF-8') . '">Logout</a>)</p>';

    $auth = new ICC_OpenID_Client_Auth(icc_settings(), new ICC_OpenID_Client_Logger(0));
    $rewritten = $auth->handle_logout_link($link);

    assert_contains('icc_oidc=logout', $rewritten);
    assert_not_contains('admin_logout', $rewritten);
    assert_contains('Hello <strong>jdoe</strong>', $rewritten, 'the rest of the link is preserved');

    $plain = new ICC_OpenID_Client_Auth(
        icc_settings(array('endpoint_end_session' => '')),
        new ICC_OpenID_Client_Logger(0)
    );
    assert_same($link, $plain->handle_logout_link($link), 'YOURS logout untouched without an end session endpoint');
});

// ---------------------------------------------------------------------------
// Login screen
// ---------------------------------------------------------------------------

test('Login form: button, button only mode and error notices', function () {
    icc_reset();

    $form = new ICC_OpenID_Client_Login_Form(
        icc_settings(array('login_button_text' => 'Sign in with SSO'))
    );

    ob_start();
    $form->render_form_top();
    $top = ob_get_clean();

    assert_not_contains('display: none', $top, 'button mode keeps the password form');

    $html = $form->get_login_button_html();
    assert_contains('Sign in with SSO', $html);
    assert_contains('response_type=code', $html);
    assert_contains('class="icc-oidc-login-button"', $html);

    $_GET['icc_oidc_error'] = 'email-domain-not-allowed';
    ob_start();
    $form->render_form_top();
    $top = ob_get_clean();

    assert_contains('not allowed to sign in', $top);

    $_GET = array();

    $only = new ICC_OpenID_Client_Login_Form(icc_settings(array('login_type' => 'button_only')));
    ob_start();
    $only->render_form_top();
    $top = ob_get_clean();

    assert_contains('#username, #password, #submit', $top);
    assert_contains('iccOidcHidePasswordForm', $top);

    $unconfigured = new ICC_OpenID_Client_Login_Form(
        icc_settings(array('endpoint_login' => '', 'client_id' => ''))
    );
    assert_same('', $unconfigured->get_login_button_html());

    $with_logo = new ICC_OpenID_Client_Login_Form(
        icc_settings(array('login_button_logo_url' => 'https://cdn.example.com/logo.png'))
    );
    assert_contains('<img src="https://cdn.example.com/logo.png"', $with_logo->get_login_button_html());
});

test('Login form: button text and logo are escaped', function () {
    icc_reset();

    $form = new ICC_OpenID_Client_Login_Form(icc_settings(array(
        'login_button_text'     => '<script>alert(1)</script>',
        'login_button_logo_url' => 'javascript:alert(2)',
    )));

    $html = $form->get_login_button_html();

    assert_not_contains('<script>', $html);
    assert_contains('&lt;script&gt;', $html);
    assert_not_contains('<img src="javascript:', $html, 'non http(s) logos are ignored');
});

// ---------------------------------------------------------------------------
// Settings page
// ---------------------------------------------------------------------------

test('Settings page: saves sanitized values and shows the redirect URI', function () {
    icc_reset();

    $_POST = array(
        'icc_oidc_action'                   => 'save',
        'icc_oidc_client_id'                => 'client-123',
        'icc_oidc_endpoint_login'           => 'https://sso.example.com/realms/test/protocol/openid-connect/auth',
        'icc_oidc_endpoint_token'           => 'javascript:alert(1)',
        'icc_oidc_login_type'               => 'not-an-option',
        'icc_oidc_redirect_user_back'       => '1',
        'icc_oidc_jwks_cache_ttl'           => '1200',
        'icc_oidc_login_button_text'        => "  Sign in with SSO  ",
        'icc_oidc_client_secret'            => ' top-secret ',
    );

    $page = new ICC_OpenID_Client_Settings_Page(new ICC_OpenID_Client_Logger(0));

    ob_start();
    $page->render();
    $html = ob_get_clean();

    assert_same('client-123', yourls_get_option('icc_oidc_client_id'));
    assert_same(
        'https://sso.example.com/realms/test/protocol/openid-connect/auth',
        yourls_get_option('icc_oidc_endpoint_login')
    );
    assert_same('', yourls_get_option('icc_oidc_endpoint_token'), 'invalid URL rejected');
    assert_same('', yourls_get_option('icc_oidc_login_type'), 'invalid select value rejected');
    assert_same(1, yourls_get_option('icc_oidc_redirect_user_back'), 'checked box stored as 1');
    assert_same(0, yourls_get_option('icc_oidc_redirect_on_logout'), 'unchecked boxes stored as 0');
    assert_same(1200, yourls_get_option('icc_oidc_jwks_cache_ttl'), 'number stored');
    assert_same('Sign in with SSO', yourls_get_option('icc_oidc_login_button_text'), 'text trimmed');
    assert_same('top-secret', yourls_get_option('icc_oidc_client_secret'));

    assert_contains('Settings saved', $html);
    assert_contains('icc_oidc=callback', $html, 'redirect URI displayed');
    assert_contains('Quick Setup', $html);
    assert_contains('SSO Logins', $html);
    assert_contains('No account is ever created here.', $html, 'mapping explained to the administrator');
    assert_not_contains('Create user if it does not exist', $html, 'account provisioning field removed');
    assert_not_contains('Bypass local 2FA', $html, 'local 2FA bypass field removed');
    assert_not_contains('Link Existing Users', $html, 'link existing users field removed');
    assert_contains('Ivan Carlos', $html);
});


test('Settings page: discovery import previews values without saving them', function () {
    icc_reset();

    $GLOBALS['icc']['http'] = icc_http_transport(array(
        'openid-configuration' => icc_json_response(array(
            'issuer'                 => 'https://sso.example.com/realms/test',
            'authorization_endpoint' => 'https://sso.example.com/realms/test/protocol/openid-connect/auth',
            'token_endpoint'         => 'https://sso.example.com/realms/test/protocol/openid-connect/token',
            'jwks_uri'               => 'https://sso.example.com/realms/test/protocol/openid-connect/certs',
        )),
    ));

    $_POST = array(
        'icc_oidc_action'        => 'discover',
        'icc_oidc_discovery_url' => 'https://sso.example.com/realms/test/.well-known/openid-configuration',
    );

    $page = new ICC_OpenID_Client_Settings_Page(new ICC_OpenID_Client_Logger(0));

    ob_start();
    $page->render();
    $html = ob_get_clean();

    assert_contains('Configuration loaded', $html);
    assert_contains('value="https://sso.example.com/realms/test/protocol/openid-connect/auth"', $html);
    assert_same(false, yourls_get_option('icc_oidc_endpoint_login'), 'not stored until saved');
});

test('Settings page: log cleaning and forgetting an identity', function () {
    icc_reset();

    yourls_update_option('icc_oidc_enable_logging', 1);
    $logger = new ICC_OpenID_Client_Logger();
    $logger->log('something happened', 'test');

    assert_same(1, count($logger->get_logs()));

    $_POST = array('icc_oidc_action' => 'clear_logs');
    $page = new ICC_OpenID_Client_Settings_Page($logger);
    ob_start();
    $page->render();
    ob_end_clean();

    assert_same(array(), $logger->get_logs(), 'logs cleared');

    $store = new ICC_OpenID_Client_Store();
    $store->save('admin', array('subject' => 'sub-1'));

    $_POST = array();
    ob_start();
    $page->render();
    $table = ob_get_clean();

    assert_contains('<strong>admin</strong>', $table, 'the config.php user is listed');
    assert_contains('value="Forget"', $table, 'the identity can be forgotten');

    $_POST = array('icc_oidc_action' => 'remove_user', 'icc_oidc_user' => 'admin');
    ob_start();
    $page->render();
    $html = ob_get_clean();

    assert_same(null, ICC_OpenID_Client_Store::get('admin'), 'identity forgotten');
    assert_contains('Forgot', $html);
    assert_contains('&quot;admin&quot;', $html);
});

// ---------------------------------------------------------------------------
// Compatibility guard
// ---------------------------------------------------------------------------

test('Compatibility: shipped code keeps a PHP 7.4 compatible syntax', function () {
    $files = array_merge(
        array(YOURLS_ABSPATH . 'plugin.php'),
        glob(YOURLS_ABSPATH . 'includes/*.php')
    );

    $forbidden = array(
        '/str_contains\s*\(/'          => 'PHP 8.0 function str_contains()',
        '/str_starts_with\s*\(/'       => 'PHP 8.0 function str_starts_with()',
        '/str_ends_with\s*\(/'         => 'PHP 8.0 function str_ends_with()',
        '/array_is_list\s*\(/'         => 'PHP 8.1 function array_is_list()',
        '/\?->/'                       => 'PHP 8.0 nullsafe operator',
        '/(?<![\w$])match\s*\(/'       => 'PHP 8.0 match expression',
        '/(?<![\w$])readonly\s+/'      => 'PHP 8.1 readonly properties',
        '/#\[/'                        => 'PHP 8.0 attribute',
        '/(?<![\w$])enum\s+[A-Za-z_]/' => 'PHP 8.1 enum declaration',
        '/\)\s*:\s*never\b/'           => 'PHP 8.1 never return type',
    );

    foreach ($files as $file) {
        $source = file_get_contents($file);

        foreach ($forbidden as $pattern => $description) {
            if (preg_match($pattern, $source)) {
                throw new ICC_Test_Assertion(basename($file) . ' uses ' . $description);
            }
        }
    }

    assert_same(10, count($files), 'all plugin files are scanned');
});

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

$suite_start = microtime(true);
$executed = 0;

echo "\nICC OpenID Connect Client - test suite\n";
echo str_repeat('-', 68) . "\n";

foreach ($GLOBALS['icc_tests'] as $case) {
    list($name, $callback) = $case;
    $executed++;

    try {
        call_user_func($callback);
        icc_test_pass($name);
    } catch (ICC_Test_Assertion $assertion) {
        icc_test_fail($name, $assertion->getMessage());
    } catch (Exception $error) {
        icc_test_fail($name, get_class($error) . ': ' . $error->getMessage());
    }
}

$duration = round((microtime(true) - $suite_start) * 1000);

echo str_repeat('-', 68) . "\n";
printf(
    "%d tests, %d passed, %d failed (%d ms)\n\n",
    $executed,
    $GLOBALS['icc_results']['pass'],
    $GLOBALS['icc_results']['fail'],
    $duration
);

if ($GLOBALS['icc_results']['fail'] > 0) {
    echo "Failures:\n";

    foreach ($GLOBALS['icc_results']['failures'] as $failure) {
        echo '  - ' . $failure . "\n";
    }

    exit(1);
}

exit(0);

