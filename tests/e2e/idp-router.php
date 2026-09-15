<?php
/**
 * Minimal OpenID Connect provider used by the end to end test only.
 *
 * Serves the discovery document, the authorization endpoint (auto consent),
 * the token endpoint (RS256 signed ID tokens), userinfo, JWKS and the
 * RP initiated logout endpoint.
 *
 * @package ICC_OpenID_Client
 */

$base      = 'http://' . ($_SERVER['HTTP_HOST'] ?? '127.0.0.1:8089');
$issuer    = $base . '/realms/mock';
$workDir   = rtrim(getenv('IDP_WORK_DIR') ?: sys_get_temp_dir(), '/');
$keyFile   = $workDir . '/key.pem';
$jwksFile  = $workDir . '/jwks.json';
$nonceFile = $workDir . '/nonce.txt';
$uri       = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

/**
 * Base64url encode.
 *
 * @param string $data Raw data.
 *
 * @return string
 */
function b64u($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

if (!file_exists($keyFile)) {
    $resource = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
    openssl_pkey_export($resource, $pem);
    file_put_contents($keyFile, $pem);

    $details = openssl_pkey_get_details($resource);
    file_put_contents($jwksFile, json_encode(array('keys' => array(array(
        'kty' => 'RSA',
        'kid' => 'mock-key-1',
        'alg' => 'RS256',
        'use' => 'sig',
        'n'   => b64u($details['rsa']['n']),
        'e'   => b64u($details['rsa']['e']),
    )))));
}

switch ($uri) {
    case '/realms/mock/.well-known/openid-configuration':
        header('Content-Type: application/json');
        echo json_encode(array(
            'issuer'                 => $issuer,
            'authorization_endpoint' => $issuer . '/protocol/openid-connect/auth',
            'token_endpoint'         => $issuer . '/protocol/openid-connect/token',
            'userinfo_endpoint'      => $issuer . '/protocol/openid-connect/userinfo',
            'end_session_endpoint'   => $issuer . '/protocol/openid-connect/logout',
            'jwks_uri'               => $issuer . '/protocol/openid-connect/certs',
        ));
        break;

    case '/realms/mock/protocol/openid-connect/auth':
        // Remember the nonce so the ID token can echo it back.
        file_put_contents($nonceFile, isset($_GET['nonce']) ? (string) $_GET['nonce'] : '');

        $redirect = (string) $_GET['redirect_uri'];
        $separator = strpos($redirect, '?') === false ? '?' : '&';

        header('Location: ' . $redirect . $separator . 'code=mock-code-1&state=' . rawurlencode((string) $_GET['state']));
        break;

    case '/realms/mock/protocol/openid-connect/token':
        $nonce = trim((string) @file_get_contents($nonceFile));
        $now = time();

        $claims = array(
            'iss'                => $issuer,
            'aud'                => 'yourls-client',
            'sub'                => 'mock-user-1',
            'exp'                => $now + 300,
            'iat'                => $now - 5,
            'nonce'              => $nonce,
            'preferred_username' => 'ssouser',
            'email'              => 'ssouser@example.com',
            'name'               => 'SSO User',
            'given_name'         => 'SSO',
            'family_name'        => 'User',
        );

        $header = array('alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'mock-key-1');
        $signingInput = b64u(json_encode($header)) . '.' . b64u(json_encode($claims));

        openssl_sign($signingInput, $signature, file_get_contents($keyFile), OPENSSL_ALGO_SHA256);

        header('Content-Type: application/json');
        echo json_encode(array(
            'access_token' => 'mock-access-token',
            'token_type'   => 'Bearer',
            'id_token'     => $signingInput . '.' . b64u($signature),
        ));
        break;

    case '/realms/mock/protocol/openid-connect/userinfo':
        header('Content-Type: application/json');
        echo json_encode(array(
            'sub'                => 'mock-user-1',
            'email'              => 'ssouser@example.com',
            'preferred_username' => 'ssouser',
        ));
        break;

    case '/realms/mock/protocol/openid-connect/certs':
        header('Content-Type: application/json');
        echo file_get_contents($jwksFile);
        break;

    case '/realms/mock/protocol/openid-connect/logout':
        header('Location: ' . (isset($_GET['post_logout_redirect_uri']) ? $_GET['post_logout_redirect_uri'] : $base));
        break;

    default:
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(array('error' => 'not_found', 'path' => $uri));
}
