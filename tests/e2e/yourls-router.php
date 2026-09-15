<?php
/**
 * Router for PHP's built-in server that mimics the YOURLS .htaccess rewrites:
 * real files are served as is, anything else goes through yourls-loader.php.
 *
 * Used by the end to end test only.
 *
 * @package ICC_OpenID_Client
 */

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$app  = getenv('YOURLS_APP_DIR') ?: '/app';
$candidate = rtrim($app, '/') . $path;

if ($path !== '/' && is_file($candidate)) {
    return false; // Let the built-in server serve admin/*.php, css, js, images...
}

require rtrim($app, '/') . '/yourls-loader.php';
