<?php
/*
Plugin Name: ICC OpenID Connect Client
Plugin URI: https://github.com/ivancarlosti/yourlsiccopenidclient
Description: Login to YOURLS with Single Sign-On using any OpenID Connect identity provider (Keycloak, Entra ID, Google, Auth0, ...) and Authorization Code Flow. Features SSO auto login, login button on the login form, email domain restriction, single logout and a debug log.
Version: 1.0.0
Author: Ivan Carlos
Author URI: https://ivancarlos.com.br/
*/

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

// Plugin version (kept in sync with the header above by the release workflow).
define('ICC_OIDC_VERSION', '1.0.0');

// Plugin directory.
define('ICC_OIDC_PLUGIN_DIR', dirname(__FILE__));

// Shared helpers, settings accessors and the plugin autoloader.
require_once ICC_OIDC_PLUGIN_DIR . '/includes/functions-icc-openid-client.php';

yourls_add_action('plugins_loaded', 'icc_oidc_bootstrap');

/**
 * Register plugin features once all plugins are loaded.
 *
 * YOURLS calls "plugins_loaded" from includes/load-yourls.php, before any entry
 * point runs the authentication, which gives this plugin the opportunity to
 * serve its OAuth callback endpoints and to catch the "require_auth" action.
 *
 * @return void
 */
function icc_oidc_bootstrap()
{
    // Callback (?icc_oidc=callback), logout (?icc_oidc=logout) and hooks.
    ICC_OpenID_Client_Auth::bootstrap();

    // Login screen: SSO button, "button only" mode and error notices.
    ICC_OpenID_Client_Login_Form::bootstrap();

    // Admin page: "OpenID Connect" (settings, discovery import, users, logs).
    ICC_OpenID_Client_Settings_Page::register();
}
