<?php
/*
Plugin Name: ICC OpenID Connect Client
Plugin URI: https://github.com/ivancarlosti/yourlsiccopenidclient
Description: Login to YOURLS with Single Sign-On using any OpenID Connect identity provider (Keycloak, Entra ID, Google, Auth0, ...) and Authorization Code Flow. Features SSO auto login, login button on the login form, email domain restriction, single logout and a debug log.
Version:           3.1.1
Author: Ivan Carlos
Author URI: https://ivancarlos.com.br/
*/

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

// Plugin version (kept in sync with the header above by the release workflow).
define('ICC_OIDC_VERSION', '3.1.1');

// Plugin directory.
define('ICC_OIDC_PLUGIN_DIR', dirname(__FILE__));

// Shared helpers, settings accessors and the plugin autoloader.
require_once ICC_OIDC_PLUGIN_DIR . '/includes/functions-icc-openid-client.php';

// Minimum supported PHP version (kept in sync with the plugin page and README).
define('ICC_OIDC_MIN_PHP', '8.2');

if (version_compare(PHP_VERSION, ICC_OIDC_MIN_PHP, '<')) {
    // Register a page that explains the requirement, then stop: no callback
    // endpoint, no SSO button and no hook runs on an unsupported PHP version.
    yourls_add_action('plugins_loaded', 'icc_oidc_php_version_notice_register_page');
    return;
}

yourls_add_action('plugins_loaded', 'icc_oidc_bootstrap');

/**
 * Register the OpenID Connect page when PHP is below ICC_OIDC_MIN_PHP.
 *
 * Uses the same slug as the settings page so the admin menu entry stays put and
 * the administrator lands on the explanation instead of a blank screen.
 *
 * @return void
 */
function icc_oidc_php_version_notice_register_page()
{
    yourls_register_plugin_page(
        'icc_openid_client',
        'OpenID Connect',
        'icc_oidc_php_version_notice'
    );
}

/**
 * Explain that Single Sign-On is disabled on an unsupported PHP version.
 *
 * @return void
 */
function icc_oidc_php_version_notice()
{
    echo '<p style="color:#a33;"><strong>'
        . icc_oidc_esc_html(
            sprintf(
                'This plugin requires PHP %s or later. This YOURLS installation runs PHP %s, so Single Sign-On is disabled.',
                ICC_OIDC_MIN_PHP,
                PHP_VERSION
            )
        )
        . '</strong></p>' . "\n";
}

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
