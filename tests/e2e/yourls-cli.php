<?php
/**
 * YOURLS bootstrap/CLI helper for the end to end test.
 *
 * Usage (inside the container):
 *   php yourls-cli.php setup
 *   php yourls-cli.php option <name> <value>
 *   php yourls-cli.php show
 *
 * @package ICC_OpenID_Client
 */

define('YOURLS_INSTALLING', true);

$app = getenv('YOURLS_APP_DIR') ?: '/app';

require rtrim($app, '/') . '/includes/load-yourls.php';
require_once YOURLS_INC . '/functions-install.php';

$action = isset($argv[1]) ? $argv[1] : 'show';

if ($action === 'setup') {
    if (!yourls_is_installed()) {
        $result = yourls_create_sql_tables();

        foreach ((array) $result as $type => $messages) {
            foreach ((array) $messages as $message) {
                echo strtoupper($type) . ': ' . $message . "\n";
            }
        }

        yourls_initialize_options();
        echo "tables created\n";
    }

    yourls_update_option('active_plugins', array('icc-openid-client/plugin.php'));
    yourls_update_option('icc_oidc_client_id', 'yourls-client');
    yourls_update_option('icc_oidc_client_secret', 'yourls-secret');
    yourls_update_option('icc_oidc_endpoint_login', 'http://127.0.0.1:8089/realms/mock/protocol/openid-connect/auth');
    yourls_update_option('icc_oidc_endpoint_token', 'http://127.0.0.1:8089/realms/mock/protocol/openid-connect/token');
    yourls_update_option('icc_oidc_endpoint_userinfo', 'http://127.0.0.1:8089/realms/mock/protocol/openid-connect/userinfo');
    yourls_update_option('icc_oidc_endpoint_jwks', 'http://127.0.0.1:8089/realms/mock/protocol/openid-connect/certs');
    yourls_update_option('icc_oidc_endpoint_end_session', 'http://127.0.0.1:8089/realms/mock/protocol/openid-connect/logout');
    yourls_update_option('icc_oidc_issuer', 'http://127.0.0.1:8089/realms/mock');
    yourls_update_option('icc_oidc_allow_internal_idp', 1);
    yourls_update_option('icc_oidc_login_type', 'auto');
    yourls_update_option('icc_oidc_create_if_does_not_exist', 1);
    yourls_update_option('icc_oidc_enable_logging', 1);
    echo "plugin configured\n";

    exit(0);
}

if ($action === 'option') {
    $name = isset($argv[2]) ? $argv[2] : '';
    $value = isset($argv[3]) ? $argv[3] : '';
    yourls_update_option($name, $value === '0' ? 0 : $value);
    echo 'set ' . $name . ' -> ' . json_encode(yourls_get_option($name)) . "\n";

    exit(0);
}

echo 'users option: ' . json_encode(yourls_get_option('icc_oidc_users')) . "\n";

$logs = yourls_get_option('icc_oidc_logs');

if (is_array($logs)) {
    echo 'log entries: ' . count($logs) . "\n";

    foreach (array_slice($logs, 0, 8) as $entry) {
        echo '  [' . $entry['type'] . '] ' . substr($entry['message'], 0, 160) . "\n";
    }
}
