<?php
/**
 * Admin settings page.
 *
 * Registered as a YOURLS plugin page ("OpenID Connect"): client settings,
 * discovery import, SSO user list and log viewer.
 *
 * @package   ICC_OpenID_Client
 * @category  Settings
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * ICC_OpenID_Client_Settings_Page class.
 */
class ICC_OpenID_Client_Settings_Page
{
    /**
     * Plugin page slug.
     */
    const SLUG = 'icc_openid_client';

    /**
     * Nonce action.
     */
    const NONCE_ACTION = 'icc_oidc_settings';

    /**
     * Logger instance.
     *
     * @var ICC_OpenID_Client_Logger
     */
    protected $logger;

    /**
     * Feedback messages to display.
     *
     * @var array
     */
    protected $notices = array();

    /**
     * Settings values read from a discovery document (not saved yet).
     *
     * @var array
     */
    protected $discovered = array();

    /**
     * @param ICC_OpenID_Client_Logger|null $logger Logger.
     */
    public function __construct($logger = null)
    {
        $this->logger = $logger !== null ? $logger : new ICC_OpenID_Client_Logger();
    }

    /**
     * Register the plugin page.
     *
     * @return ICC_OpenID_Client_Settings_Page
     */
    public static function register()
    {
        $page = new self();

        yourls_register_plugin_page(self::SLUG, 'OpenID Connect', array($page, 'render'));

        return $page;
    }

    /**
     * Field definitions, grouped by section.
     *
     * @return array
     */
    protected function fields()
    {
        return array(
            'client_settings' => array(
                'title'  => 'Client Settings',
                'fields' => array(
                    'login_type'            => array('label' => 'Login Type', 'type' => 'select', 'options' => array(
                        'button'      => 'OpenID Connect button on login form',
                        'button_only' => 'OpenID Connect button only (no password form)',
                        'auto'        => 'Auto Login - SSO',
                    ), 'hint' => 'How the login screen should offer the SSO login.'),
                    'login_button_text'     => array('label' => 'Login Button Text', 'type' => 'text', 'hint' => 'Empty uses "Login with Single Sign-On".'),
                    'login_button_logo_url' => array('label' => 'Login Button Logo URL', 'type' => 'text', 'hint' => 'Optional image shown before the button text.'),
                    'client_id'             => array('label' => 'Client ID', 'type' => 'text', 'hint' => 'Client identifier registered at the identity provider.'),
                    'client_secret'         => array('label' => 'Client Secret', 'type' => 'password', 'hint' => 'Client secret from the identity provider.'),
                    'scope'                 => array('label' => 'OpenID Scope', 'type' => 'text', 'hint' => 'Space separated, e.g. "openid profile email".'),
                    'endpoint_login'        => array('label' => 'Login Endpoint URL', 'type' => 'url', 'hint' => 'Authorization endpoint.'),
                    'endpoint_token'        => array('label' => 'Token Endpoint URL', 'type' => 'url', 'hint' => 'Token endpoint.'),
                    'endpoint_userinfo'     => array('label' => 'Userinfo Endpoint URL', 'type' => 'url', 'hint' => 'Optional: user information endpoint.'),
                    'endpoint_end_session'  => array('label' => 'Logout Endpoint URL', 'type' => 'url', 'hint' => 'Optional: end session endpoint for single logout.'),
                    'endpoint_jwks'         => array('label' => 'JWKS Endpoint URL', 'type' => 'url', 'hint' => 'Required: signing keys used to verify ID tokens.'),
                    'issuer'                => array('label' => 'Issuer', 'type' => 'text', 'hint' => 'Optional: derived from the login endpoint when empty.'),
                    'jwks_cache_ttl'        => array('label' => 'JWKS Cache TTL (seconds)', 'type' => 'number', 'hint' => 'Default: 3600.'),
                    'acr_values'            => array('label' => 'ACR Values', 'type' => 'text', 'hint' => 'Optional authentication context.'),
                    'http_request_timeout'  => array('label' => 'HTTP Request Timeout (seconds)', 'type' => 'number', 'hint' => 'Default: 5.'),
                    'no_sslverify'          => array('label' => 'Disable SSL Verify', 'type' => 'checkbox', 'hint' => 'Development only: ignored unless YOURLS_DEBUG is on.'),
                    'allow_internal_idp'    => array('label' => 'Allow Internal IdP', 'type' => 'checkbox', 'hint' => 'Allow HTTP and private network endpoints (local development).'),
                ),
            ),
            'user_settings' => array(
                'title'       => 'User Settings',
                'description' => 'Single Sign-On signs in as a YOURLS user defined in user/config.php: the identity claim is matched against the login name (and a single YOURLS user is used when the claim does not match). No account is ever created here.',
                'fields'      => array(
                    'identity_key'             => array('label' => 'Identity Key', 'type' => 'text', 'hint' => 'Claim matched against the YOURLS login from user/config.php, e.g. preferred_username, sub or email.'),
                    'nickname_key'             => array('label' => 'Nickname Key', 'type' => 'text', 'hint' => 'Claim used as the nickname.'),
                    'email_format'             => array('label' => 'Email Formatting', 'type' => 'text', 'hint' => 'Claim string used to build the email, e.g. {email}.'),
                    'displayname_format'       => array('label' => 'Display Name Formatting', 'type' => 'text', 'hint' => 'Optional, e.g. {given_name} {family_name}.'),
                    'email_domain_restriction' => array('label' => 'Email Domain Restriction', 'type' => 'text', 'hint' => 'Space separated allowed domains or email addresses. Empty allows all.'),
                ),
            ),
            'session_settings' => array(
                'title'  => 'Authorization Settings',
                'fields' => array(
                    'state_time_limit'   => array('label' => 'State Time Limit (seconds)', 'type' => 'number', 'hint' => 'Lifetime of a login attempt. Default: 180.'),
                    'redirect_uri'       => array('label' => 'Redirect URI Override', 'type' => 'text', 'hint' => 'Optional custom callback URL (must be registered at the identity provider).'),
                    'redirect_user_back' => array('label' => 'Redirect Back to Origin Page', 'type' => 'checkbox', 'hint' => 'Return the user to the page they started from.'),
                    'redirect_on_logout' => array('label' => 'Redirect to IdP on logout', 'type' => 'checkbox', 'hint' => 'End the identity provider session when logging out.'),
                ),
            ),
            'log_settings' => array(
                'title'  => 'Log Settings',
                'fields' => array(
                    'enable_logging' => array('label' => 'Enable Logging', 'type' => 'checkbox', 'hint' => 'Keep a debug log of SSO activity.'),
                    'log_limit'      => array('label' => 'Log Limit', 'type' => 'number', 'hint' => 'Number of entries to keep. Default: 1000.'),
                ),
            ),
        );
    }

    /**
     * Handle POST actions (must run before any output).
     *
     * @return void
     */
    protected function handle_post()
    {
        if (empty($_POST['icc_oidc_action'])) {
            return;
        }

        $action = (string) $_POST['icc_oidc_action'];

        // Every action carries our nonce (dies on failure, like the rest of YOURLS).
        if (function_exists('yourls_verify_nonce')) {
            yourls_verify_nonce(self::NONCE_ACTION);
        }

        if ($action === 'save') {
            $this->save_settings();

            return;
        }

        if ($action === 'discover') {
            $this->import_discovery();

            return;
        }

        if ($action === 'clear_logs') {
            $this->logger->clear_logs();
            $this->notices[] = array('success', 'Log entries cleared.');

            return;
        }

        if ($action === 'remove_user') {
            $this->remove_user();
        }
    }

    /**
     * Store the submitted settings (constants in config.php always win).
     *
     * @return void
     */
    protected function save_settings()
    {
        $saved = 0;
        $skipped = array();

        foreach ($this->fields() as $section) {
            foreach ($section['fields'] as $key => $field) {
                if (icc_oidc_is_constant($key)) {
                    $skipped[] = $key;

                    continue;
                }

                yourls_update_option(icc_oidc_option_name($key), $this->sanitize_field($field, $key));
                $saved++;
            }
        }

        $this->notices[] = array('success', sprintf('Settings saved (%d values).', $saved));

        if (!empty($skipped)) {
            $this->notices[] = array(
                'info',
                'Defined as constants in config.php, so not stored here: ' . implode(', ', $skipped) . '.',
            );
        }
    }

    /**
     * Sanitize one submitted field.
     *
     * @param array  $field Field definition.
     * @param string $key   Setting key.
     *
     * @return mixed
     */
    protected function sanitize_field($field, $key)
    {
        $post_key = 'icc_oidc_' . $key;

        if ($field['type'] === 'checkbox') {
            return isset($_POST[$post_key]) ? 1 : 0;
        }

        $raw = isset($_POST[$post_key]) ? (string) $_POST[$post_key] : '';
        $raw = trim($raw);

        if ($field['type'] === 'number') {
            $number = intval($raw);

            return $number < 0 ? 0 : $number;
        }

        if ($field['type'] === 'select') {
            $options = isset($field['options']) ? $field['options'] : array();

            return isset($options[$raw]) ? $raw : '';
        }

        // Drop control characters from free text values.
        $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $raw);

        if (!is_string($clean)) {
            $clean = '';
        }

        if ($field['type'] === 'url' && $clean !== '') {
            $parts = parse_url($clean);

            if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])
                || !in_array(strtolower($parts['scheme']), array('http', 'https'), true)
            ) {
                $this->notices[] = array(
                    'error',
                    'Ignored an invalid URL for "' . $field['label'] . '" (only http and https are allowed).',
                );

                return '';
            }
        }

        return $clean;
    }

    /**
     * Import endpoints from an OpenID Connect discovery document.
     *
     * @return void
     */
    protected function import_discovery()
    {
        $url = isset($_POST['icc_oidc_discovery_url']) ? trim((string) $_POST['icc_oidc_discovery_url']) : '';
        $client = new ICC_OpenID_Client_Client(icc_oidc_get_all(), $this->logger);

        try {
            $document = $client->discover($url);
            $this->discovered = $client->map_discovery_to_settings($document);

            $this->notices[] = array(
                'success',
                sprintf(
                    'Configuration loaded (%d values). Review the fields below and click "Save settings" to apply.',
                    count($this->discovered)
                ),
            );
        } catch (ICC_OpenID_Client_Error $error) {
            $this->notices[] = array('error', $error->getMessage());
        }
    }

    /**
     * Forget the OpenID Connect identity linked to a YOURLS user.
     *
     * @return void
     */
    protected function remove_user()
    {
        $login = isset($_POST['icc_oidc_user']) ? trim((string) $_POST['icc_oidc_user']) : '';
        $store = new ICC_OpenID_Client_Store($this->logger);

        if ($login === '' || !$store->remove($login)) {
            $this->notices[] = array('error', 'The SSO login could not be found.');

            return;
        }

        $this->notices[] = array(
            'success',
            'Forgot the OpenID Connect identity linked to "' . $login . '". '
                . 'The YOURLS user in config.php is unchanged and is linked again on the next SSO login.',
        );
    }

    /**
     * Render the settings page.
     *
     * @return void
     */
    public function render()
    {
        $this->handle_post();

        $settings = icc_oidc_get_all();
        $redirect_uri = icc_oidc_redirect_uri();

        $this->render_notices();

        $this->render_discovery_form();

        echo '<form method="post" action="">' . "\n";

        if (function_exists('yourls_nonce_field')) {
            yourls_nonce_field(self::NONCE_ACTION);
        }

        echo '<input type="hidden" name="icc_oidc_action" value="save" />' . "\n";

        foreach ($this->fields() as $section_key => $section) {
            echo '<h3>' . icc_oidc_esc_html($section['title']) . '</h3>' . "\n";

            if (!empty($section['description'])) {
                echo '<p><small>' . icc_oidc_esc_html($section['description']) . '</small></p>' . "\n";
            }

            foreach ($section['fields'] as $key => $field) {
                $this->render_field($key, $field, $settings);
            }
        }

        echo '<p><input type="submit" class="button" value="Save settings" /></p>' . "\n";
        echo '</form>' . "\n";

        $this->render_users();
        $this->render_logs($settings);
        $this->render_notes($redirect_uri);
        $this->render_footer();
    }

    /**
     * Output the feedback messages.
     *
     * @return void
     */
    protected function render_notices()
    {
        foreach ($this->notices as $notice) {
            $type = $notice[0] === 'error' ? 'error' : ($notice[0] === 'info' ? 'message' : 'success');
            $color = $notice[0] === 'error' ? '#a33' : ($notice[0] === 'info' ? '#666' : '#2a7a2a');

            echo '<div class="' . icc_oidc_esc_attr($type) . '" style="border-left:4px solid ' . $color
                . ';padding:8px;margin:10px 0;background:#f8f8f8;">'
                . icc_oidc_esc_html($notice[1]) . '</div>' . "\n";
        }
    }

    /**
     * Output the discovery import form.
     *
     * @return void
     */
    protected function render_discovery_form()
    {
        echo '<h3>Quick Setup</h3>' . "\n";
        echo '<p>Import the endpoints from your identity provider discovery document '
            . '(for example <code>https://sso.example.com/realms/myrealm/.well-known/openid-configuration</code>).</p>' . "\n";

        echo '<form method="post" action="">' . "\n";

        if (function_exists('yourls_nonce_field')) {
            yourls_nonce_field(self::NONCE_ACTION);
        }

        echo '<input type="hidden" name="icc_oidc_action" value="discover" />' . "\n";
        echo '<p><label for="icc_oidc_discovery_url" style="display:inline-block;width:230px;">Discovery URL</label>'
            . '<input type="text" id="icc_oidc_discovery_url" name="icc_oidc_discovery_url" value="" size="80" />'
            . '<br /><span style="padding-left:235px;"><small>Loaded values are shown below but are only stored when you save the settings.</small></span></p>' . "\n";
        echo '<p><input type="submit" class="button" value="Load configuration" /></p>' . "\n";
        echo '</form>' . "\n";
    }

    /**
     * Output a single settings field.
     *
     * @param string $key      Setting key.
     * @param array  $field    Field definition.
     * @param array  $settings Stored settings.
     *
     * @return void
     */
    protected function render_field($key, $field, $settings)
    {
        $value = isset($this->discovered[$key])
            ? $this->discovered[$key]
            : (isset($settings[$key]) ? $settings[$key] : '');

        $name = 'icc_oidc_' . $key;
        $disabled = icc_oidc_is_constant($key);
        $disabled_attr = $disabled ? ' disabled="disabled"' : '';
        $label_style = 'display:inline-block;width:230px;vertical-align:top;';

        echo '<p>';
        echo '<label for="' . icc_oidc_esc_attr($name) . '" style="' . $label_style . '">'
            . icc_oidc_esc_html($field['label']) . '</label>';

        if ($field['type'] === 'checkbox') {
            echo '<input type="checkbox" id="' . icc_oidc_esc_attr($name) . '" name="' . icc_oidc_esc_attr($name)
                . '" value="1"' . ($value ? ' checked="checked"' : '') . $disabled_attr . ' />';
        } elseif ($field['type'] === 'select') {
            echo '<select id="' . icc_oidc_esc_attr($name) . '" name="' . icc_oidc_esc_attr($name) . '"' . $disabled_attr . '>';

            foreach ($field['options'] as $option_value => $option_label) {
                echo '<option value="' . icc_oidc_esc_attr($option_value) . '"'
                    . ((string) $value === (string) $option_value ? ' selected="selected"' : '') . '>'
                    . icc_oidc_esc_html($option_label) . '</option>';
            }

            echo '</select>';
        } else {
            $type = in_array($field['type'], array('number', 'password'), true) ? $field['type'] : 'text';
            $size = $field['type'] === 'number' ? '10' : '80';

            echo '<input type="' . icc_oidc_esc_attr($type) . '" id="' . icc_oidc_esc_attr($name) . '" name="'
                . icc_oidc_esc_attr($name) . '" value="' . icc_oidc_esc_attr($value) . '" size="' . $size . '"'
                . ($type === 'password' ? ' autocomplete="new-password"' : '') . $disabled_attr . ' />';
        }

        if (!empty($field['hint'])) {
            echo '<br /><span style="padding-left:235px;"><small>' . icc_oidc_esc_html($field['hint']) . '</small></span>';
        }

        if ($disabled) {
            echo '<br /><span style="padding-left:235px;"><small>'
                . icc_oidc_esc_html('Defined as a constant in config.php (read only here).')
                . '</small></span>';
        }

        echo '</p>' . "\n";
    }

    /**
     * Output the YOURLS accounts used by Single Sign-On.
     *
     * @return void
     */
    protected function render_users()
    {
        $users = ICC_OpenID_Client_Store::all();

        echo '<hr style="margin-top: 40px" />' . "\n";
        echo '<h3>SSO Logins</h3>' . "\n";
        echo '<p><small>Last OpenID Connect identity used for each YOURLS user from user/config.php. '
            . 'Forgetting an identity only clears this list: the next SSO login links it again.</small></p>' . "\n";

        if (empty($users)) {
            echo '<p>No Single Sign-On login has been recorded yet.</p>' . "\n";

            return;
        }

        echo '<table style="width:100%;border-collapse:collapse;">' . "\n";
        echo '<thead><tr>';

        foreach (array('User', 'Subject', 'Email', 'Display name', 'Last login', '') as $heading) {
            echo '<th style="text-align:left;border-bottom:1px solid #ccc;padding:4px;">'
                . icc_oidc_esc_html($heading) . '</th>';
        }

        echo '</tr></thead><tbody>' . "\n";

        foreach ($users as $login => $data) {
            if (!is_array($data)) {
                continue;
            }

            $last_login = isset($data['last_login']) ? intval($data['last_login']) : 0;

            echo '<tr>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;"><strong>' . icc_oidc_esc_html($login) . '</strong></td>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;"><code>'
                . icc_oidc_esc_html(isset($data['subject']) ? $data['subject'] : '') . '</code></td>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html(isset($data['email']) ? $data['email'] : '') . '</td>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html(isset($data['displayname']) ? $data['displayname'] : '') . '</td>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html($last_login > 0 ? date('Y-m-d H:i:s', $last_login) : 'never') . '</td>';
            echo '<td style="border-bottom:1px solid #eee;padding:4px;">';

            echo '<form method="post" action="" style="margin:0;">';

            if (function_exists('yourls_nonce_field')) {
                yourls_nonce_field(self::NONCE_ACTION);
            }

            echo '<input type="hidden" name="icc_oidc_action" value="remove_user" />';
            echo '<input type="hidden" name="icc_oidc_user" value="' . icc_oidc_esc_attr($login) . '" />';
            echo '<input type="submit" class="button" value="Forget" />';
            echo '</form>';

            echo '</td>';
            echo '</tr>' . "\n";
        }

        echo '</tbody></table>' . "\n";
    }

    /**
     * Output the log viewer (when logging is enabled).
     *
     * @param array $settings Current settings.
     *
     * @return void
     */
    protected function render_logs($settings)
    {
        if (empty($settings['enable_logging'])) {
            return;
        }

        echo '<hr style="margin-top: 40px" />' . "\n";
        echo '<h3>Logs</h3>' . "\n";
        echo '<div id="icc-oidc-logs-wrapper" style="max-height:400px;overflow:auto;font-size:12px;">'
            . $this->logger->get_logs_table() . '</div>' . "\n";

        echo '<form method="post" action="">' . "\n";

        if (function_exists('yourls_nonce_field')) {
            yourls_nonce_field(self::NONCE_ACTION);
        }

        echo '<input type="hidden" name="icc_oidc_action" value="clear_logs" />' . "\n";
        echo '<p><input type="submit" class="button" value="Clear logs" /></p>' . "\n";
        echo '</form>' . "\n";
    }

    /**
     * Output the setup notes (redirect URI, issuer hints, requirements).
     *
     * @param string $redirect_uri Effective redirect URI.
     *
     * @return void
     */
    protected function render_notes($redirect_uri)
    {
        echo '<hr style="margin-top: 40px" />' . "\n";
        echo '<h3>Notes</h3>' . "\n";

        echo '<p><strong>Redirect URI</strong><br />'
            . '<code>' . icc_oidc_esc_html($redirect_uri) . '</code><br />'
            . '<small>Register this exact URL as a valid redirect URI for the client at your identity provider.</small></p>' . "\n";

        echo '<p><strong>Logout URL</strong><br />'
            . '<code>' . icc_oidc_esc_html(icc_oidc_logout_url()) . '</code><br />'
            . '<small>Clears the YOURLS session (and the provider session when single logout is enabled). '
            . 'It follows the Redirect URI Override, so both endpoints stay on the same entry point.</small></p>' . "\n";

        if (!icc_oidc_is_local_url($redirect_uri)) {
            echo '<p style="color:#a33;"><strong>Warning:</strong> the redirect URI above does not point at this YOURLS installation ('
                . icc_oidc_esc_html(icc_oidc_site_url()) . '): the identity provider response would never reach the plugin. '
                . 'Set the Redirect URI Override to a URL served by YOURLS.</p>' . "\n";
        } else {
            echo '<p><small>The redirect URI must be answered by YOURLS itself. If another application or a static '
                . '<code>index.php</code> owns the site root, set the Redirect URI Override to a YOURLS URL '
                . '(for example <code>[your YOURLS admin URL]?icc_oidc=callback</code>) and register it at the identity provider.</small></p>' . "\n";
        }

        echo '<p><strong>Issuer examples</strong><br />'
            . '<small>Keycloak: <code>https://host/realms/&lt;realm&gt;</code> &middot; '
            . 'Entra ID: <code>https://login.microsoftonline.com/&lt;tenant&gt;/v2.0</code> &middot; '
            . 'Google: <code>https://accounts.google.com</code></small></p>' . "\n";

        echo '<p><strong>Requirements</strong><br />'
            . '<small>YOURLS 1.8.2+ (tested on 1.10.x), PHP 7.4+, ext-openssl. '
            . 'No third party libraries are bundled.</small></p>' . "\n";

        if (!icc_oidc_is_https(icc_oidc_site_url())) {
            echo '<p style="color:#a33;"><strong>Warning:</strong> this YOURLS installation is not served over HTTPS. '
                . 'Single Sign-On requires HTTPS in production.</p>' . "\n";
        }
    }

    /**
     * Output the page footer.
     *
     * @return void
     */
    protected function render_footer()
    {
        $version = defined('ICC_OIDC_VERSION') ? ICC_OIDC_VERSION : '';

        echo '<hr style="margin-top: 40px">' . "\n";
        echo '<p style="text-align: center; color: #666; font-size: 12px;">'
            . icc_oidc_esc_html('ICC OpenID Connect Client - OpenID Connect SSO for YOURLS') . '<br />'
            . '<a href="https://github.com/ivancarlosti/yourlsiccopenidclient" target="_blank" rel="noopener noreferrer">'
            . 'github.com/ivancarlosti/yourlsiccopenidclient</a><br />'
            . icc_oidc_esc_html('v' . $version) . '</p>' . "\n";

        echo '<p style="text-align: center;"><strong>'
            . '<a href="https://ivancarlos.me/" target="_blank" rel="noopener noreferrer">Ivan Carlos</a></strong>'
            . ' &raquo; <a href="https://buymeacoffee.com/ivancarlos" target="_blank" rel="noopener noreferrer">'
            . 'Buy Me a Coffee</a></p>' . "\n";
    }
}
