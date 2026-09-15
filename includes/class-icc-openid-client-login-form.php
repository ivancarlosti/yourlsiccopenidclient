<?php
/**
 * Login screen integration: SSO button, "button only" mode and error notices.
 *
 * @package   ICC_OpenID_Client
 * @category  Login
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * ICC_OpenID_Client_Login_Form class.
 */
class ICC_OpenID_Client_Login_Form
{
    /**
     * Plugin settings.
     *
     * @var array
     */
    protected $settings;

    /**
     * Protocol client.
     *
     * @var ICC_OpenID_Client_Client|null
     */
    protected $client;

    /**
     * @param array|null  $settings Plugin settings.
     * @param object|null $client   Optional protocol client.
     */
    public function __construct($settings = null, $client = null)
    {
        $this->settings = is_array($settings) ? $settings : icc_oidc_get_all();
        $this->client = $client;
    }

    /**
     * Register the login screen hooks.
     *
     * @return ICC_OpenID_Client_Login_Form
     */
    public static function bootstrap()
    {
        $form = new self();

        yourls_add_action('login_form_top', array($form, 'render_form_top'));
        yourls_add_action('login_form_bottom', array($form, 'render_login_button'));

        return $form;
    }

    /**
     * Get a setting.
     *
     * @param string $key     Setting key.
     * @param mixed  $default Default value.
     *
     * @return mixed
     */
    protected function setting($key, $default = '')
    {
        return isset($this->settings[$key]) ? $this->settings[$key] : $default;
    }

    /**
     * Is the plugin ready to show a login button?
     *
     * @return bool
     */
    protected function is_configured()
    {
        return trim((string) $this->setting('endpoint_login')) !== ''
            && trim((string) $this->setting('client_id')) !== '';
    }

    /**
     * Build (or reuse) the protocol client.
     *
     * @return ICC_OpenID_Client_Client
     */
    protected function client()
    {
        if ($this->client === null) {
            $this->client = new ICC_OpenID_Client_Client($this->settings, new ICC_OpenID_Client_Logger());
        }

        return $this->client;
    }

    /**
     * Message for an error code coming back from the callback.
     *
     * @return string
     */
    protected function error_message()
    {
        if (empty($_GET[ICC_OpenID_Client_Auth::ERROR_VAR])) {
            return '';
        }

        $code = preg_replace('/[^a-zA-Z0-9\-_]/', '', (string) $_GET[ICC_OpenID_Client_Auth::ERROR_VAR]);

        if ($code === '') {
            return '';
        }

        return ICC_OpenID_Client_Auth::error_message($code);
    }

    /**
     * Render the error notice (if any) and hide the password form in "button only" mode.
     *
     * @return void
     */
    public function render_form_top()
    {
        $message = $this->error_message();

        if ($message !== '') {
            echo '<p id="error-message" class="error">' . icc_oidc_esc_html($message) . '</p>' . "\n";
        }

        if ((string) $this->setting('login_type') !== 'button_only') {
            return;
        }

        // "Button only": hide the user name, password and submit fields (and labels).
        echo '<style type="text/css">' . "\n"
            . "#username, #password, #submit, label[for=\"username\"], label[for=\"password\"] { display: none !important; }\n"
            . "</style>\n";

        echo '<script type="text/javascript">' . "\n"
            . "(function(){\n"
            . "  function iccOidcHidePasswordForm(){\n"
            . "    var ids = ['username', 'password', 'submit'];\n"
            . "    for (var i = 0; i < ids.length; i++) {\n"
            . "      var el = document.getElementById(ids[i]);\n"
            . "      if (el && el.parentNode && el.parentNode.tagName === 'P') {\n"
            . "        el.parentNode.style.display = 'none';\n"
            . "      }\n"
            . "    }\n"
            . "  }\n"
            . "  if (document.readyState === 'loading') {\n"
            . "    document.addEventListener('DOMContentLoaded', iccOidcHidePasswordForm);\n"
            . "  } else {\n"
            . "    iccOidcHidePasswordForm();\n"
            . "  }\n"
            . "})();\n"
            . "</script>\n";
    }

    /**
     * Authentication URL for the current login attempt.
     *
     * @return string
     *
     * @throws ICC_OpenID_Client_Error When the login endpoint is not configured.
     */
    protected function authentication_url()
    {
        $redirect_to = '';

        if ($this->setting('redirect_user_back')) {
            $redirect_to = $this->current_url();
        }

        return $this->client()->get_authentication_url($redirect_to);
    }

    /**
     * URL of the page currently being displayed.
     *
     * @return string
     */
    protected function current_url()
    {
        if (empty($_SERVER['REQUEST_URI'])) {
            return '';
        }

        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : '';

        if ($host === '') {
            return '';
        }

        return $scheme . '://' . $host . (string) $_SERVER['REQUEST_URI'];
    }

    /**
     * Button HTML, or an empty string when the plugin is not configured.
     *
     * @return string
     */
    public function get_login_button_html()
    {
        if (!$this->is_configured()) {
            return '';
        }

        try {
            $url = $this->authentication_url();
        } catch (ICC_OpenID_Client_Error $error) {
            return '';
        }

        $text = trim((string) $this->setting('login_button_text'));

        if ($text === '') {
            $text = 'Login with Single Sign-On';
        }

        /**
         * Filter the SSO login button text.
         *
         * @param string $text Button text.
         */
        $text = yourls_apply_filter('icc_oidc_login_button_text', $text);

        $logo = trim((string) $this->setting('login_button_logo_url'));
        $logo_html = '';

        if ($logo !== '' && preg_match('#^https?://#i', $logo)) {
            $logo_html = '<img src="' . icc_oidc_esc_url($logo) . '" alt=""'
                . ' style="height:1.25em;width:auto;vertical-align:middle;margin-right:6px;" />';
        }

        return '<p class="icc-oidc-login-button" style="text-align:center;margin:1em 0;">'
            . '<a class="button" href="' . icc_oidc_esc_url($url) . '"'
            . ' style="display:inline-block;padding:6px 12px;">'
            . $logo_html . icc_oidc_esc_html($text)
            . '</a></p>' . "\n";
    }

    /**
     * Output the login button on the login screen.
     *
     * @return void
     */
    public function render_login_button()
    {
        echo $this->get_login_button_html();
    }
}
