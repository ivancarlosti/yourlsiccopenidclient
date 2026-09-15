<?php
/**
 * SSO user store.
 *
 * YOURLS keeps its users in user/config.php ($yourls_user_passwords), so SSO
 * accounts are stored in a plugin option and injected into that global at
 * plugin load time. This is what allows YOURLS' own cookie verification to
 * accept them, while password authentication stays impossible for them.
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
 * ICC_OpenID_Client_Store class.
 */
class ICC_OpenID_Client_Store
{
    /**
     * Option holding the SSO users.
     */
    const OPTION = 'icc_oidc_users';

    /**
     * Optional logger.
     *
     * @var object|null
     */
    protected $logger;

    /**
     * @param object|null $logger Optional logger.
     */
    public function __construct($logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * All stored SSO users.
     *
     * @return array login => data
     */
    public static function all()
    {
        $users = yourls_get_option(self::OPTION);

        return is_array($users) ? $users : array();
    }

    /**
     * Get a stored SSO user.
     *
     * @param string $login YOURLS login.
     *
     * @return array|null
     */
    public static function get($login)
    {
        $users = self::all();

        return isset($users[$login]) && is_array($users[$login]) ? $users[$login] : null;
    }

    /**
     * Find a stored user by OpenID Connect subject identity.
     *
     * @param string $subject Subject ("sub" claim).
     *
     * @return string|null The login, or null when unknown.
     */
    public static function find_login_by_subject($subject)
    {
        $subject = (string) $subject;

        foreach (self::all() as $login => $data) {
            if (
                is_array($data)
                && isset($data['subject'])
                && (string) $data['subject'] === $subject
            ) {
                return (string) $login;
            }
        }

        return null;
    }

    /**
     * Find a stored user by email address.
     *
     * @param string $email Email address.
     *
     * @return string|null The login, or null when unknown.
     */
    public static function find_login_by_email($email)
    {
        $email = strtolower(trim((string) $email));

        if ($email === '') {
            return null;
        }

        foreach (self::all() as $login => $data) {
            if (is_array($data) && !empty($data['email']) && strtolower((string) $data['email']) === $email) {
                return (string) $login;
            }
        }

        return null;
    }

    /**
     * Create or update an SSO user.
     *
     * @param string $login YOURLS login.
     * @param array  $data  User data.
     *
     * @return array The saved user.
     */
    public function save($login, array $data)
    {
        $users = self::all();
        $existing = isset($users[$login]) && is_array($users[$login]) ? $users[$login] : array();

        $users[$login] = array_merge(
            array(
                'subject'      => '',
                'email'        => '',
                'nickname'     => '',
                'displayname'  => '',
                'linked'       => 0,
                'created'      => time(),
                'last_login'   => 0,
                'last_id_token' => '',
            ),
            $existing,
            $data
        );

        yourls_update_option(self::OPTION, $users);

        return $users[$login];
    }

    /**
     * Delete a stored SSO user.
     *
     * @param string $login YOURLS login.
     *
     * @return bool True when a user was removed.
     */
    public function remove($login)
    {
        $users = self::all();

        if (!isset($users[$login])) {
            return false;
        }

        unset($users[$login]);
        yourls_update_option(self::OPTION, $users);

        return true;
    }

    /**
     * Store the outcome of a successful login (last login time and ID token).
     *
     * @param string $login    YOURLS login.
     * @param string $id_token Last ID token (used for the logout hint).
     *
     * @return void
     */
    public function record_login($login, $id_token = '')
    {
        $this->save($login, array(
            'last_login'    => time(),
            'last_id_token' => (string) $id_token,
        ));
    }

    /**
     * Inject stored SSO users into YOURLS' user list.
     *
     * Must run while the plugin file is included (before any authentication
     * happens) so cookie verification accepts SSO accounts. Users already
     * defined in user/config.php are never overridden.
     *
     * @return void
     */
    public static function inject_virtual_users()
    {
        global $yourls_user_passwords;

        if (!isset($yourls_user_passwords) || !is_array($yourls_user_passwords)) {
            $yourls_user_passwords = array();
        }

        foreach (self::all() as $login => $data) {
            if (!is_string($login) || $login === '' || isset($yourls_user_passwords[$login])) {
                continue;
            }

            $yourls_user_passwords[$login] = 'phpass:' . self::unusable_password_hash($login);
        }
    }

    /**
     * Build an unverifiable password hash for an SSO account.
     *
     * The value is keyed with YOURLS' own secret, so it can neither be matched
     * through password_verify() nor guessed as a clear text password.
     *
     * @param string $login YOURLS login.
     *
     * @return string
     */
    public static function unusable_password_hash($login)
    {
        if (function_exists('yourls_salt')) {
            $secret = yourls_salt('icc-oidc-password:' . $login);
        } else {
            $key = defined('YOURLS_COOKIEKEY') ? YOURLS_COOKIEKEY : '';
            $secret = hash('sha256', 'icc-oidc-password:' . $login . '|' . $key);
        }

        return hash('sha256', $secret . '|unusable');
    }

    /**
     * Is this login an SSO managed account (not a config.php password account)?
     *
     * @param string $login YOURLS login.
     *
     * @return bool
     */
    public static function is_virtual_user($login)
    {
        $user = self::get($login);

        if ($user === null) {
            return false;
        }

        // Linked accounts exist in config.php and keep their password login.
        return (int) (isset($user['linked']) ? $user['linked'] : 0) !== 1;
    }
}
