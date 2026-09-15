<?php
/**
 * SSO login store.
 *
 * YOURLS keeps its users in user/config.php ($yourls_user_passwords) and this
 * plugin never creates users: an OpenID Connect identity is mapped to one of
 * those accounts. This option only remembers which identity was used for which
 * login (plus the last login time and ID token, the latter being sent as
 * id_token_hint on logout).
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
     * Option holding the SSO logins.
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
     * All stored SSO logins.
     *
     * @return array login => data
     */
    public static function all()
    {
        $users = yourls_get_option(self::OPTION);

        return is_array($users) ? $users : array();
    }

    /**
     * Get a stored SSO login.
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
     * Find a stored login by OpenID Connect subject identity.
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
     * Create or update the mapping of an OpenID Connect identity to a YOURLS login.
     *
     * @param string $login YOURLS login (an account from user/config.php).
     * @param array  $data  Identity data.
     *
     * @return array The saved entry.
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
     * Delete a stored SSO login.
     *
     * @param string $login YOURLS login.
     *
     * @return bool True when an entry was removed.
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
}
