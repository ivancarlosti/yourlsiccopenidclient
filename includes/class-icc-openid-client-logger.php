<?php
/**
 * Simple option based logger with a viewer table.
 *
 * @package   ICC_OpenID_Client
 * @category  Logging
 * @author    Ivan Carlos
 * @license   MIT
 */

// No direct call
if (!defined('YOURLS_ABSPATH'))
    die();

/**
 * ICC_OpenID_Client_Logger class.
 */
class ICC_OpenID_Client_Logger
{
    /**
     * Option holding the log entries.
     */
    const OPTION = 'icc_oidc_logs';

    /**
     * Whether logging is enabled.
     *
     * @var bool
     */
    protected $enabled;

    /**
     * Maximum number of entries to keep.
     *
     * @var int
     */
    protected $limit;

    /**
     * @param bool|null $enabled Whether logging is enabled (defaults to the setting).
     * @param int|null  $limit   Maximum number of entries to keep.
     */
    public function __construct($enabled = null, $limit = null)
    {
        if ($enabled === null) {
            $enabled = function_exists('icc_oidc_get') ? icc_oidc_get('enable_logging') : 0;
        }

        if ($limit === null) {
            $limit = function_exists('icc_oidc_get') ? icc_oidc_get('log_limit') : 1000;
        }

        $this->enabled = (bool) $enabled;
        $this->limit = intval($limit) > 0 ? intval($limit) : 1000;
    }

    /**
     * Is logging enabled?
     *
     * @return bool
     */
    public function is_enabled()
    {
        return $this->enabled;
    }

    /**
     * Write a log entry.
     *
     * @param mixed  $message Message (or object/array to be stringified).
     * @param string $type    Log type/category.
     *
     * @return bool True when the entry was stored.
     */
    public function log($message, $type = 'general')
    {
        if (!$this->enabled) {
            return false;
        }

        if (!is_scalar($message)) {
            if (is_object($message) && method_exists($message, 'getMessage')) {
                $message = get_class($message) . ': ' . $message->getMessage();
            } else {
                $encoded = json_encode($message);
                $message = $encoded === false ? '[unserializable message]' : $encoded;
            }
        }

        $entry = array(
            'time'    => time(),
            'type'    => (string) $type,
            'message' => (string) $message,
            'user'    => $this->current_user(),
        );

        $logs = $this->get_logs();
        array_unshift($logs, $entry);

        if (count($logs) > $this->limit) {
            $logs = array_slice($logs, 0, $this->limit);
        }

        yourls_update_option(self::OPTION, $logs);

        if (function_exists('yourls_debug_log')) {
            yourls_debug_log('ICC OpenID Connect [' . $type . '] ' . $message);
        }

        return true;
    }

    /**
     * Current YOURLS user, if any.
     *
     * @return string
     */
    protected function current_user()
    {
        return defined('YOURLS_USER') && YOURLS_USER !== '' ? (string) YOURLS_USER : '-';
    }

    /**
     * Stored log entries, newest first.
     *
     * @return array
     */
    public function get_logs()
    {
        $logs = yourls_get_option(self::OPTION);

        return is_array($logs) ? $logs : array();
    }

    /**
     * Delete all log entries.
     *
     * @return void
     */
    public function clear_logs()
    {
        yourls_delete_option(self::OPTION);
    }

    /**
     * Log table HTML for the settings page.
     *
     * @return string
     */
    public function get_logs_table()
    {
        $logs = $this->get_logs();

        if (empty($logs)) {
            return '<p>' . icc_oidc_esc_html('No log entries yet.') . '</p>';
        }

        $html = '<table style="width:100%;border-collapse:collapse;" class="icc-oidc-logs">';
        $html .= '<thead><tr>';
        foreach (array('Time', 'Type', 'Message', 'User') as $heading) {
            $html .= '<th style="text-align:left;border-bottom:1px solid #ccc;padding:4px;">'
                . icc_oidc_esc_html($heading) . '</th>';
        }
        $html .= '</tr></thead><tbody>';

        foreach ($logs as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $time = isset($entry['time']) ? intval($entry['time']) : 0;

            $html .= '<tr>';
            $html .= '<td style="border-bottom:1px solid #eee;padding:4px;white-space:nowrap;">'
                . icc_oidc_esc_html($time > 0 ? date('Y-m-d H:i:s', $time) : '-') . '</td>';
            $html .= '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html(isset($entry['type']) ? $entry['type'] : '') . '</td>';
            $html .= '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html(isset($entry['message']) ? $entry['message'] : '') . '</td>';
            $html .= '<td style="border-bottom:1px solid #eee;padding:4px;">'
                . icc_oidc_esc_html(isset($entry['user']) ? $entry['user'] : '-') . '</td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table>';

        return $html;
    }
}
