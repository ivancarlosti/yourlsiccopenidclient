<?php
/**
 * Plugin layout and version guard.
 *
 * YOURLS loads a plugin from `<YOURLS_PLUGINDIR>/<folder>/plugin.php` only:
 * `yourls_get_plugins()` keeps one entry per plugin folder and only for the
 * file named `plugin.php`, and `yourls_is_a_plugin_file()` rejects any other
 * file name. A package is therefore only loadable when it keeps exactly one
 * `Plugin Name:` header, in `plugin.php`, at the root of the plugin folder.
 *
 * This guard fails the build when the tree YOURLS would see is wrong:
 *
 *  - `plugin.php` is missing, or declares no `Plugin Name:` header;
 *  - another PHP file declares a `Plugin Name:` header (a template or a file
 *    copied from the WordPress plugin): YOURLS never loads it, and it is how
 *    "the plugin does not appear in the plugin list" reports start;
 *  - the `Version:` header, the `ICC_OIDC_VERSION` constant and
 *    `manifest.json` disagree (a release stamped in only some files);
 *  - the minimum PHP version drifts between the `Requires PHP:` header,
 *    `ICC_OIDC_MIN_PHP` and `composer.json`.
 *
 * Usage: php tests/validate-plugin-layout.php [path-to-plugin-root]
 *
 * Exits with 0 when every check passes and 1 otherwise.
 *
 * @package   ICC_OpenID_Client
 * @category  Tests
 * @author    Ivan Carlos
 * @license   MIT
 */

$GLOBALS['icc_layout_checks'] = 0;
$GLOBALS['icc_layout_failures'] = 0;

/**
 * Record one assertion.
 *
 * @param string $label     What is being checked.
 * @param bool   $condition Result.
 * @param string $detail    Extra information printed on failure.
 *
 * @return void
 */
function icc_layout_check($label, $condition, $detail = '')
{
    $GLOBALS['icc_layout_checks']++;

    if ($condition) {
        echo '  ok   ' . $label . PHP_EOL;

        return;
    }

    $GLOBALS['icc_layout_failures']++;
    echo '  FAIL ' . $label . ($detail !== '' ? ' (' . $detail . ')' : '') . PHP_EOL;
}

/**
 * Parse a plugin header the way YOURLS' yourls_get_plugin_data() does.
 *
 * Only the first comment block of the file is read (8 KB), and every
 * "Field: value" line of that block becomes one array entry.
 *
 * @param string $file Absolute path.
 *
 * @return array Field => value, empty when the file has no comment block.
 */
function icc_layout_plugin_data($file)
{
    $data = @file_get_contents($file, false, null, 0, 8192);

    if ($data === false || !preg_match('!.*?/\*(.*?)\*/!ms', $data, $matches)) {
        return array();
    }

    $plugin_data = array();

    foreach (preg_split("[\n|\r]", $matches[1]) as $line) {
        if (!preg_match('!(\s*)?\*?(\s*)?(.*?):\s+(.*)!', $line, $parts)) {
            continue;
        }

        $field = trim($parts[3]);

        if ($field === '') {
            continue;
        }

        $plugin_data[$field] = trim($parts[4]);
    }

    return $plugin_data;
}

/**
 * List every PHP file of the tree, relative to its root.
 *
 * `.git`, `vendor` and `node_modules` are not part of the packaged tree.
 *
 * @param string $root Absolute path.
 *
 * @return array Sorted relative paths.
 */
function icc_layout_php_files($root)
{
    $prefix = rtrim($root, '/') . '/';
    $files = array();

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
            continue;
        }

        $relative = str_replace($prefix, '', $file->getPathname());

        if (preg_match('!^(\.git|vendor|node_modules)/!', $relative)) {
            continue;
        }

        $files[] = $relative;
    }

    sort($files);

    return $files;
}

/**
 * Read a `define( 'NAME', 'value' );` string constant from a PHP file.
 *
 * @param string $source File contents.
 * @param string $name   Constant name.
 *
 * @return string Value, empty when the constant is not defined.
 */
function icc_layout_constant($source, $name)
{
    $pattern = "/define\\(\\s*'" . preg_quote($name, '/') . "'\\s*,\\s*'([^']*)'\\s*\\)/";

    return preg_match($pattern, $source, $matches) ? $matches[1] : '';
}

/**
 * Read and decode a JSON file.
 *
 * @param string $file Absolute path.
 *
 * @return array|null Decoded array, null when the file is missing or invalid.
 */
function icc_layout_json($file)
{
    if (!is_file($file)) {
        return null;
    }

    $decoded = json_decode((string) file_get_contents($file), true);

    return is_array($decoded) ? $decoded : null;
}

$root = realpath(isset($argv[1]) ? $argv[1] : dirname(__DIR__));

echo 'Plugin layout: ' . $root . PHP_EOL;

$main_file = 'plugin.php';
$main_path = $root . '/' . $main_file;
$plugin_source = is_file($main_path) ? (string) file_get_contents($main_path) : '';
$header = icc_layout_plugin_data($main_path);

// ---------------------------------------------------------------------------
// 1. YOURLS only loads <folder>/plugin.php with a valid header.
// ---------------------------------------------------------------------------
echo PHP_EOL . '1. main plugin file' . PHP_EOL;

icc_layout_check('plugin.php exists in the plugin root', is_file($main_path));
icc_layout_check(
    'plugin.php declares a Plugin Name header',
    isset($header['Plugin Name']) && $header['Plugin Name'] !== ''
);
icc_layout_check(
    'plugin.php declares a Version header',
    isset($header['Version']) && $header['Version'] !== ''
);

// ---------------------------------------------------------------------------
// 2. No other file may look like a plugin to YOURLS or to a reader.
// ---------------------------------------------------------------------------
echo PHP_EOL . '2. stray plugin headers' . PHP_EOL;

$stray = array();

foreach (icc_layout_php_files($root) as $relative) {
    if ($relative === $main_file) {
        continue;
    }

    $data = icc_layout_plugin_data($root . '/' . $relative);

    if (isset($data['Plugin Name'])) {
        $stray[] = $relative;
    }
}

icc_layout_check(
    'no other PHP file declares a Plugin Name header',
    $stray === array(),
    implode(', ', $stray)
);

// ---------------------------------------------------------------------------
// 3. One release version: header, constant and manifest.json.
// ---------------------------------------------------------------------------
echo PHP_EOL . '3. release version' . PHP_EOL;

$header_version = isset($header['Version']) ? $header['Version'] : '';
$define_version = icc_layout_constant($plugin_source, 'ICC_OIDC_VERSION');
$manifest = icc_layout_json($root . '/manifest.json');
$manifest_version = isset($manifest['version']) ? (string) $manifest['version'] : '';

icc_layout_check('ICC_OIDC_VERSION is defined in plugin.php', $define_version !== '');
icc_layout_check(
    'the Version header matches ICC_OIDC_VERSION',
    $define_version !== '' && $define_version === $header_version,
    'header ' . $header_version . ', constant ' . $define_version
);
icc_layout_check('manifest.json is valid JSON', $manifest !== null);
icc_layout_check(
    'the Version header matches manifest.json',
    $manifest_version !== '' && $manifest_version === $header_version,
    'header ' . $header_version . ', manifest ' . ($manifest_version !== '' ? $manifest_version : '<missing>')
);

// ---------------------------------------------------------------------------
// 4. One minimum PHP version: header, constant and composer.json.
// ---------------------------------------------------------------------------
echo PHP_EOL . '4. minimum PHP version' . PHP_EOL;

$min_php = icc_layout_constant($plugin_source, 'ICC_OIDC_MIN_PHP');
$requires_php = isset($header['Requires PHP']) ? $header['Requires PHP'] : '';
$composer = icc_layout_json($root . '/composer.json');
$composer_php = isset($composer['require']['php']) ? (string) $composer['require']['php'] : '';

icc_layout_check('ICC_OIDC_MIN_PHP is defined in plugin.php', $min_php !== '');
icc_layout_check(
    'the Requires PHP header matches ICC_OIDC_MIN_PHP',
    $min_php !== '' && $requires_php === $min_php,
    'header ' . ($requires_php !== '' ? $requires_php : '<missing>') . ', constant ' . $min_php
);
icc_layout_check('composer.json is valid JSON', $composer !== null);
icc_layout_check(
    'composer.json requires the same minimum PHP version',
    $min_php !== '' && str_replace(' ', '', $composer_php) === '>=' . $min_php,
    'composer ' . ($composer_php !== '' ? $composer_php : '<missing>') . ', constant ' . $min_php
);

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------
$failures = $GLOBALS['icc_layout_failures'];
$checks = $GLOBALS['icc_layout_checks'];

echo PHP_EOL . sprintf('%d checks, %d failure(s)', $checks, $failures) . PHP_EOL;

exit($failures === 0 ? 0 : 1);

