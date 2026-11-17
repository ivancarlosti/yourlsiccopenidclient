# Align the YOURLS plugin with the `wordpressiccsupercache` release hardening

## Context

The latest commits of [`ivancarlosti/wordpressiccsupercache`](https://github.com/ivancarlosti/wordpressiccsupercache)
were reviewed (`8aa7f80`, `5705cc5`, `f746d02`, `0108c3e`, `66ebed0`, `98ae344`, `5c81b4a`, `f991c42`) to find
improvements that also apply to this YOURLS plugin:

| Reference change | Applies here? | Why |
| --- | --- | --- |
| `tests/validate-plugin-layout.sh` + run it in `build.yml` / `wordpress-deploy.yml` before zipping (`5705cc5`) | **Yes, adapted** | WordPress scans two directory levels for `Plugin Name:` headers; YOURLS only loads `user/plugins/<folder>/plugin.php` (`yourls_get_plugins()` globs `YOURLS_PLUGINDIR . '/*/plugin.php'`, `yourls_is_a_plugin_file()` requires the `plugin.php` suffix). The equivalent risk is a package with the wrong layout, a second plugin header (dead code copied from the WordPress plugin) or a release version stamped in only some files. |
| Run the guard before the ZIP is created, and document it in `docs/testing.md` (`5705cc5`) | **Yes** | This repository only lints and tests on `push`/`pull_request` (`tests.yml`). A release or a manual dispatch can package a tag that never passed those checks. |
| Declare the PHP requirement in `composer.json` and in the plugin header (`98ae344`, `8aa7f80`) | **Yes** | The plugin already requires PHP 8.2 in `plugin.php`, the README and `tests.yml`, but nothing machine readable declares it and the header has no `Requires PHP:` line. |
| `.gitignore` for local tooling (`66ebed0`) | **Yes** | The repository has none, so `vendor/`, `node_modules/`, logs and editor folders are untracked noise waiting to happen. It must not ignore `docs`, `plans`, `docker` or `.github` (organization standard). |
| `plans/` with Context / Goal / Steps / Risks (`5705cc5`) | **Yes** | Organization standard, and `.dockerignore` already lists `plans`. |
| `fix(dropins)`: move files with `Plugin Name:` out of the scanned levels (`5705cc5`) | **No (already safe)** | `includes/` in this plugin has no plugin header, and YOURLS does not scan sub-folders at all. The guard keeps it that way. |
| `feat(updater)`: forced GitHub update checks (`f746d02`) | **No (out of scope)** | YOURLS has no plugin update API. Shipping an updater is a new feature with its own security surface (token, package verification), not a hardening of the current code. |
| Local page cache, Varnish, image optimizer, drop-ins (`66ebed0`, `0108c3e`) | **No** | Cache backends for WordPress; nothing to port to an OpenID Connect client. |
| Remove `readme.txt` (`8aa7f80`) | **No (already done)** | This repository never had a WordPress.org `readme.txt`. |

## Goal

Make the packaged plugin fail fast in CI, exactly like the WordPress plugin does, and keep the release
version and the PHP requirement in a single, verifiable place:

1. `php tests/validate-plugin-layout.php` proves the tree is loadable by YOURLS and internally consistent.
2. `build.yml` and `yourls-deploy.yml` run lint + the security regression script + the guard **before**
   creating the ZIP.
3. `composer.json` and a `Requires PHP:` header declare the PHP 8.2 minimum that `ICC_OIDC_MIN_PHP` already
   enforces at runtime.
4. `.gitignore` keeps local tooling out of the repository without hiding `docs`, `plans`, `docker` or
   `.github`.

## Steps

1. Add `tests/validate-plugin-layout.php`: fails when `plugin.php` is missing or has no `Plugin Name:` header,
   when any other PHP file declares one, when the `Version:` header, `ICC_OIDC_VERSION` and `manifest.json`
   disagree, or when `Requires PHP:`, `ICC_OIDC_MIN_PHP` and `composer.json` disagree.
2. Run the guard in `tests.yml` (every push / pull request).
3. Run lint + `tests/security-login-flow.php` + the guard in `build.yml` and `yourls-deploy.yml` before the
   ZIP is created (PHP 8.2 via `shivammathur/setup-php`).
4. Add `composer.json` (`"php": ">=8.2"`) and the `Requires PHP: 8.2` plugin header; update the
   `ICC_OIDC_MIN_PHP` comment to name every place the value is kept in sync with.
5. Document both the static checks and how to verify a release ZIP in `docs/testing.md`; mention the guard in
   the README *Testing* section.
6. Add `.gitignore` (no `docs`, `plans`, `docker`, `.github` entries).
7. Keep `plans/` out of the release ZIP (`rsync --exclude='plans'` and the forbidden-path loop in
   `yourls-deploy.yml`); `build.yml` keeps it, because that ZIP doubles as a repository backup.

## Risks

- **Failing a release on a version mismatch.** The guard compares `Version:` with `ICC_OIDC_VERSION` and
  `manifest.json`. `@semantic-release/exec` updates the first two and `yourls-deploy.yml` stamps all three, so
  the happy path is unchanged; a manual bump that forgets one file now fails instead of shipping a plugin that
  reports the wrong version in `/admin/plugins.php`.
- **Adding a header line.** `Requires PHP: 8.2` is parsed by `yourls_get_plugin_data()` as an extra field and
  ignored by the YOURLS UI; the `sed` expressions in `semantic-release.yml` and `yourls-deploy.yml` target
  `Version:` only and are unaffected.
- **`composer.json` inside the ZIP.** It ships with the plugin (the deploy ZIP excludes only development paths).
  It declares no `version` field, so semantic-release does not need to rewrite it and it cannot drift.
- **CI time.** `setup-php` adds a few seconds to `build.yml` and `yourls-deploy.yml`, and only on the steps that
  actually create a package.
- **Guard scope.** It runs on the checked-out tree, not inside the ZIP; the ZIP-level checks (folder name,
  `plugin.php`, stamped version, no development paths) already exist in `yourls-deploy.yml` and stay there.
- **Rebuilding an old tag.** `build.yml` / `yourls-deploy.yml` are dispatched from the default branch but check
  out the requested tag, so packaging a tag older than this change fails the new step with
  `Could not open input file: tests/validate-plugin-layout.php`. That is deliberate: a package built today must
  pass today's checks. Re-release the tag (or backport the script to it) instead of weakening the step.
- **`plans/` in the package.** The folder is tracked, so the release ZIP has to exclude it explicitly; missed,
  it would ship the internal plans to every YOURLS install. The forbidden-path check in `yourls-deploy.yml`
  now covers it.
