<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — Phase 3.1 admin presentation layer.
 *
 * ARCHITECTURE NOTE (read before extending): the Phase 3 spec's target
 * template tree uses the `.tpl` extension, which in WHMCS normally implies
 * Smarty. This module's admin side has never had a Smarty rendering path —
 * confirmed by inspecting the full admin dispatch chain
 * (`security_pack_output()` in security_pack.php -> NNM_Page_Builder::
 * header()/footer() in core/pagebuilder.php -> each Admin\*Controller's
 * index()): every one of them builds HTML via raw `echo`/string
 * concatenation and WHMCS's own addon `_output()` contract just captures
 * that output. The only Smarty `.tpl` files that exist anywhere in this
 * module (`templates/settings.tpl`, `templates/security_center.tpl`,
 * `templates/logs.tpl`) are CLIENT-AREA templates spliced into the active
 * theme via `{include file="modules/addons/security_pack/templates/
 * settings.tpl"}` during activation — a completely different mechanism,
 * for client-area theme integration, not admin rendering.
 *
 * Whether WHMCS exposes a safe, supported way for an addon admin
 * controller to obtain and `fetch()` a real Smarty instance is UNVERIFIED
 * against this specific WHMCS version, and gambling on it in a live
 * production admin panel is not an acceptable risk for a presentation-
 * layer refactor. Instead, this renderer is a small, dependency-free
 * PHP-include template engine: `.tpl` files under `templates/admin/` are
 * plain PHP (escaped output via `$this->e()`/`e()`), rendered with
 * `extract()` + `include` inside an output buffer. This satisfies the
 * spec's actual architectural goal — controllers prepare a data array,
 * templates render it, no more giant inline `echo` blocks in controllers —
 * without introducing an unverified runtime dependency. If a real Smarty
 * integration is confirmed safe on this install later, these same `.tpl`
 * files can be ported to Smarty syntax without changing the controller
 * contract (`render($template, $data): string`).
 */
class TemplateRenderer
{
    private static string $baseDir = __DIR__ . "/../../templates/admin";

    /**
     * Renders one template file with the given data array and returns the
     * resulting HTML as a string (never echoes directly — callers decide
     * when/whether to output it, keeping this testable).
     *
     * @param string $template Relative path under templates/admin/, e.g. "dashboard" or "components/stat-card"
     * @param array $data Associative array — each key becomes a variable inside the template
     */
    public static function render(string $template, array $data = []): string
    {
        $path = self::$baseDir . "/" . ltrim($template, "/") . ".tpl";
        if(!is_file($path)) {
            return "<!-- security_pack template not found: " . self::e($template) . " -->";
        }
        $renderer = static function (string $__path, array $__data) {
            extract($__data, EXTR_SKIP);
            ob_start();
            include $__path;
            return ob_get_clean();
        };
        return (string) $renderer($path, $data);
    }

    /** Renders a component template — identical to render(), just a semantic alias for templates/admin/components/*.tpl callers. */
    public static function component(string $name, array $data = []): string
    {
        return self::render("components/" . $name, $data);
    }

    public static function e($value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
    }

    /**
     * Phase 3.3: factored out of DashboardController's own (untouched,
     * already-validated) private assetTags() method so Alerts/Activity can
     * load the identical DCTLAB CSS layer without a third near-duplicate
     * copy of this logic. Same absolute-URL resolution
     * (security_pack_2fa_asset_base_url()) DashboardController already
     * relies on — see that method's own docblock for why a relative "../"
     * URL isn't safe here. DashboardController itself is left as-is
     * (working, live-validated code — not touched by this addition).
     */
    public static function assetTags(): string
    {
        $base = function_exists("security_pack_2fa_asset_base_url") ? security_pack_2fa_asset_base_url() : "";
        $cssBase = $base . "/modules/addons/security_pack/assets/css/";
        $version = defined("SECURITY_PACK_VERSION") ? SECURITY_PACK_VERSION : "3.2";
        $files = ["security-pack.css", "components.css", "responsive.css"];
        $html = "";
        foreach ($files as $file) {
            $html .= '<link rel="stylesheet" href="' . self::e($cssBase . $file . "?v=" . rawurlencode((string) $version)) . '">';
        }
        return $html;
    }
}

// BUGFIX (Phase 3.2 gate investigation, 2026-08-24): the global template
// helpers (security_pack_e(), security_pack_render_component()) used to be
// declared here, but this file is `namespace WHMCS\Module\Addon\Security_Pack\Admin;`
// — a function declared anywhere in a semicolon-form-namespaced file is
// namespaced too, regardless of `if` nesting, so they were never actually
// reachable as bare global calls from templates/admin/*.tpl (which are
// plain, un-namespaced PHP and resolve unqualified calls against the
// global namespace). Every template calls these bare, so every render
// fatal-errored with "Call to undefined function security_pack_e()". Moved
// to a separate, deliberately un-namespaced file — see its own docblock.
require_once __DIR__ . "/template_functions.php";
