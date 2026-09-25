<?php

/**
 * Security Pack — global (NOT namespaced) helper functions for the plain-
 * PHP templates/admin/*.tpl files.
 *
 * DELIBERATELY has no `namespace` declaration. These are called bare (e.g.
 * `security_pack_e($x)`, not `\security_pack_e($x)` or a class-qualified
 * call) from every templates/admin/*.tpl file, and those template files are
 * themselves plain, un-namespaced PHP — an unqualified function call inside
 * them resolves against the GLOBAL namespace at compile time. A prior
 * version of this pair lived inside TemplateRenderer.php's own file, which
 * declares `namespace WHMCS\Module\Addon\Security_Pack\Admin;` — PHP
 * namespaces a function by the declaring FILE's namespace regardless of
 * which `if` block it's nested in, so those definitions actually created
 * `WHMCS\Module\Addon\Security_Pack\Admin\security_pack_e()`, not a global
 * one. Every template's bare `security_pack_e(...)` call then resolved to
 * nothing, fatal-erroring with "Call to undefined function security_pack_e()"
 * the moment ANY template rendered — caught by re-running the standalone
 * render smoke test against the real component templates (not just
 * TemplateRenderer's own class methods), during the Phase 3.2 gate
 * investigation. This file is the fix: define these two helpers in a file
 * with no namespace, so they land where the templates actually look for
 * them. Required once from TemplateRenderer.php.
 */

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

if(!function_exists("security_pack_e")) {
    /** Global escape helper available inside every templates/admin/*.tpl file (they're plain PHP, included in a narrow closure scope with no automatic access to the TemplateRenderer class). */
    function security_pack_e($value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
    }
}

if(!function_exists("security_pack_render_component")) {
    /** Convenience wrapper so a template can render a nested component without a fully-qualified class reference. */
    function security_pack_render_component(string $name, array $data = []): string
    {
        return \WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer::component($name, $data);
    }
}
