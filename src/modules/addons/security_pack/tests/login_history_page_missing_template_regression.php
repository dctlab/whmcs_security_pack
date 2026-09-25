<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 report:
 * "in client area index.php?m=security_pack&page=login_history not
 * working."
 *
 * ROOT CAUSE: `templates/logs.tpl` — the client-area Smarty template
 * ClientController::login_history() returns as its "templatefile" for
 * this exact page — was MISSING entirely from the shipped module, even
 * though the code that builds and returns it, and the exact variable
 * shape it expects, were both still fully present and unmodified. This
 * is the same failure mode ("Smarty template not found" — a blank/
 * broken page for every visitor) that templates/settings.tpl's own
 * RECONSTRUCTED docblock already documents hitting once before, and
 * lib/Admin/TemplateRenderer.php's own architecture-note docblock
 * already explicitly names "templates/logs.tpl" as one of the three
 * client-area .tpl files this module is supposed to ship with — it just
 * didn't exist on disk.
 *
 * FIX: rebuilt templates/logs.tpl from that surviving evidence — the
 * exact "vars" shape ClientController::login_history() returns
 * (logs => [{ip_address,os,browser,date_time}, ...], nnmlang => $lang),
 * and the already-existing (unused until now) lang/english.php keys
 * clearly authored for this exact page (login_history, ip_address, os,
 * browser, date_time). Nothing in ClientController.php or hooks.php was
 * touched — only the missing template file was added.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging new regression tests into tests/run.php.
 * Run on its own:
 *
 *   php tests/login_history_page_missing_template_regression.php
 *
 * No live theme file / live database is available in this CLI runner —
 * source-level checks, same technique used throughout this suite —
 * PLUS a direct behavioral check that renders the template against a
 * minimal Smarty-subset interpreter for the handful of tags it actually
 * uses (since real Smarty isn't available in this environment either).
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function lhpt_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function lhpt_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

// =============================================================================
// 1) The template that was missing now genuinely exists and is non-empty.
// =============================================================================

lhpt_assert(
    "templates/logs.tpl exists (the file whose absence caused this page to fail)",
    is_file($MODULE_DIR . "/templates/logs.tpl"),
    $failures,
    $passed
);
$logsTplSource = lhpt_src("templates/logs.tpl");
lhpt_assert(
    "templates/logs.tpl is non-trivial content, not an empty placeholder",
    strlen($logsTplSource) > 500,
    $failures,
    $passed
);

// =============================================================================
// 2) ClientController::login_history() — the code that returns this
//    template — is completely unmodified: same templatefile resolution
//    (custom-logs override, falling back to logs), same "vars" shape,
//    same gating on client_history + login_history settings.
// =============================================================================

$clientControllerSource = lhpt_src("lib/Client/ClientController.php");
lhpt_assert(
    "ClientController::login_history() still resolves \"templates/logs\" as its templatefile when no custom-logs override exists — unchanged by this fix (only the missing target file was added, not the resolution logic)",
    strpos($clientControllerSource, '"templatefile" => "templates/" . (file_exists(security_pack_module_root . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . "custom-logs") ? "custom-logs" : "logs")') !== false,
    $failures,
    $passed
);
lhpt_assert(
    "ClientController::login_history() still passes exactly [\"logs\" => \$logs, \"nnmlang\" => \$lang] as \"vars\" — the template was built to match this exact shape, not a guessed one",
    strpos($clientControllerSource, '"vars" => ["logs" => $logs, "nnmlang" => $lang]') !== false,
    $failures,
    $passed
);
lhpt_assert(
    "ClientController::login_history() still builds each \$logs row as exactly ip_address/os/browser/date_time — the four columns this template renders",
    strpos($clientControllerSource, '["ip_address" => $item->ip, "os" => security_pack_get_os($item->browser), "browser" => security_pack_get_browser($item->browser), "date_time" => fromMySQLDate($item->logged_at, true)]') !== false,
    $failures,
    $passed
);
lhpt_assert(
    "ClientController::login_history() still requires BOTH \"client_history\" and \"login_history\" settings before showing this page (redirects to clientarea.php otherwise) — unchanged gating, not something this fix touched",
    strpos($clientControllerSource, 'if(!isset($settings["client_history"]) || !isset($settings["login_history"])) {') !== false,
    $failures,
    $passed
);

// =============================================================================
// 3) The reconstructed template renders exactly the fields the
//    controller provides, with every log value escaped (this table
//    displays a client's own IP and User-Agent string — both
//    attacker-influenced input).
// =============================================================================

lhpt_assert(
    "logs.tpl iterates \$logs with a foreach (matches the array ClientController::login_history() actually returns)",
    (bool) preg_match('/\{foreach from=\$logs item=log\}/', $logsTplSource),
    $failures,
    $passed
);
foreach (["ip_address", "os", "browser", "date_time"] as $field) {
    lhpt_assert(
        "logs.tpl renders \$log.$field with |escape — never raw, since this is client-influenced data (IP / User-Agent derived)",
        strpos($logsTplSource, '{$log.' . $field . '|escape}') !== false,
        $failures,
        $passed
    );
}
lhpt_assert(
    "logs.tpl handles the empty-history case (no rows yet) rather than rendering a bare empty table",
    strpos($logsTplSource, '{if $logs|@count}') !== false && strpos($logsTplSource, '{else}') !== false,
    $failures,
    $passed
);

// =============================================================================
// 4) Every label string logs.tpl uses actually exists in lang/english.php
//    — confirms nothing was invented that isn't backed by the surviving,
//    previously-unused language keys.
// =============================================================================

$langSource = lhpt_src("lang/english.php");
$requiredLangKeys = ["ip_address", "os", "browser", "date_time"];
$missingLangKeys = [];
foreach ($requiredLangKeys as $key) {
    if (strpos($langSource, "\$_ADDONLANG['" . $key . "']") === false) {
        $missingLangKeys[] = "lang/english.php missing key: " . $key;
    }
    if (strpos($logsTplSource, "nnmlang." . $key) === false) {
        $missingLangKeys[] = "logs.tpl never references \$nnmlang." . $key;
    }
}
lhpt_assert(
    "every column-header lang key logs.tpl relies on is defined in lang/english.php and actually used — " . (empty($missingLangKeys) ? "clean" : implode("; ", $missingLangKeys)),
    empty($missingLangKeys),
    $failures,
    $passed
);

// =============================================================================
// 5) Behavioral: render the template against a tiny Smarty-subset
//    interpreter covering only the handful of tags this file actually
//    uses ({if}/{else}/{/if}, {foreach}, {$var}, {$var.field|escape},
//    |default) — proves the markup is well-formed and the data flows
//    through correctly, not just that certain substrings exist.
// =============================================================================

function lhpt_render_logs_tpl(string $tplSource, array $vars): string
{
    // Strip the leading Smarty comment block ({* ... *}) and the
    // {literal}...{/literal} CSS block (kept byte-for-byte, no tags to
    // interpret inside it).
    $src = (string) preg_replace('/\{\*.*?\*\}/s', '', $tplSource);
    $src = (string) preg_replace('/\{literal\}(.*?)\{\/literal\}/s', '$1', $src);

    // {if $logs|@count} ... {else} ... {/if}
    $src = (string) preg_replace_callback(
        '/\{if \$logs\|@count\}(.*?)\{else\}(.*?)\{\/if\}/s',
        function ($m) use ($vars) {
            return count($vars["logs"]) > 0 ? $m[1] : $m[2];
        },
        $src
    );

    // {foreach from=$logs item=log} ... {/foreach}
    $src = (string) preg_replace_callback(
        '/\{foreach from=\$logs item=log\}(.*?)\{\/foreach\}/s',
        function ($m) use ($vars) {
            $rowTpl = $m[1];
            $out = "";
            foreach ($vars["logs"] as $log) {
                $row = $rowTpl;
                $row = (string) preg_replace_callback('/\{\$log\.(\w+)\|escape\}/', function ($fm) use ($log) {
                    return htmlspecialchars((string) ($log[$fm[1]] ?? ""), ENT_QUOTES);
                }, $row);
                $out .= $row;
            }
            return $out;
        },
        $src
    );

    // {$nnmlang.key|default:'Fallback'}
    $src = (string) preg_replace_callback('/\{\$nnmlang\.(\w+)\|default:\'([^\']*)\'\}/', function ($m) use ($vars) {
        return $vars["nnmlang"][$m[1]] ?? $m[2];
    }, $src);

    return $src;
}

$rowsCase = lhpt_render_logs_tpl($logsTplSource, [
    "logs" => [
        ["ip_address" => "203.0.113.5", "os" => "Windows 11", "browser" => "Chrome <script>alert(1)</script>", "date_time" => "2026-08-27 10:00:00"],
        ["ip_address" => "198.51.100.9", "os" => "macOS", "browser" => "Safari", "date_time" => "2026-08-26 09:00:00"],
    ],
    "nnmlang" => [],
]);
lhpt_assert(
    "behavioral: with 2 log rows, the rendered output contains both IP addresses",
    strpos($rowsCase, "203.0.113.5") !== false && strpos($rowsCase, "198.51.100.9") !== false,
    $failures,
    $passed
);
lhpt_assert(
    "behavioral: a browser string containing HTML is escaped in the rendered output — no raw <script> tag reaches the page",
    strpos($rowsCase, "<script>alert(1)</script>") === false && strpos($rowsCase, "&lt;script&gt;") !== false,
    $failures,
    $passed
);
lhpt_assert(
    "behavioral: the empty-state branch is NOT shown when there are log rows",
    strpos($rowsCase, "No login history recorded yet.") === false,
    $failures,
    $passed
);

$emptyCase = lhpt_render_logs_tpl($logsTplSource, ["logs" => [], "nnmlang" => []]);
lhpt_assert(
    "behavioral: with zero log rows, the empty-state message renders instead of a bare table",
    strpos($emptyCase, "No login history recorded yet.") !== false,
    $failures,
    $passed
);
lhpt_assert(
    "behavioral: with zero log rows, no stray table markup leaks through from the non-empty branch",
    strpos($emptyCase, "<table") === false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Login-history missing-template regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
