<?php
/**
 * Security Pack — templated navigation renderer (Phase 3.1 deliverable).
 *
 * Consumes the SAME $menu / $menuGroups data NNM_Page_Builder already
 * builds in security_pack.php (identical array shape:
 * menu[label] = ["href","address","istab","external"],
 * menuGroups[groupLabel] = [menu keys...]) — this is a templated
 * *rendering* of that existing data, not a second source of truth, and it
 * does not change routing/hrefs/addresses at all.
 *
 * WIRED IN (navigation-wiring phase, 2026-08-24): NNM_Page_Builder::menu()
 * (core/pagebuilder.php) now renders this template for the nav item list —
 * see that method for the surrounding navbar-brand/collapse/Help markup,
 * which is unchanged. menulistFlat()/menulistGrouped() are left in the
 * class body (dead code, intentionally not deleted) so the exact previous
 * behaviour is easy to diff against or revert to if a live-validation
 * issue turns up. The "navbar-left" class on the root <ul> below was added
 * during wiring specifically to preserve the original Bootstrap
 * float-left layout that the previous inline <ul class="nav navbar-nav
 * navbar-left"> wrapper provided.
 *
 * 3.2.0 nav reorder: previously this template rendered ALL dropdown
 * groups first (in $menuGroups order), then ALL ungrouped top-level
 * items (in $menu order) — dropdowns could never be interleaved with
 * top-level items. That made the requested exact top-level order
 * (Overview, Two-Factor Authentication, Protection▼, Activity▼, Login
 * History, Language & Currency, System▼, Settings) unrenderable, since
 * it alternates between ungrouped items and dropdowns. Fixed by doing a
 * SINGLE pass over $menu in its insertion order: an ungrouped item
 * renders where it sits; a grouped item renders its whole dropdown
 * (built from $menuGroups[thatGroup], same sub-item order as before) at
 * the position of that group's FIRST member in $menu, and any later
 * member of an already-rendered group is skipped. This is still driven
 * entirely by $menu/$menuGroups insertion order from security_pack.php
 * — no routing/href/address/permission/content logic changed, purely
 * where each item/dropdown appears in the list.
 *
 * Expected variables:
 *   array $menu        ["Label" => ["href" => "c=...", "address" => "...", "istab" => bool, "external" => bool], ...]
 *   array $menuGroups  ["Group Label" => ["Menu Label", ...], ...]
 *   string $modulelink e.g. "security_pack"
 *   string $activeAddress  current $_REQUEST["c"] value (or "" for the default/index page)
 */
$menu = $menu ?? [];
$menuGroups = $menuGroups ?? [];
$modulelink = $modulelink ?? "security_pack";
$activeAddress = $activeAddress ?? "";

// Map each grouped menu key => its group label (first group wins if a
// key were ever listed in more than one group — matches the previous
// behaviour's implicit "first assignment sticks" semantics).
$groupOf = [];
foreach ($menuGroups as $groupLabel => $keys) {
    foreach ($keys as $key) {
        if(!isset($groupOf[$key])) {
            $groupOf[$key] = $groupLabel;
        }
    }
}

$renderItem = function (string $label, array $item) use ($modulelink, $activeAddress) {
    $address = $item["address"] ?? "";
    $href = $item["href"] ?? "";
    $isActive = ($address === "" && $activeAddress === "") || ($address !== "" && $address === $activeAddress);
    $url = $href !== ""
        ? "addonmodules.php?module=" . rawurlencode($modulelink) . "&" . $href
        : "addonmodules.php?module=" . rawurlencode($modulelink);
    // Phase 5 UI polish: aria-current="page" is purely additive markup
    // (no class/href/label/routing change) so the active item is
    // conveyed to assistive tech too, not just via the CSS active
    // state — same $isActive value already used for the "active" class,
    // nothing new computed.
    return '<li class="' . ($isActive ? "active" : "") . '"><a href="' . security_pack_e($url) . '"' . ($isActive ? ' aria-current="page"' : '') . '>' . security_pack_e($label) . '</a></li>';
};
$renderGroup = function (string $groupLabel) use ($menu, $menuGroups, $activeAddress, $renderItem) {
    $items = [];
    $groupActive = false;
    foreach ($menuGroups[$groupLabel] as $key) {
        if(!isset($menu[$key])) {
            continue;
        }
        $items[$key] = $menu[$key];
        $address = $menu[$key]["address"] ?? "";
        if(($address === "" && $activeAddress === "") || ($address !== "" && $address === $activeAddress)) {
            $groupActive = true;
        }
    }
    if(!$items) {
        return "";
    }
    if(count($items) === 1) {
        $onlyLabel = array_key_first($items);
        return $renderItem($onlyLabel, $items[$onlyLabel]);
    }
    $html = '<li class="dropdown' . ($groupActive ? " active" : "") . '">'
        . '<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false"' . ($groupActive ? ' aria-current="true"' : '') . '>'
        . security_pack_e($groupLabel) . ' <span class="caret"></span></a><ul class="dropdown-menu">';
    foreach ($items as $label => $item) {
        $html .= $renderItem($label, $item);
    }
    $html .= '</ul></li>';
    return $html;
};

$renderedGroups = [];
?>
<ul class="sp-navigation nav navbar-nav navbar-left">
    <?php foreach ($menu as $label => $item):
        if(isset($groupOf[$label])):
            $groupLabel = $groupOf[$label];
            if(isset($renderedGroups[$groupLabel])) {
                continue;
            }
            $renderedGroups[$groupLabel] = true;
            echo $renderGroup($groupLabel);
        else:
            echo $renderItem($label, $item);
        endif;
    endforeach; ?>
</ul>
