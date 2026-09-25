<?php
/**
 * Phase 3.6A — per-row Enable/Disable + Delete actions for one IP
 * Restriction rule. Genuinely reused once per row in ip-restrictions.tpl's
 * rules table (IpRestrictionsController::renderList() built this same
 * pair of inline forms once per row before this migration).
 *
 * Preserves exactly: two separate POST forms (never merged — Enable/
 * Disable and Delete are two distinct backend actions/endpoints), the
 * same hidden security_pack_token + id fields, the same native
 * confirm() dialog text on Delete (no new confirmation mechanism — see
 * ip-restrictions.tpl's own docblock for why this stayed a native
 * confirm() rather than a custom modal).
 *
 * Expected variables:
 *   string $token
 *   int $id
 *   bool $enabled
 *   string $target        used only in the Delete confirm() text, same as the original
 *   string $baseHref      e.g. "?module=security_pack&amp;c=ipRestrictions&amp;a="
 */
$token = $token ?? "";
$id = $id ?? 0;
$enabled = !empty($enabled);
$target = $target ?? "";
$baseHref = $baseHref ?? "";
$toggleAction = $enabled ? "disable" : "enable";
$toggleLabel = $enabled ? "Disable" : "Enable";
// Same construction as the pre-migration controller: the target is
// HTML-escaped (never JS-escaped separately) before being placed inside
// the single-quoted confirm() string, which itself sits inside a
// double-quoted HTML attribute — identical to the original markup.
// Safe in practice because $target only ever reaches here after
// IpRestrictionService::normalizeTarget()/IpUtil::isValidEntry()
// validation, so it can never contain a quote or HTML-special character.
?>
<form method="post" action="<?php echo $baseHref . $toggleAction; ?>" style="display:inline;margin:0;">
    <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
    <input type="hidden" name="id" value="<?php echo (int) $id; ?>">
    <button type="submit" class="btn btn-default btn-sm"><?php echo security_pack_e($toggleLabel); ?></button>
</form>
<form method="post" action="<?php echo $baseHref . "delete"; ?>" style="display:inline;margin:0;" onsubmit="return confirm('Delete this IP restriction rule? <?php echo security_pack_e($target); ?> — this cannot be undone.')">
    <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
    <input type="hidden" name="id" value="<?php echo (int) $id; ?>">
    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
</form>
