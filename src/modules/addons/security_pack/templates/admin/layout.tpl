<?php
/**
 * Security Pack — shared admin page shell (Phase 3.1).
 *
 * Plain-PHP template (see TemplateRenderer.php's docblock for why). Renders
 * ONLY the content area inside NNM_Page_Builder::header()/footer()'s
 * existing panel/navbar wrapper — it deliberately does NOT touch the outer
 * navbar or panel chrome, so every other controller's page keeps rendering
 * exactly as it always has while this is rolled out incrementally.
 *
 * Expected variables (all optional except $content):
 *   string $pageTitle
 *   string $pageDescription
 *   string $pageActionsHtml   pre-rendered HTML for buttons in the header (e.g. "Refresh")
 *   string $notificationsHtml pre-rendered HTML for a notice/alert banner
 *   string $content           pre-rendered HTML for the main content area
 */
$pageTitle = $pageTitle ?? "";
$pageDescription = $pageDescription ?? "";
$pageActionsHtml = $pageActionsHtml ?? "";
$notificationsHtml = $notificationsHtml ?? "";
$content = $content ?? "";
?>
<div class="sp-page">
    <?php if($pageTitle !== "" || $pageActionsHtml !== ""): ?>
    <div class="sp-header">
        <div class="sp-header-text">
            <?php if($pageTitle !== ""): ?><h2 class="sp-header-title"><?php echo security_pack_e($pageTitle); ?></h2><?php endif; ?>
            <?php if($pageDescription !== ""): ?><p class="sp-header-desc"><?php echo security_pack_e($pageDescription); ?></p><?php endif; ?>
        </div>
        <?php if($pageActionsHtml !== ""): ?>
        <div class="sp-header-actions"><?php echo $pageActionsHtml; ?></div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php if($notificationsHtml !== ""): ?>
    <div class="sp-notifications"><?php echo $notificationsHtml; ?></div>
    <?php endif; ?>

    <div class="sp-content">
        <?php echo $content; ?>
    </div>
</div>
