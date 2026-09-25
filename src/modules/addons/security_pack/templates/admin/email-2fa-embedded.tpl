<?php
/**
 * PHASE 3.8 — the embedded branch of Email2faController::renderContent(false).
 * Called ONLY from TwoFactorController::render() (embedded into the
 * c=twoFactor page) — see that controller's own docblock for the
 * embedding contract this template's caller preserves exactly. Per
 * 3.1.27's fix, this branch NEVER shows a bypass table (TwoFactorController
 * already shows the one, unified, method-agnostic bypass table above
 * this) — only the Overview panel, with copy describing what it still
 * adds (pending/24h-failure counts) that the unified page doesn't track.
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   array $overview   see components/email-2fa-overview.tpl
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$overview = $overview ?? [];
?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<hr style="margin:24px 0;">
<h4>Email 2FA</h4>
<p class="text-muted">Pending-verification and 24-hour failed-verification counts specific to the Email Verification method — the Enrollment Overview and Administrator Manual Bypass panels above already cover active enrollment counts and bypasses for Email/WhatsApp/TOTP together, so they are not repeated here.</p>

<?php echo security_pack_render_component("email-2fa-overview", ["overview" => $overview]); ?>
