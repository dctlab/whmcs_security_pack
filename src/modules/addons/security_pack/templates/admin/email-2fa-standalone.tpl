<?php
/**
 * PHASE 3.8 — the standalone branch of Email2faController::renderContent(true).
 * Currently UNREACHABLE via normal navigation — index() always redirects
 * a GET on c=email2fa to c=twoFactor (see Email2faController::index()),
 * so nothing routes here today. Preserved, migrated, and kept correct
 * anyway per this controller's own docblock ("kept only so this method
 * still behaves correctly if ever called directly").
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   array $overview          see components/email-2fa-overview.tpl
 *   array $bypasses          {token, rows:[{id,userId,userType,scope,expiresAt,createdBy,reason}]}
 *   array $userTypeOptions   type => label
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$overview = $overview ?? [];
$bypasses = $bypasses ?? ["token" => "", "rows" => []];
$userTypeOptions = $userTypeOptions ?? [];
?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<p class="text-muted">Email Two-Factor Authentication is a native WHMCS Two-Factor Authentication method. To turn it on, and to configure code length/validity/attempts/resend limits and the same-IP bypass, go to <strong>Setup &gt; Security &gt; Two-Factor Authentication</strong> and Activate "Email Verification" — users and administrators then enable it individually on their own account from their Security Settings page, the same way as any other WHMCS 2FA method. This page shows enrollment status and lets you grant/revoke administrator manual bypasses, which have no equivalent on WHMCS's native screen.</p>

<?php echo security_pack_render_component("email-2fa-overview", ["overview" => $overview]); ?>

<div class="sp-card">
    <h3 class="sp-card-title">Administrator Manual Bypass</h3>
    <form method="post" action="?module=security_pack&amp;c=email2fa&amp;a=bypass" class="form-inline" onsubmit="return confirm('Bypass Email 2FA for this user for the given number of days?')">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($bypasses["token"]); ?>">
        <div class="form-group"><label>User Type</label> <select name="user_type" class="form-control">
            <?php foreach ($userTypeOptions as $type => $label): ?>
                <option value="<?php echo security_pack_e($type); ?>"><?php echo security_pack_e($label); ?></option>
            <?php endforeach; ?>
        </select></div>
        <div class="form-group"><label>WHMCS User ID</label> <input type="number" min="1" name="user_id" class="form-control" style="width:120px;" required></div>
        <div class="form-group"><label>Duration (days)</label> <input type="number" min="1" max="90" value="7" name="days" class="form-control" style="width:90px;"></div>
        <div class="form-group"><label>Reason (optional)</label> <input type="text" name="reason" maxlength="255" class="form-control"></div>
        <button type="submit" class="btn btn-warning">Confirm Bypass</button>
    </form>

    <table class="table table-condensed" style="margin-top:16px;">
        <thead><tr><th>User</th><th>Type</th><th>Scope</th><th>Expires</th><th>Created By</th><th>Reason</th><th></th></tr></thead>
        <tbody>
        <?php if(!$bypasses["rows"]): ?>
            <tr><td colspan="7"><?php echo security_pack_render_component("empty-state", ["message" => "No active bypasses."]); ?></td></tr>
        <?php endif; ?>
        <?php foreach ($bypasses["rows"] as $row): ?>
            <tr>
                <td>#<?php echo (int) $row["userId"]; ?></td>
                <td><?php echo security_pack_e($row["userType"]); ?></td>
                <td><?php echo security_pack_e($row["scope"]); ?></td>
                <td><?php echo security_pack_e($row["expiresAt"]); ?></td>
                <td><?php echo security_pack_e($row["createdBy"]); ?></td>
                <td><?php echo security_pack_e($row["reason"]); ?></td>
                <td>
                    <form method="post" action="?module=security_pack&amp;c=email2fa&amp;a=revoke" style="display:inline;">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($bypasses["token"]); ?>">
                        <input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-danger btn-xs">Revoke</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
