<?php
/**
 * PHASE 3.8 — Two-Factor Authentication (Security Center > Authentication
 * > Two-Factor Authentication). Formerly TwoFactorController::render()'s
 * hand-built HTML — see that method's own docblock for exactly what
 * changed (presentation only) and what didn't (every query, every
 * POST/CSRF-protected form target, every redirect).
 *
 * SECURITY-SENSITIVE: this page is entirely READ-ONLY presentation plus
 * forms that POST to this controller's own (untouched) action methods.
 * Every value that can contain admin- or client-entered text (reason
 * fields, device labels, IP/CIDR entries, exemption "Created By" actor
 * strings) is rendered through security_pack_e(). $bypasses.rows[].methodLabelHtml
 * is the ONE deliberate exception — it is pre-escaped HTML returned by
 * TwoFactorController::bypassMethodLabel() (which itself calls
 * $this->e() internally, unchanged since 3.1.16) and must be echoed
 * raw, not re-escaped.
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   array $overviewStats     stat-card view models, see buildOverviewViewModel()
 *   array $reportRows        buildReportRows() output, UNCHANGED shape
 *   array $manageUser        see buildManageUserViewModel()
 *   array $ipExemptions      see buildIpExemptionsViewModel()
 *   array $policy            see buildPolicyViewModel()
 *   array $bypasses          see buildBypassesViewModel()
 *   string $email2faEmbedHtml  pre-rendered HTML captured from Email2faController::renderContent(false) — echoed raw, unmodified
 *   array $userTypeOptions   type => label
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$overviewStats = $overviewStats ?? [];
$reportRows = $reportRows ?? [];
$manageUser = $manageUser ?? ["userId" => 0, "userType" => "client", "lookedUp" => false, "providerRows" => [], "recoveryCodesRemaining" => 0, "trustedBrowsersAvailable" => false, "trustedBrowsers" => [], "trustedBrowserCount" => 0, "activeMethod" => null, "hasDisableableMethod" => false, "token" => ""];
$ipExemptions = $ipExemptions ?? ["token" => "", "globalRows" => [], "userRows" => []];
$policy = $policy ?? ["required" => false, "defaultMethod" => "email", "methodOptions" => [], "token" => ""];
$bypasses = $bypasses ?? ["token" => "", "rows" => []];
$email2faEmbedHtml = $email2faEmbedHtml ?? "";
$userTypeOptions = $userTypeOptions ?? [];
?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<p class="sp-header-desc text-muted" style="margin:-8px 0 14px;">Manage authentication methods, security policy, and administrator controls.</p>
<details class="sp-help-disclosure" style="margin-bottom:16px;">
    <summary>What does this page cover?</summary>
    <p class="sp-help-text">DCTLAB Security Pack offers three Two-Factor Authentication methods, each activated natively on <strong>Setup &gt; Security &gt; Two-Factor Authentication</strong> (Email Verification / DCTLAB WhatsApp / Time-Based Token) — that native screen owns each method's own OTP settings and DCTLAB credentials. This page covers what that screen doesn't: enrollment across all three methods, whether 2FA is required, and the administrator manual bypass (which applies no matter which method a user has enrolled).</p>
</details>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Security Overview</h3>
    <div class="row sp-metric-row">
        <?php foreach ($overviewStats as $stat): ?>
            <div class="col-sm-6 col-md-4 sp-metric-col">
                <?php echo security_pack_render_component("method-status-card", $stat); ?>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Users / 2FA Overview</h3>
    <?php if(!$reportRows): ?>
        <?php echo security_pack_render_component("empty-state", ["message" => "No users have enrolled in (or previously enrolled in) Two-Factor Authentication yet."]); ?>
    <?php else: ?>
        <p class="text-muted small">Every identity with any Two-Factor Authentication history (enrolled, active, or previously active), most recently active first. A required-by-policy identity with no enrollment at all — nothing to show a date for here — is instead flagged on the admin Client Profile &gt; Users tab. Use "Manage a User's Two-Factor Authentication" below to look up any specific User ID, including one with no history yet.</p>
        <div class="table-responsive sp-table-scroll">
        <table class="table table-condensed table-striped sp-table">
            <thead><tr><th>User</th><th>Type</th><th>2FA</th><th>Method</th><th>Activated</th><th>Last Verified</th><th>Trusted Browser</th><th>Trusted IP</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($reportRows as $r): ?>
                <tr>
                    <td><?php echo security_pack_e($r["user_label"]); ?> <span class="text-muted">(#<?php echo (int) $r["user_id"]; ?>)</span></td>
                    <td><?php echo security_pack_e($userTypeOptions[$r["user_type"]] ?? $r["user_type"]); ?></td>
                    <td>
                        <?php echo security_pack_render_component("two-factor-status-badge", ["status" => $r["status"]]); ?>
                        <?php if($r["required_not_enrolled"]): ?><br><span class="text-danger">&#9888; Required &mdash; Not Enrolled</span><?php endif; ?>
                    </td>
                    <td><?php echo security_pack_e($r["method"] !== "" ? $r["method"] : "—"); ?></td>
                    <td><?php echo security_pack_e($r["activated_at"] !== "" ? $r["activated_at"] : "—"); ?></td>
                    <td><?php echo security_pack_e($r["last_verified_at"] !== "" ? $r["last_verified_at"] : "—"); ?></td>
                    <td><span class="sp-badge <?php echo strpos($r["trusted_browser_label"], "Yes") === 0 ? "sp-badge-on" : "sp-badge-off"; ?>"><?php echo security_pack_e($r["trusted_browser_label"]); ?></span></td>
                    <td><?php echo $r["trusted_ip_label"] === "None" ? '<span class="text-muted">None</span>' : '<span class="sp-badge sp-badge-on">' . security_pack_e($r["trusted_ip_label"]) . '</span>'; ?></td>
                    <td><a href="?module=security_pack&amp;c=twoFactor&amp;manage_user_id=<?php echo (int) $r["user_id"]; ?>&amp;manage_user_type=<?php echo security_pack_e($r["user_type"]); ?>#sp-manage-user" class="btn btn-default btn-xs">Manage</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    <?php endif; ?>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Security Policy</h3>
    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=save">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($policy["token"]); ?>">
        <div class="sp-policy-control">
            <div class="checkbox"><label><input type="checkbox" name="twofactor_require" value="1" <?php echo $policy["required"] ? "checked" : ""; ?>> Require Two-Factor Authentication</label></div>
            <p class="text-muted small" style="margin:6px 0 0;">Default: off — enabling this does not retroactively lock out users who have not yet enrolled; it flags a &#9888; "Required — Not Enrolled" badge in place of "N/A" on the admin Client Profile &gt; Users tab for every account that has not enrolled in a method yet, and is intended to pair with your own account-onboarding process.</p>
        </div>
        <div class="sp-policy-control">
            <div class="form-group" style="margin-bottom:0;"><label>Default Authentication Method</label> <select name="twofactor_default_method" class="form-control" style="width:250px;display:inline-block;">
                <?php foreach ($policy["methodOptions"] as $key => $label): ?>
                    <option value="<?php echo security_pack_e($key); ?>" <?php echo $policy["defaultMethod"] === $key ? "selected" : ""; ?>><?php echo security_pack_e($label); ?></option>
                <?php endforeach; ?>
            </select></div>
        </div>
        <button type="submit" class="btn btn-primary">Save Changes</button>
    </form>
</div>

<div class="sp-card" id="sp-manage-user" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Manage a User's Two-Factor Authentication</h3>
    <p class="text-muted small">Look up any WHMCS User's current 2FA status and, if enrolled, disable it on their behalf (e.g. they lost their device and cannot complete the challenge themselves).</p>
    <form method="get" action="addonmodules.php" class="form-inline" style="margin-bottom:16px;">
        <input type="hidden" name="module" value="security_pack"><input type="hidden" name="c" value="twoFactor">
        <div class="form-group"><label>User Type</label> <select name="manage_user_type" class="form-control">
            <?php foreach ($userTypeOptions as $type => $label): ?>
                <option value="<?php echo security_pack_e($type); ?>" <?php echo $manageUser["userType"] === $type ? "selected" : ""; ?>><?php echo security_pack_e($label); ?></option>
            <?php endforeach; ?>
        </select></div>
        <div class="form-group"><label>WHMCS User ID</label> <input type="number" min="1" name="manage_user_id" class="form-control" style="width:120px;" value="<?php echo $manageUser["userId"] > 0 ? (int) $manageUser["userId"] : ""; ?>" required></div>
        <button type="submit" class="btn btn-default">Look Up</button>
    </form>

    <?php if($manageUser["lookedUp"]): ?>
        <h5 style="margin-top:0;">Authentication Status</h5>
        <div class="sp-method-lookup-grid">
            <?php foreach ($manageUser["providerRows"] as $p): ?>
                <?php echo security_pack_render_component("method-lookup-card", $p); ?>
            <?php endforeach; ?>
        </div>

        <div class="sp-inline-stats">
            <span class="sp-inline-stat"><strong><?php echo (int) $manageUser["recoveryCodesRemaining"]; ?></strong> recovery codes remaining</span>
            <?php if($manageUser["trustedBrowsersAvailable"]): ?>
                <span class="sp-inline-stat"><strong><?php echo (int) $manageUser["trustedBrowserCount"]; ?></strong> trusted browser<?php echo (int) $manageUser["trustedBrowserCount"] === 1 ? "" : "s"; ?></span>
            <?php endif; ?>
        </div>

        <?php if($manageUser["trustedBrowsersAvailable"] && $manageUser["trustedBrowserCount"] > 0): ?>
            <div class="table-responsive sp-table-scroll">
            <table class="table table-condensed sp-table">
                <thead><tr><th>Device</th><th>Created</th><th>Last Used</th><th>Expires</th></tr></thead>
                <tbody>
                <?php foreach ($manageUser["trustedBrowsers"] as $tb): ?>
                    <tr>
                        <td><?php echo security_pack_e($tb["deviceLabel"]); ?></td>
                        <td><?php echo security_pack_e($tb["createdAt"]); ?></td>
                        <td><?php echo security_pack_e($tb["lastUsedAt"]); ?></td>
                        <td><?php echo security_pack_e($tb["expiresAt"]); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=revokeTrustedBrowsers" onsubmit="return confirm('Revoke all trusted browsers for this user? They will need to complete a full 2FA challenge on their next login.')" style="margin-bottom:16px;">
                <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($manageUser["token"]); ?>">
                <input type="hidden" name="user_id" value="<?php echo (int) $manageUser["userId"]; ?>">
                <input type="hidden" name="user_type" value="<?php echo security_pack_e($manageUser["userType"]); ?>">
                <button type="submit" class="btn btn-default">Revoke All Trusted Browsers For This User</button>
            </form>
        <?php endif; ?>

        <?php if($manageUser["hasDisableableMethod"]): ?>
            <div class="sp-danger-zone">
                <p class="sp-danger-zone-title">Danger Zone</p>
                <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=disableUser" onsubmit="return confirm('Disable Two-Factor Authentication for this user? Their enrollment is preserved (same as any other disable) but they will need to re-verify to turn it back on.')">
                    <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($manageUser["token"]); ?>">
                    <input type="hidden" name="user_id" value="<?php echo (int) $manageUser["userId"]; ?>">
                    <input type="hidden" name="user_type" value="<?php echo security_pack_e($manageUser["userType"]); ?>">
                    <button type="submit" class="btn btn-danger">Disable Two-Factor Authentication for This User</button>
                </form>
            </div>
        <?php else: ?>
            <p class="text-muted">This user has no active or pending Two-Factor Authentication method to disable.</p>
        <?php endif; ?>
    <?php endif; ?>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">2FA IP Exemptions</h3>
    <p class="text-muted small">Skips the 2FA challenge entirely for logins from a matching IP — separate from the general IP Restrictions feature (which controls whether a request reaches WHMCS at all). A global entry applies to every account; a per-user entry applies ONLY to the exact User ID + Type given, and is never inherited by another identity.</p>

    <h5>Company-Wide (Global)</h5>
    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=addIpExemption" class="form-inline" style="margin-bottom:10px;">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($ipExemptions["token"]); ?>">
        <input type="hidden" name="scope" value="global">
        <div class="form-group"><label>IP or CIDR</label> <input type="text" name="entry" class="form-control" placeholder="203.0.113.5 or 203.0.113.0/24" required></div>
        <div class="form-group"><label>Reason</label> <input type="text" name="reason" maxlength="255" class="form-control"></div>
        <button type="submit" class="btn btn-default">Add Company-Wide Exemption</button>
    </form>
    <div class="table-responsive sp-table-scroll">
    <table class="table table-condensed sp-table">
        <thead><tr><th>Entry</th><th>Reason</th><th>Created By</th><th>Created</th><th></th></tr></thead>
        <tbody>
        <?php if(!$ipExemptions["globalRows"]): ?>
            <tr><td colspan="5" class="text-muted">No company-wide exemptions.</td></tr>
        <?php endif; ?>
        <?php foreach ($ipExemptions["globalRows"] as $row): ?>
            <tr>
                <td><code><?php echo security_pack_e($row["entry"]); ?></code></td>
                <td><?php echo security_pack_e($row["reason"]); ?></td>
                <td><?php echo security_pack_e($row["createdBy"]); ?></td>
                <td><?php echo security_pack_e($row["createdAt"]); ?></td>
                <td>
                    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=removeIpExemption" style="display:inline;">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($ipExemptions["token"]); ?>">
                        <input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-danger btn-xs">Remove</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>

    <h5 style="margin-top:20px;">Per-User</h5>
    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=addIpExemption" class="form-inline" style="margin-bottom:10px;">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($ipExemptions["token"]); ?>">
        <input type="hidden" name="scope" value="user">
        <div class="form-group"><label>User Type</label> <select name="user_type" class="form-control">
            <?php foreach ($userTypeOptions as $type => $label): ?>
                <option value="<?php echo security_pack_e($type); ?>"><?php echo security_pack_e($label); ?></option>
            <?php endforeach; ?>
        </select></div>
        <div class="form-group"><label>WHMCS User ID</label> <input type="number" min="1" name="user_id" class="form-control" style="width:120px;" required></div>
        <div class="form-group"><label>IP or CIDR</label> <input type="text" name="entry" class="form-control" placeholder="203.0.113.5 or 203.0.113.0/24" required></div>
        <div class="form-group"><label>Reason</label> <input type="text" name="reason" maxlength="255" class="form-control"></div>
        <button type="submit" class="btn btn-default">Add Exemption For This User</button>
    </form>
    <div class="table-responsive sp-table-scroll">
    <table class="table table-condensed sp-table">
        <thead><tr><th>User</th><th>Type</th><th>Entry</th><th>Reason</th><th>Created By</th><th></th></tr></thead>
        <tbody>
        <?php if(!$ipExemptions["userRows"]): ?>
            <tr><td colspan="6" class="text-muted">No per-user exemptions.</td></tr>
        <?php endif; ?>
        <?php foreach ($ipExemptions["userRows"] as $row): ?>
            <tr>
                <td>#<?php echo (int) $row["userId"]; ?></td>
                <td><?php echo security_pack_e($row["userType"]); ?></td>
                <td><code><?php echo security_pack_e($row["entry"]); ?></code></td>
                <td><?php echo security_pack_e($row["reason"]); ?></td>
                <td><?php echo security_pack_e($row["createdBy"]); ?></td>
                <td>
                    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=removeIpExemption" style="display:inline;">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($ipExemptions["token"]); ?>">
                        <input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-danger btn-xs">Remove</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Administrator Manual Bypass</h3>
    <p class="text-muted small">Applies regardless of which method (Email/WhatsApp/TOTP) the user has enrolled — one bypass system, not one per method.</p>
    <p class="text-muted small"><strong>This must be the WHMCS <em>User</em> ID, not the Client ID.</strong> A Client can have multiple Users (an owner plus any sub-accounts); each logs in — and is checked for a bypass — as their own User ID, never the Client's. If you're not sure, use "Manage a User's Two-Factor Authentication" above first to confirm the exact User ID.</p>
    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=bypass" class="form-inline" onsubmit="return confirm('Bypass 2FA for this user for the given number of days?')">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($bypasses["token"]); ?>">
        <div class="form-group"><label>User Type</label> <select name="user_type" class="form-control">
            <?php foreach ($userTypeOptions as $type => $label): ?>
                <option value="<?php echo security_pack_e($type); ?>"><?php echo security_pack_e($label); ?></option>
            <?php endforeach; ?>
        </select></div>
        <div class="form-group"><label>WHMCS User ID</label> <input type="number" min="1" name="user_id" class="form-control" style="width:120px;" required></div>
        <div class="form-group"><label>Duration (days)</label> <input type="number" min="1" max="90" value="7" name="days" class="form-control" style="width:90px;"></div>
        <div class="form-group"><label>Reason</label> <input type="text" name="reason" maxlength="255" class="form-control" required></div>
        <button type="submit" class="btn btn-warning">Confirm Bypass</button>
    </form>

    <div class="table-responsive sp-table-scroll" style="margin-top:16px;">
    <table class="table table-condensed sp-table">
        <thead><tr><th>User</th><th>Type</th><th>Scope</th><th>Method</th><th>Expires</th><th>Created By</th><th>Reason</th><th></th></tr></thead>
        <tbody>
        <?php if(!$bypasses["rows"]): ?>
            <tr><td colspan="8" class="text-muted">No active bypasses.</td></tr>
        <?php endif; ?>
        <?php foreach ($bypasses["rows"] as $row): ?>
            <tr>
                <td>#<?php echo (int) $row["userId"]; ?></td>
                <td><?php echo security_pack_e($row["userType"]); ?></td>
                <td><?php echo security_pack_e($row["scope"]); ?></td>
                <td><?php echo $row["methodLabelHtml"]; /* pre-escaped by TwoFactorController::bypassMethodLabel() — echo raw */ ?></td>
                <td><?php echo security_pack_e($row["expiresAt"]); ?></td>
                <td><?php echo security_pack_e($row["createdBy"]); ?></td>
                <td><?php echo security_pack_e($row["reason"]); ?></td>
                <td>
                    <form method="post" action="?module=security_pack&amp;c=twoFactor&amp;a=revoke" style="display:inline;">
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
</div>

<?php echo $email2faEmbedHtml; /* pre-rendered by Email2faController::renderContent(false) via its own templates — echoed raw, unmodified, same embedding position as before this migration */ ?>
