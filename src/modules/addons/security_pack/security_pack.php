<?php

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

function security_pack_config()
{
    return ["name" => "DCTLAB Security Pack", "description" => "Enterprise Security & Authentication for WHMCS — track logins, get alerts, email/WhatsApp/TOTP 2FA, protect accounts, and control access, all in one simple solution.", "version" => "3.1.31", "author" => "<a href='https://dctlab.directcybertech.com/' target='_blank'>DCTLAB</a>", "language" => "english", "fields" => ["nodeletedb" => ["FriendlyName" => "Database Table", "Type" => "yesno", "Size" => "25", "Description" => "Tick this box to delete the tables from the database when deactivating the module."],]];
}

/**
 * Creates every table the module needs if it does not already exist.
 * Idempotent — safe to call from both _activate() (fresh install) and
 * _upgrade() (module was already active when new tables were added, so
 * WHMCS never calls _activate() again on its own).
 */
function security_pack_ensure_tables()
{
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_logins")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_logins", function ($table) {
            $table->increments("id");
            $table->string("client_id")->nullable();
            $table->boolean("is_admin")->default(0);
            $table->string("ip")->nullable();
            $table->text("browser")->nullable();
            $table->dateTime("logged_at");
        });
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_opt")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_opt", function ($table) {
            $table->increments("id");
            $table->string("client_id")->nullable();
            $table->boolean("is_admin")->default(0);
            $table->boolean("allowed")->default(1);
        });
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_dpass")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_dpass", function ($table) {
            $table->increments("id");
            $table->string("user_id")->nullable();
        });
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack", function ($table) {
            $table->increments("id");
            $table->string("setting")->nullable();
            $table->text("value")->nullable();
        });
    }
    if(!Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Login Notification")->count()) {
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->insert(["type" => "general", "name" => "Security Pack - Login Notification", "subject" => "New sign-in from {\$security_pack_browser}", "message" => "<p>Dear {\$client_first_name},</p>\r\n<p>Your account <strong>{\$client_email}</strong> has just been accessed using <strong>{\$security_pack_browser}</strong> on <strong>{\$security_pack_os}</strong>, from the IP address <strong>{\$security_pack_ip}</strong>.</p><p>We're notifying you for security reasons. It's our priority to ensure you're aware of significant activities in your account. We noticed a sign-in from a possibly unfamiliar browser or device. This might occur when you log in for the first time on a new computer, phone, or browser, use incognito/private mode, clear your cookies, or if someone else accesses your account.</p>", "language" => "", "plaintext" => "0", "custom" => "0", "disabled" => "0"]);
    }
    if(!Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Admin Login Notification")->count()) {
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->insert(["type" => "admin", "name" => "Security Pack - Admin Login Notification", "subject" => "New sign-in to admin area from {\$security_pack_browser}", "message" => "<p>Hi {\$firstname},</p><p>Your account <strong>{\$security_pack_email}</strong> has just been accessed using <strong>{\$security_pack_browser}</strong> on <strong>{\$security_pack_os}</strong>, from the IP address <strong>{\$security_pack_ip}</strong>.</p><p>We're notifying you for security reasons. It's our priority to ensure you're aware of significant activities in your account. We noticed a sign-in from a possibly unfamiliar browser or device. This might occur when you log in for the first time on a new computer, phone, or browser, use incognito/private mode, clear your cookies, or if someone else accesses your account.</p>", "language" => "", "plaintext" => "0", "custom" => "0", "disabled" => "0"]);
    }
    if(!Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Admin Two-Factor Authentication")->count()) {
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->insert(["type" => "admin", "name" => "Security Pack - Admin Two-Factor Authentication", "subject" => "Complete Your Account Authorization", "message" => "<div style=\"max-width: 600px; margin: 30px auto; background-color: #fff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); padding: 30px;\">\r\n    <p>Dear {\$firstname},</p>\r\n    <p>Please use the one-time password below to authorize your account:</p>\r\n    <p style=\"font-size: 18px; margin-top: 20px; text-align: center; background-color: #e1e1e1; padding: 15px;\"><strong style=\"color: #333;\">{\$auth_code}</strong></p>\r\n</div>", "custom" => "0"]);
    }
    if(!Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - User Two-Factor Authentication")->count()) {
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->insert(["type" => "user", "name" => "Security Pack - User Two-Factor Authentication", "subject" => "Complete Your Account Authorization", "message" => "<div style=\"max-width: 600px; margin: 30px auto; background-color: #fff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); padding: 30px;\">\r\n    <p>Hello {\$user_first_name},</p>\r\n    <p>Please use the one-time password below to authorize your account:</p>\r\n    <p style=\"font-size: 18px; margin-top: 20px; text-align: center; background-color: #e1e1e1; padding: 15px;\"><strong style=\"color: #333;\">{\$auth_code}</strong></p>\r\n</div>", "custom" => "0"]);
    }
    if(!Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Security Alert Digest")->count()) {
        // Security Pack 2.5 — optional daily digest of open HIGH/CRITICAL
        // security alerts (Settings > Security Intelligence, off by
        // default). Reuses the exact same sendAdminMessage()/email
        // template mechanism as the four templates above — no new
        // notification channel.
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->insert(["type" => "admin", "name" => "Security Pack - Security Alert Digest", "subject" => "DCTLAB Security Pack: {\$security_pack_alert_count} open security alert(s)", "message" => "<p>Hi {\$firstname},</p><p>DCTLAB Security Pack has {\$security_pack_alert_count} open HIGH or CRITICAL security alert(s):</p><pre>{\$security_pack_alert_summary}</pre><p>Review these in the Security Center under Activity &gt; Alerts.</p>", "language" => "", "plaintext" => "0", "custom" => "0", "disabled" => "0"]);
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_ips")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_ips", function ($table) {
            $table->increments("id");
            $table->string("user_id")->nullable();
            $table->string("start_ip")->nullable();
            $table->string("end_ip")->nullable();
        });
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_geo_cache")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_geo_cache", function ($table) {
            $table->increments("id");
            $table->string("ip_hash", 64)->unique();
            $table->string("country_code", 2)->nullable();
            $table->dateTime("expires_at");
            $table->dateTime("updated_at");
            $table->index("expires_at");
        });
    }
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_lc_overrides")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_lc_overrides", function ($table) {
            $table->increments("id");
            $table->string("country_code", 2)->unique();
            $table->string("language", 100)->nullable();
            $table->string("currency", 3)->nullable();
            $table->boolean("enabled")->default(1);
            $table->dateTime("updated_at")->nullable();
        });
    } elseif(!Illuminate\Database\Capsule\Manager::schema()->hasColumn("dctlab_security_pack_lc_overrides", "enabled")) {
        // Table existed from before the "enabled" column was added
        // (v1.2.0) — add it now rather than skip it, since hasTable()
        // above only guards against creating the table from scratch.
        Illuminate\Database\Capsule\Manager::schema()->table("dctlab_security_pack_lc_overrides", function ($table) {
            $table->boolean("enabled")->default(1)->after("currency");
        });
    }

    // --- Security Pack 2.0 additions below: purely additive, nothing
    // above this point is touched, dropped, or renamed. Existing data in
    // every pre-2.0 table (logins, opt-in flags, disabled-password list,
    // IP ranges, GeoIP cache, language/currency overrides) is preserved
    // untouched by upgrading. ---

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_events")) {
        // Centralized security event log (section: "Centralized Security
        // Event System"). Every subsystem — login/account protection, IP
        // security, country restriction, settings changes — records here
        // through security_pack_record_event() instead of each feature
        // rolling its own ad-hoc logging. Never stores secrets/tokens.
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_events", function ($table) {
            $table->increments("id");
            $table->string("event_type", 64)->index();
            $table->string("severity", 16)->default("info")->index();
            $table->text("message")->nullable();
            $table->string("ip", 45)->nullable()->index();
            $table->string("country_code", 2)->nullable();
            $table->string("actor_type", 16)->nullable();
            $table->string("actor_id", 64)->nullable();
            $table->text("context")->nullable();
            $table->dateTime("created_at")->index();
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_schema_version")) {
        // Tracks the last-applied migration so future upgrades can run
        // ordered, idempotent migration steps instead of re-running every
        // ensure_tables() check unconditionally forever.
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_schema_version", function ($table) {
            $table->increments("id");
            $table->string("version", 20);
            $table->dateTime("applied_at");
        });
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.0.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    } else {
        $already = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.0.0")->count();
        if(!$already) {
            Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
                "version" => "2.0.0",
                "applied_at" => date("Y-m-d H:i:s"),
            ]);
        }
    }

    // --- Security Pack 2.1 (Phase 2) additions below: additive only,
    // nothing above this point is touched. ---

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_rate_limits")) {
        // Fixed-window counters for \WHMCS\Module\Addon\Security_Pack\Security\RateLimiter.
        // Deliberately NOT the same table as dctlab_security_pack_events —
        // this is mutable "current counter state", not an append-only
        // audit log.
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_rate_limits", function ($table) {
            $table->increments("id");
            $table->string("rate_key", 191)->unique();
            $table->unsignedInteger("hits")->default(0);
            $table->dateTime("window_started_at");
            $table->dateTime("updated_at");
        });
    }

    $already21 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.1.0")->count();
    if(!$already21) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.1.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // --- Security Pack 2.2 (Phase 3A) additions below: additive only,
    // nothing above this point is touched. ---

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_ip_rules")) {
        // Backs \WHMCS\Module\Addon\Security_Pack\Security\IpRestrictionService.
        // Deliberately its own table (not dctlab_security_pack_ips, which is
        // the pre-existing PER-CLIENT "Session IP Security Limits"
        // allow-range feature from 1.2.0 — a completely different
        // responsibility: these rules are global ALLOW/BLOCK entries set
        // by an admin, not a client's own login IP allow-list).
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_ip_rules", function ($table) {
            $table->increments("id");
            $table->enum("rule_type", ["allow", "block"]);
            $table->string("target", 45); // bare IP or CIDR, as entered
            $table->unsignedTinyInteger("mask_bits")->default(32); // specificity: 32/128 for a bare IP, else the CIDR mask
            $table->text("description")->nullable();
            $table->boolean("enabled")->default(1);
            $table->integer("priority")->default(0);
            $table->dateTime("expires_at")->nullable();
            $table->string("created_by", 191)->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->index(["enabled", "expires_at"]);
            $table->index("rule_type");
        });
    }

    $already22 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.2.0")->count();
    if(!$already22) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.2.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // --- Security Pack 2.3 (Phase 3B) additions below: additive only,
    // nothing above this point is touched. ---

    // Seed the three no-compatibility-risk security headers to "on" — but
    // ONLY on first install of this migration (guarded by schema_version
    // below, not by a per-key existence check), so an admin who already
    // visited Settings and explicitly turned one of these off never has
    // their choice silently overwritten on a later upgrade/reactivation.
    $already23 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.3.0")->count();
    if(!$already23) {
        $defaultOnHeaders = ["sh_nosniff", "sh_referrer_policy", "sh_permissions_policy"];
        foreach ($defaultOnHeaders as $headerKey) {
            $exists = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->where("setting", $headerKey)->count();
            if(!$exists) {
                Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->insert([
                    "setting" => $headerKey,
                    "value" => "1",
                ]);
            }
        }

        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.3.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // --- Security Pack 2.4 (Phase 4) — Security Assurance. This phase
    // was a code-level audit/hardening pass, not a feature/data-model
    // change: no new tables, no new settings keys, nothing to seed. The
    // schema_version row exists purely so Diagnostics/future migrations
    // can tell this audit pass has run against a given install. ---
    $already24 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.4.0")->count();
    if(!$already24) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.4.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // --- Security Pack 2.5 (Advanced Security Center) additions below:
    // additive only, nothing above this point is touched. Three new
    // tables, each a genuinely new responsibility — none of these
    // duplicate dctlab_security_pack_events (an append-only audit log) or
    // dctlab_security_pack_rate_limits (a fixed-window hit counter). ---

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_csp_reports")) {
        // CSP violation reports are TELEMETRY, not audit events — the
        // same browser/policy mismatch fires repeatedly (every pageview
        // that loads the same blocked resource), so this table stores
        // one GROUPED row per distinct violation shape (see
        // CspReportService::groupingKey()) with an occurrence_count,
        // rather than one row per report. Bounded by retention +
        // max-rows enforcement in CspReportService, not by row size.
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_csp_reports", function ($table) {
            $table->increments("id");
            $table->string("group_key", 64); // sha256 of the normalized violation shape
            $table->string("violated_directive", 191)->nullable();
            $table->string("effective_directive", 191)->nullable();
            $table->string("blocked_uri", 500)->nullable();
            $table->string("document_uri", 500)->nullable();
            $table->string("source_file", 500)->nullable();
            $table->unsignedInteger("line_number")->nullable();
            $table->unsignedInteger("column_number")->nullable();
            $table->string("disposition", 20)->nullable(); // "enforce" | "report"
            $table->string("sample_user_agent", 300)->nullable();
            $table->string("sample_referrer", 500)->nullable();
            $table->unsignedInteger("occurrence_count")->default(1);
            $table->dateTime("first_seen");
            $table->dateTime("last_seen");
            $table->unique("group_key");
            $table->index("last_seen");
            $table->index("violated_directive");
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_anomalies")) {
        // Deterministic anomaly-detection findings (SecurityAnomalyService)
        // with their own acknowledge/dismiss lifecycle — a genuinely
        // different shape from an append-only event ("this happened") or
        // a rate-limit counter ("how often is this happening right now").
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_anomalies", function ($table) {
            $table->increments("id");
            $table->string("rule", 64); // e.g. "auth.repeated_failures_same_ip"
            $table->string("dedupe_key", 191); // rule + the specific IP/country/etc this instance is about
            $table->string("severity", 20); // info|warning|high|critical
            $table->string("confidence", 10); // low|medium|high
            $table->text("reason");
            $table->text("evidence")->nullable(); // JSON — counts/IPs/window, never secrets
            $table->string("ip", 45)->nullable();
            $table->string("status", 20)->default("open"); // open|acknowledged|dismissed
            $table->dateTime("suppressed_until")->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->index(["dedupe_key", "status"]);
            $table->index("created_at");
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_score_snapshots")) {
        // One row per day (written by DailyCronJob), purely so the
        // Security Score trend and the "Security Score drop" alert have
        // history to compare against — the live score itself is still
        // always computed fresh by SecurityScoreService::compute(), this
        // table never substitutes for that.
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_score_snapshots", function ($table) {
            $table->increments("id");
            $table->date("snapshot_date");
            $table->unsignedInteger("score");
            $table->unsignedInteger("max");
            $table->dateTime("created_at");
            $table->unique("snapshot_date");
        });
    }

    $already25 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.5.0")->count();
    if(!$already25) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.5.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // --- Security Pack 2.6 (Email Two-Factor Authentication) additions
    // below. THIS IS THE AUTHORITATIVE EMAIL 2FA IMPLEMENTATION — it
    // extends the pre-existing "email_2fa_length"/"email_2fa_minutes"
    // settings and the already-seeded "Security Pack - Admin/User
    // Two-Factor Authentication" email templates above (both dated from
    // an earlier release but never actually wired to anything), rather
    // than creating a second, parallel 2FA system. Three new tables,
    // each a genuinely distinct lifecycle: persistent per-user
    // configuration, ephemeral single-use OTP challenges, and
    // time-bounded bypass grants. ---

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_email2fa", function ($table) {
            $table->increments("id");
            // WHMCS USER identity (\WHMCS\User\User::id for clients,
            // admin id for admins) — never a per-client-relationship id.
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10); // "client" | "admin"
            $table->string("email", 191)->nullable();
            $table->string("status", 20)->default("disabled"); // pending|active|disabled
            $table->dateTime("activated_at")->nullable();
            $table->dateTime("deactivated_at")->nullable();
            $table->dateTime("last_verified_at")->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->unique(["user_id", "user_type"]);
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa_challenges")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_email2fa_challenges", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            $table->string("purpose", 20); // "activation" | "login"
            $table->string("otp_hash", 255); // never the plaintext OTP
            $table->dateTime("expires_at");
            $table->unsignedInteger("attempt_count")->default(0);
            $table->unsignedInteger("max_attempts")->default(5);
            $table->unsignedInteger("resend_count")->default(0);
            $table->dateTime("last_sent_at")->nullable();
            $table->string("ip", 45)->nullable();
            $table->string("status", 20)->default("pending"); // pending|consumed|expired|invalidated
            // LEGACY (2.6.0, unused as of 2.6.1): sha256 of a
            // continuation token used by the now-removed standalone
            // email2fa-admin-verify.php pre-session page. That page was
            // superseded by the native modules/security/dct_email_2fa
            // security module, which WHMCS itself calls directly with no
            // need for a continuation cookie. Column kept (never
            // destructively dropped from a live schema) but no longer
            // written or read by any current code path.
            $table->string("continuation_hash", 64)->nullable();
            $table->dateTime("created_at");
            // Explicit, short index names (rather than Laravel's
            // auto-generated <table>_<cols>_index) — the auto-generated
            // name for the 4-column index below is 76 characters, over
            // MySQL's 64-character identifier limit, and fails the
            // migration outright (a real production bug this fixes).
            $table->index(["user_id", "user_type", "purpose", "status"], "sp_e2fa_chal_lookup_idx");
            $table->index("expires_at", "sp_e2fa_chal_expires_idx");
            $table->index("continuation_hash", "sp_e2fa_chal_cthash_idx");
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa_bypasses")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_email2fa_bypasses", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            // Normalized visitor IP this grant is scoped to — always
            // paired with user_id+user_type (Step 27 — never a global/
            // IP-only bypass). Empty for "admin_manual" scope, which is
            // scoped to the user only, not an IP.
            $table->string("ip", 45)->default("");
            $table->string("scope", 20); // "same_ip" | "admin_manual"
            $table->dateTime("expires_at");
            $table->string("created_by", 100)->nullable(); // actor label, e.g. "system" or "admin#4"
            $table->string("reason", 255)->nullable();
            $table->dateTime("revoked_at")->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            // Explicit short index names, same reasoning as the
            // challenges table above — these two are currently under the
            // 64-char limit, but named explicitly anyway so a future
            // column addition can never silently push one over it again.
            $table->index(["user_id", "user_type", "ip"], "sp_e2fa_bypass_lookup_idx");
            $table->index("expires_at", "sp_e2fa_bypass_expires_idx");
        });
    }

    $already26 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.6.0")->count();
    if(!$already26) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.6.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.6.1: architecture correction only (see CHANGELOG.md /
    // SECURITY-AUDIT-PHASE-4.md "Phase 7") — no schema change, but
    // recorded for the audit trail exactly like every other version
    // marker here.
    $already261 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.6.1")->count();
    if(!$already261) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.6.1",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.6.2: fixes the over-length auto-generated MySQL index identifier
    // on dctlab_security_pack_email2fa_challenges (see CHANGELOG.md /
    // SECURITY-AUDIT-PHASE-4.md's "Post-release fix" note) — the index
    // NAMES on that table and dctlab_security_pack_email2fa_bypasses
    // changed above; the indexed columns themselves did not.
    $already262 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.6.2")->count();
    if(!$already262) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.6.2",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.6.3: Email 2FA delivery diagnostics fix (see CHANGELOG.md /
    // SECURITY-AUDIT-PHASE-4.md's "Post-release fix — 2.6.3") — no
    // schema change; sendOtpEmail() now captures/logs the real mail()
    // failure reason and passes an envelope sender, the activation/
    // login-challenge screens now reflect actual send status instead of
    // an unconditional "we sent a code" message, and a "Send Test Email"
    // diagnostic action was added.
    $already263 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.6.3")->count();
    if(!$already263) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.6.3",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.0: Email 2FA OTP mail now sent via WHMCS's own mail pipeline
    // (sendAdminMessage()/sendMessage()), per explicit instruction — NOT
    // via raw PHP mail() anymore (see CHANGELOG.md "2.7.0" and
    // SECURITY-AUDIT-PHASE-4.md's matching section). No schema change.
    // SECURITY-RELEVANT: this reverses the pre-2.7.0 guarantee that
    // Global BCC never receives an OTP — if BCC is configured, it now
    // will. Disclosed prominently, not silently changed.
    $already270 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.0")->count();
    if(!$already270) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.1: Security Activity table layout fix — event context no
    // longer renders as a separate, disconnected <tr> (blank Time cell,
    // colspan trailing off) that broke column alignment; it now renders
    // as a second line inside that row's own Message cell. No schema
    // change.
    $already271 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.1")->count();
    if(!$already271) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.1",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.2: Security Activity table overflow fix — the 2.7.1 fix moved
    // context onto the same row but didn't stop very long context (e.g.
    // settings.updated's full settings snapshot) from overflowing past
    // the table/panel edge. Now wrapped in .table-responsive, columns
    // given fixed widths via <colgroup>, the Message cell force-wraps
    // long words, and context JSON over ~220 chars is truncated with a
    // visible marker. No schema change.
    $already272 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.2")->count();
    if(!$already272) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.2",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.3: Security Activity table Event column width fix — the fixed
    // 170px Event column from 2.7.2 was too narrow for the longest real
    // event_type values (e.g. "email_2fa.verification.success", 31
    // chars); <code> doesn't wrap by default, so overflowing text
    // visually collided with the Severity badge next to it. Widened to
    // 230px and given its own word-break rule so it wraps within its
    // own cell instead. No schema change.
    $already273 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.3")->count();
    if(!$already273) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.3",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.4: Security Activity table IP column width fix — the fixed
    // 110px IP column from 2.7.2 was sized for IPv4 (max ~15 chars).
    // Full IPv6 addresses (up to 39 chars) overflowed it and visually
    // ran into the Country column. Widened IP to 190px (Actor trimmed
    // to 90px to compensate) and both cells given word-break so long
    // values wrap within their own cell. No schema change.
    $already274 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.4")->count();
    if(!$already274) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.4",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.5: "Account Security" now also added to the client area's
    // PRIMARY sidebar (main left-hand icon nav) via a new
    // ClientAreaPrimarySidebar hook in core/loginHistory.php, in
    // addition to the existing ClientAreaSecondaryNavbar entry — per
    // explicit user request, since the page was previously only
    // reachable via the secondary "Account" list. No schema change.
    $already275 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.5")->count();
    if(!$already275) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.5",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.6: per explicit user request, removed BOTH client-area
    // "Account Security" menu injections — the 2.7.5 ClientAreaPrimarySidebar
    // hook (deleted entirely) AND the original ClientAreaSecondaryNavbar
    // "Account" dropdown entry (2.3.0, now removed from the same hook
    // that still adds Login History). The security_center controller/page
    // itself is unchanged and still reachable directly by URL. No schema
    // change.
    $already276 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.6")->count();
    if(!$already276) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.6",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.7: per explicit user request, removed the Login History entry
    // from the client area's secondary "Account" dropdown as well —
    // this was the last remaining item added by the
    // ClientAreaSecondaryNavbar hook in core/loginHistory.php (the
    // "Account Security" entry was already removed in 2.7.6), so the
    // hook itself was removed entirely rather than left as a no-op. The
    // login_history controller/page is unchanged and still reachable
    // directly by URL. No schema change.
    $already277 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.7")->count();
    if(!$already277) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.7",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.8: "Account Security" added back to the client area, this
    // time nested as a CHILD of the existing WHMCS "Account" item in
    // the PRIMARY sidebar, via a new ClientAreaPrimarySidebar hook in
    // core/loginHistory.php built from user-supplied, confirmed-working
    // reference code (getChild("Account") resolves on the primary
    // sidebar, unlike the earlier secondary-navbar case). No schema
    // change.
    $already278 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.8")->count();
    if(!$already278) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.8",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    // 2.7.9: fix — every "Manage" button in the Account Security page's
    // "Authentication" box linked to a guessed, nonexistent URL
    // ({$WEB_ROOT}/user-security or {$WEB_ROOT}/security). Fixed to
    // {$WEB_ROOT}/clientarea.php?action=security, WHMCS's documented,
    // always-valid classic URL for the native Security Settings page
    // (hosts Password Reset / Login Notification / Two-Factor
    // Authentication together). No schema change.
    $already279 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.7.9")->count();
    if(!$already279) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.7.9",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    $already280 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.8.0")->count();
    if(!$already280) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.8.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
    $already290 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "2.9.0")->count();
    if(!$already290) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "2.9.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // Security Pack 3.0 — Unified Two-Factor Authentication. Per the
    // NON-NEGOTIABLE non-duplication rule this feature was built under:
    // the existing dctlab_security_pack_email2fa_bypasses table is REUSED
    // as the one authoritative 2FA bypass store (see
    // TwoFactorBypassService) — only an additive, nullable `method`
    // column is added to it, never a second bypass table. WhatsApp and
    // TOTP each get their own enrollment/challenge tables, mirroring the
    // existing Email 2FA schema shape, plus one shared recovery-codes
    // table (Section 16/17 — one recovery-code system, not one per
    // method).
    if(!Illuminate\Database\Capsule\Manager::schema()->hasColumn("dctlab_security_pack_email2fa_bypasses", "method")) {
        Illuminate\Database\Capsule\Manager::schema()->table("dctlab_security_pack_email2fa_bypasses", function ($table) {
            $table->string("method", 20)->nullable()->after("scope"); // "email"|"whatsapp"|"totp"|"manual"|null (pre-3.0 rows)
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_whatsapp2fa")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_whatsapp2fa", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            $table->string("phone", 32)->nullable();
            $table->string("status", 20)->default("disabled"); // pending|active|disabled
            $table->dateTime("activated_at")->nullable();
            $table->dateTime("deactivated_at")->nullable();
            $table->dateTime("last_verified_at")->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->unique(["user_id", "user_type"]);
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_whatsapp2fa_challenges")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_whatsapp2fa_challenges", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            $table->string("purpose", 20);
            $table->string("otp_hash", 255);
            $table->dateTime("expires_at");
            $table->unsignedInteger("attempt_count")->default(0);
            $table->unsignedInteger("max_attempts")->default(5);
            $table->unsignedInteger("resend_count")->default(0);
            $table->dateTime("last_sent_at")->nullable();
            $table->string("ip", 45)->nullable();
            $table->string("status", 20)->default("pending");
            $table->dateTime("created_at");
            $table->index(["user_id", "user_type", "purpose", "status"], "sp_w2fa_chal_lookup_idx");
            $table->index("expires_at", "sp_w2fa_chal_expires_idx");
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_totp2fa")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_totp2fa", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            // Encrypted at rest (libsodium secretbox) — see TotpKeyStore.
            // Never the plaintext secret.
            $table->text("secret_encrypted")->nullable();
            $table->string("status", 20)->default("disabled"); // pending|active|disabled
            $table->dateTime("activated_at")->nullable();
            $table->dateTime("deactivated_at")->nullable();
            $table->dateTime("last_verified_at")->nullable();
            // Replay protection (dct_totp_2fa rebuild) — the RFC 4226 HOTP
            // counter of the most recently ACCEPTED login code. A code
            // whose matched counter is <= this value is rejected as a
            // replay. Nullable: unset until the first successful
            // verification (enrollment activation or first login).
            $table->unsignedBigInteger("last_used_step")->nullable();
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->unique(["user_id", "user_type"]);
        });
    } elseif(!Illuminate\Database\Capsule\Manager::schema()->hasColumn("dctlab_security_pack_totp2fa", "last_used_step")) {
        // Additive, idempotent migration for installs that already have
        // this table from before the replay-protection rebuild. Existing
        // rows (including already-active enrollments) are left otherwise
        // untouched — no re-enrollment required, no secret is touched or
        // re-encrypted. The new column starts NULL for every existing
        // row, so each account's very next successful login simply
        // establishes its first baseline (identical to a brand-new
        // enrollment) rather than rejecting anything retroactively.
        Illuminate\Database\Capsule\Manager::schema()->table("dctlab_security_pack_totp2fa", function ($table) {
            $table->unsignedBigInteger("last_used_step")->nullable();
        });
    }

    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_2fa_recovery_codes")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_2fa_recovery_codes", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            $table->string("code_hash", 255); // never the plaintext code
            $table->dateTime("used_at")->nullable();
            $table->dateTime("created_at");
            $table->index(["user_id", "user_type"], "sp_2fa_recovery_lookup_idx");
        });
    }

    // 2026-08-22 — Requirements doc Section 1: dedicated 2FA IP/CIDR
    // exemption store. Deliberately its OWN table, not a reuse of
    // dctlab_security_pack_ip_rules (IpRestrictionService's table) — see
    // TwoFactorIpExemptionService's class docblock for why. user_id/
    // user_type both NULL means a global/"company IP" rule; both set
    // means the rule is scoped to that EXACT identity only.
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_2fa_ip_exemptions")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_2fa_ip_exemptions", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id")->nullable();
            $table->string("user_type", 10)->nullable();
            $table->string("entry", 45);
            $table->string("reason", 255)->nullable();
            $table->string("created_by", 100)->nullable();
            $table->boolean("enabled")->default(true);
            $table->dateTime("created_at");
            $table->dateTime("updated_at");
            $table->index(["user_id", "user_type"], "sp_2fa_ipexempt_user_idx");
            $table->index("enabled", "sp_2fa_ipexempt_enabled_idx");
        });
    }

    // 2026-08-22 — Requirements doc Section 3: "Remember this browser
    // for 30 days" trusted-browser store. Deliberately its OWN table —
    // independent from BOTH dctlab_security_pack_email2fa_bypasses (the
    // same-IP/admin-manual bypass store) AND
    // dctlab_security_pack_2fa_ip_exemptions (the company-IP exemption
    // store) — see TrustedBrowserService's class docblock for why none
    // of the three may be merged. token_hash stores only
    // hash('sha256', $rawToken) — the plaintext token is NEVER
    // persisted anywhere. user_id/user_type scope every row to one
    // exact identity, the same isolation guarantee as every other 2FA
    // table since v3.1.28.
    if(!Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_trusted_browsers")) {
        Illuminate\Database\Capsule\Manager::schema()->create("dctlab_security_pack_trusted_browsers", function ($table) {
            $table->increments("id");
            $table->unsignedInteger("user_id");
            $table->string("user_type", 10);
            $table->string("token_hash", 64); // hex sha256 — never the plaintext token
            $table->string("device_label", 255)->nullable(); // display-only metadata (e.g. truncated User-Agent), never a security decision input
            $table->string("created_ip", 45)->nullable(); // display/audit only — NOT used to re-validate the token; that would reintroduce IP as part of the trust decision
            $table->dateTime("created_at");
            $table->dateTime("last_used_at")->nullable();
            $table->dateTime("expires_at"); // absolute — never extended/renewed on use, see class docblock
            $table->dateTime("revoked_at")->nullable();
            $table->unique("token_hash", "sp_trusted_browser_token_idx");
            $table->index(["user_id", "user_type"], "sp_trusted_browser_identity_idx");
            $table->index("expires_at", "sp_trusted_browser_expires_idx");
        });
    }

    $already300 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "3.0.0")->count();
    if(!$already300) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "3.0.0",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }

    // Post-3.1.0 mutual-exclusion fix: no schema change, but existing
    // accounts may already have more than one 2FA method marked
    // "active" (the exact bug being fixed — each method's own table was
    // written to independently, with nothing enforcing exclusivity).
    // TwoFactorAuthenticationService::enforceSingleActiveMethod() also
    // self-heals lazily whenever a given user's status is next read
    // (Client Security Center, admin overview), but that only happens
    // per-user, on demand. Run it once for every account already in a
    // multi-active state, so the fix is complete immediately rather
    // than depending on each affected user visiting their Security
    // Center page first. Idempotent (gated by its own schema_version
    // marker) and never fatal — any failure here is swallowed, exactly
    // like every other schema_version step in this function.
    $already311 = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->where("version", "3.1.1")->count();
    if(!$already311) {
        security_pack_repair_2fa_exclusivity();
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->insert([
            "version" => "3.1.1",
            "applied_at" => date("Y-m-d H:i:s"),
        ]);
    }
}

/**
 * One-time batch repair for the 2FA mutual-exclusion fix (see the
 * "3.1.1" schema_version step above). Finds every (user_id, user_type)
 * pair with MORE THAN ONE 2FA method currently marked "active" across
 * the three method tables, and calls the SAME
 * TwoFactorAuthenticationService::enforceSingleActiveMethod() the
 * Client Security Center already self-heals with on every status read
 * — never a separate/duplicate repair implementation. Never touches
 * accounts that are already consistent (0 or 1 active method).
 */
function security_pack_repair_2fa_exclusivity(): void
{
    if(!class_exists(\WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService::class)) {
        return;
    }
    try {
        $activeByUser = []; // "userType:userId" => count of active methods
        $tables = [
            "dctlab_security_pack_email2fa",
            "dctlab_security_pack_whatsapp2fa",
            "dctlab_security_pack_totp2fa",
        ];
        foreach ($tables as $table) {
            if(!Illuminate\Database\Capsule\Manager::schema()->hasTable($table)) {
                continue;
            }
            $rows = Illuminate\Database\Capsule\Manager::table($table)->where("status", "active")->select("user_id", "user_type")->get();
            foreach ($rows as $row) {
                $key = $row->user_type . ":" . $row->user_id;
                $activeByUser[$key] = ($activeByUser[$key] ?? 0) + 1;
            }
        }
        foreach ($activeByUser as $key => $count) {
            if($count <= 1) {
                continue;
            }
            [$userType, $userId] = explode(":", $key, 2);
            \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService::enforceSingleActiveMethod((int) $userId, $userType, "system-upgrade-repair");
        }
    } catch (\Throwable $e) {
        // Never block activation/upgrade over this — the same self-heal
        // will still run lazily the next time each affected user's
        // status is read (see TwoFactorAuthenticationService::status()).
    }
}
function security_pack_activate()
{
    security_pack_ensure_tables();
    return ["status" => "success", "description" => "security_pack has been activated."];
}
function security_pack_upgrade(array $vars)
{
    // WHMCS only calls _activate() on a fresh install — sites that already
    // had security_pack active before a given release need this to run
    // instead, so newly added tables/columns actually get created.
    security_pack_ensure_tables();
}
function security_pack_deactivate()
{
    $delete = Illuminate\Database\Capsule\Manager::table("tbladdonmodules")->where("module", "security_pack")->where("setting", "nodeletedb")->first();
    if($delete->value) {
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_logins");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_opt");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_ips");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_dpass");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_geo_cache");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_lc_overrides");
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Admin Login Notification")->delete();
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Login Notification")->delete();
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - User Two-Factor Authentication")->delete();
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Admin Two-Factor Authentication")->delete();
        Illuminate\Database\Capsule\Manager::table("tblemailtemplates")->where("name", "Security Pack - Security Alert Digest")->delete();
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_csp_reports");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_anomalies");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_score_snapshots");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_email2fa");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_email2fa_challenges");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_email2fa_bypasses");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_whatsapp2fa");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_whatsapp2fa_challenges");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_totp2fa");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_2fa_recovery_codes");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_2fa_ip_exemptions");
        Illuminate\Database\Capsule\Manager::schema()->dropIfExists("dctlab_security_pack_trusted_browsers");
    }
    global $CONFIG;
    $template_file = ROOTDIR . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . $CONFIG["Template"] . DIRECTORY_SEPARATOR . "user-security.tpl";
    if(file_exists($template_file)) {
        $template_content = file_get_contents($template_file);
        file_put_contents($template_file, str_replace("{include file=\"modules/addons/security_pack/templates/settings.tpl\"}", "", $template_content));
    } else {
        $template_file = ROOTDIR . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . $CONFIG["Template"] . DIRECTORY_SEPARATOR . "clientareasecurity.tpl";
        if(file_exists($template_file)) {
            $template_content = file_get_contents($template_file);
            file_put_contents($template_file, str_replace("{include file=\"modules/addons/security_pack/templates/settings.tpl\"}", "", $template_content));
        }
    }
    return ["status" => "success", "description" => "security_pack has been deactivated."];
}
function security_pack_output($vars)
{
    if(!class_exists("NNM_Page_Builder")) {
        include __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "pagebuilder.php";
    }
    $LANG = $vars["_lang"];
    $page_manager = new NNM_Page_Builder();
    $page_manager->modulename = "DCTLAB Security Pack";
    $page_manager->modulelink = "security_pack";
    $page_manager->helplink = "https://dctlab.directcybertech.com/";
    $settings = security_pack_settings();
    // Security Pack 2.1: "Overview" (the new Security Center
    // dashboard) is now the default landing tab instead of
    // Settings — Settings itself is unchanged, just one click
    // away, at its own explicit c=settings URL.
    $page_manager->menu["Overview"] = ["href" => "", "address" => "", "istab" => false, "external" => false];
    // 3.2.0 nav reorder: "Two-Factor Authentication" moved up to sit
    // directly after "Overview" — it's the primary security function
    // and should be prominent in the menu. href/address unchanged
    // ("c=twoFactor"), so no existing URL or bookmark breaks.
    //
    // 3.1.25: "Email 2FA" no longer has its OWN nav entry — its content
    // (enrollment overview + its own bypass table) is now embedded
    // directly on the "Two-Factor Authentication" page below, per
    // explicit request to show both on one page. c=email2fa is still a
    // fully working route (old bookmarks/links), it just redirects to
    // c=twoFactor now — see Email2faController::index().
    //
    // Always shown — Security Pack 3.0's unified 2FA policy/overview/
    // bypass page (Section 21: "move [the admin bypass] to the unified
    // 2FA layer"), now also embedding Email 2FA's own page content
    // (3.1.25). WHMCS's own native Setup > Security > Two-Factor
    // Authentication screen remains where each method is actually
    // activated — see TwoFactorController's own header comment for the
    // exact division of responsibility.
    $page_manager->menu["Two-Factor Authentication"] = ["href" => "c=twoFactor", "address" => "twoFactor", "istab" => false, "external" => false];
    // --- "Protection" dropdown group (order below = dropdown order) ---
    // Always shown — safe to open even with zero rules
    // configured (Security Pack 2.2); the feature only does
    // anything once an admin explicitly adds a rule.
    $page_manager->menu["IP Restrictions"] = ["href" => "c=ipRestrictions", "address" => "ipRestrictions", "istab" => false, "external" => false];
    // Always shown — dedicated Country Restrictions status/rules page
    // (Security Pack 2.8), a CONSUMER of the existing GeoIP Manager
    // architecture (same MaxMind database / providers as GeoIP Language
    // & Currency), not a second GeoIP system. Safe to open even with the
    // feature currently disabled (the page shows Disabled + a link to
    // turn it on).
    $page_manager->menu["Country Restrictions"] = ["href" => "c=countryRestriction", "address" => "countryRestriction", "istab" => false, "external" => false];
    if(isset($settings["password_reset"])) {
        $page_manager->menu["Disabled Reset Password Clients"] = ["href" => "c=passwordDisabled", "address" => "passwordDisabled", "istab" => false, "external" => false];
    }
    // Not part of the requested target menu tree, but still a live,
    // reachable controller/route — kept available (appended to the end
    // of the "Protection" dropdown) rather than dropped, per "keep each
    // existing page available exactly once."
    if(isset($settings["ip_range_limits"])) {
        $page_manager->menu["IP Security Limited Clients"] = ["href" => "c=ipLimitedClients", "address" => "ipLimitedClients", "istab" => false, "external" => false];
    }
    // --- "Activity" dropdown group (order below = dropdown order) ---
    // Security Pack 2.5: this item's LABEL is "All Events" (it sits
    // inside the "Activity" dropdown alongside Analytics/Anomalies/
    // Alerts below) but its href/address ("c=activity") is completely
    // unchanged, so the existing URL keeps working exactly as before.
    $page_manager->menu["All Events"] = ["href" => "c=activity", "address" => "activity", "istab" => false, "external" => false];
    $page_manager->menu["Analytics"] = ["href" => "c=analytics", "address" => "analytics", "istab" => false, "external" => false];
    $page_manager->menu["Anomalies"] = ["href" => "c=anomalies", "address" => "anomalies", "istab" => false, "external" => false];
    $page_manager->menu["Alerts"] = ["href" => "c=alerts", "address" => "alerts", "istab" => false, "external" => false];
    if(isset($settings["login_history"])) {
        $page_manager->menu["Login History"] = ["href" => "c=LoginLogs", "address" => "LoginLogs", "istab" => false, "external" => false];
    }
    // Always shown — it's a dedicated management page (GeoIP
    // database, test-a-lookup, default fallback, country rules,
    // advanced settings) independent of whether the feature is
    // currently switched on via the Enable toggle on that page.
    $page_manager->menu["Language & Currency"] = ["href" => "c=langCurrency", "address" => "langCurrency", "istab" => false, "external" => false];
    // --- "System" dropdown group (order below = dropdown order) ---
    // Always shown — read-only diagnostics/health page, no
    // dependency on any feature toggle (Security Pack 2.0).
    $page_manager->menu["Security Diagnostics"] = ["href" => "c=diagnostics", "address" => "diagnostics", "istab" => false, "external" => false];
    // Always shown — dedicated CSP Reporting Center page
    // (Security Pack 2.5); safe to open even with report
    // collection currently switched off (the page explains how to
    // enable it).
    $page_manager->menu["CSP Reports"] = ["href" => "c=cspReports", "address" => "cspReports", "istab" => false, "external" => false];
    $page_manager->menu["Settings"] = ["href" => "c=settings", "address" => "settings", "istab" => false, "external" => false];

    // Security Pack 2.3/2.5/2.6/3.2.0 — Security Center navigation
    // groups. Deliberately only groups pages that ACTUALLY EXIST
    // as dedicated controllers today — it would be dishonest to
    // show a grouped sub-item when that feature is really just a
    // panel inside another tab with no page of its own. The
    // spec's target tree also lists "Login Notifications" and
    // "Password Protection" under Authentication, and an "Audit
    // Log" page under System; none of those are added here
    // because they're still panels inside Settings / the
    // existing Activity(All Events) page rather than dedicated
    // controllers. This changes ONLY how menu items are visually
    // organized — every href/address above is completely
    // unchanged, so no existing URL or bookmark breaks.
    //
    // 3.2.0: reduced to exactly the three requested dropdown groups
    // (Protection, Activity, System) — "Two-Factor Authentication",
    // "Login History", "Language & Currency", and "Settings" are no
    // longer wrapped in single-item dropdown groups ("Authentication",
    // "Clients", "Geo & Localization"), matching the requested exact
    // top-level menu order. navigation.tpl renders each dropdown at the
    // position of the FIRST group member's position in $page_manager
    // ->menu above (see that template's header comment), which is why
    // the insertion order above places "IP Restrictions" / "All Events"
    // / "Security Diagnostics" exactly where each dropdown should appear.
    $page_manager->menuGroups = [
        "Protection" => ["IP Restrictions", "Country Restrictions", "Disabled Reset Password Clients", "IP Security Limited Clients"],
        "Activity" => ["All Events", "Analytics", "Anomalies", "Alerts"],
        "System" => ["Security Diagnostics", "CSP Reports"],
    ];

    // 3.1.16: the "ajaxUsersTwoFactorStatus" bare-output action
    // (TwoFactorController) was the AJAX endpoint for the admin Client
    // Profile > Users tab integration — REMOVED in 3.1.16, which
    // replaced that whole mechanism with a server-side JSON mapping (see
    // core/two_factor_admin_display.php and
    // TwoFactorController::buildUsersTwoFactorMappingForClient()), so
    // there is no longer any bare-output AJAX action for that feature.
    // "user" (the Login History tab pane) is unrelated and unchanged.
    $bareOutputActions = ["user"];
    $page_manager->startlang();
    if(!isset($_REQUEST["a"]) || !in_array($_REQUEST["a"], $bareOutputActions, true)) {
        $page_manager->header();
    }
    if(isset($_REQUEST["saved"])) {
        echo "<div class=\"alert alert-success\">Saved Successfully!</div>";
    }
    if(isset($_REQUEST["deleted"])) {
        echo "<div class=\"alert alert-success\">Deleted Successfully!</div>";
    }
    // Security Pack 2.1: default landing tab is now the Security
    // Center Overview (dashboard) instead of Settings.
    $controller = isset($_REQUEST["c"]) ? $_REQUEST["c"] : "Dashboard";
    $action = isset($_REQUEST["a"]) ? $_REQUEST["a"] : "index";
    $controller .= "Controller";
    $controller = ucfirst($controller);
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\" . $controller)) {
        redir("module=security_pack", "addonmodules.php");
    }
    $controller = "\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\" . $controller;
    $controller = new $controller();
    // 3.1.12: method_exists() reports a hit regardless of visibility, so
    // an action name matching a controller's PRIVATE helper method (e.g.
    // TwoFactorController::save()/bypass()/revoke(), which are only ever
    // meant to be invoked internally by that controller's own index()
    // via its own $_REQUEST["a"] switch) fatal-errored here with "Call
    // to private method ... from global scope" the moment a form posted
    // a=save/a=bypass/a=revoke. is_callable() is visibility-aware from
    // the CALLING scope (this plain global function, outside the class),
    // so it correctly returns false for a private/protected method here
    // and this now falls through to index() exactly as intended — no
    // change for any action that's genuinely public, since is_callable()
    // and method_exists() agree for those.
    if(is_callable([$controller, $action])) {
        $controller->{$action}($vars);
    } else {
        $controller->index($vars);
    }
    if(!isset($_REQUEST["a"]) || !in_array($_REQUEST["a"], $bareOutputActions, true)) {
        $page_manager->footer();
    }
}
function security_pack_clientarea($vars)
{
    $lang = $vars["_lang"];
    $currentUser = new WHMCS\Authentication\CurrentUser();
    $user = $currentUser->client();
    if(!$user) {
        redir("", "index.php");
    }
    $controller = isset($_REQUEST["c"]) ? $_REQUEST["c"] : "Client";
    $action = isset($_REQUEST["page"]) ? $_REQUEST["page"] : "login_history";
    $controller .= "Controller";
    $controller = ucfirst($controller);
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Client\\" . $controller)) {
        redir("", "index.php");
    }
    $controller = "\\WHMCS\\Module\\Addon\\Security_Pack\\Client\\" . $controller;
    $controller = new $controller();
    // 3.1.12: same visibility-aware fix as the admin dispatcher above —
    // is_callable() (not method_exists()) so a private/protected client
    // controller method can never be invoked directly from this global
    // scope; falls through to index() instead of fatal-erroring.
    if(is_callable([$controller, $action])) {
        return $controller->{$action}($vars);
    }
    return $controller->index($vars);
}

?>