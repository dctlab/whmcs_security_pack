<?php
/* * ********************************************************************
 * Dct Lab
 * ******************************************************************** */

$_ADDONLANG['login_history'] = "Login History";
$_ADDONLANG['client_area'] = "Client Area";
$_ADDONLANG['ip_address'] = "IP Address";
$_ADDONLANG['os'] = "OS";
$_ADDONLANG['browser'] = "Browser";
$_ADDONLANG['date_time'] = "Date Time";
$_ADDONLANG['login_notification'] = 'Login Notification';
$_ADDONLANG['login_notification_details'] = 'Send an email notification when you log into our system.';
$_ADDONLANG['account_settings'] = 'Account Settings';
$_ADDONLANG['invalid_ips'] = 'Both Start IP and End Ip must be valid IP addresses.';
$_ADDONLANG['invalid_start_ip'] = "Start IP must be less than End IP.";


# Email 2FA Variables
$_ADDONLANG['email_2fa'] = "Email";
$_ADDONLANG['email_2fa_desc'] = "Receive two-factor authentication codes through email.";
$_ADDONLANG['email_2fa_client_area'] = "An email containing a one-time code has been dispatched to you.";
$_ADDONLANG['email_2fa_empty'] = "The code was not entered.";
$_ADDONLANG['email_2fa_invalid'] = "The code entered does not match.";
$_ADDONLANG['email_2fa_expired'] = "This code has expired";
$_ADDONLANG['email_2fa_put'] = "Please enter the code you received here";
$_ADDONLANG['email_2fa_activated'] = "The email-based two-factor authentication has been successfully activated.";
$_ADDONLANG['email_2fa_activate'] = "Active Now";
$_ADDONLANG['email_2fa_login'] = "Login Now2";
$_ADDONLANG['email_2fa_received_code'] = "Code";
$_ADDONLANG['disable_reset_password_title'] = "Disable Forgot Password Reset";
$_ADDONLANG['disable_reset_password_desc'] = "Enable this option so the system can prevent password reset requests for your account.";
$_ADDONLANG['yes'] = "Yes";
$_ADDONLANG['no'] = "No";
$_ADDONLANG['ip_login_limit'] = "Session IP Security Limits";
$_ADDONLANG['ip_login_limit_desc'] = "This feature limits access to your account to logins from pre-approved IP addresses, enhancing security by preventing unauthorized access. Ensure your IP address is static to avoid unintended lockouts.";
$_ADDONLANG['ip_login_limit_current_ip'] = "Your Current IP Address:";
$_ADDONLANG['ip_login_limit_start_ip'] = "Start IP";
$_ADDONLANG['ip_login_limit_end_ip'] = "End IP";
$_ADDONLANG['ip_login_limit_add'] = "Add Range";
$_ADDONLANG['are_you_sure'] = "Are you sure?";
$_ADDONLANG['delete'] = "Delete";
$_ADDONLANG['saved'] = "Saved Successfully";
$_ADDONLANG['right_click_error'] = "Right Click Disabled.";
$_ADDONLANG['copy_paste_disabled'] = "Copy/Paste functions is disabled.";
$_ADDONLANG['free_email_error'] = "We apologize, but we are unable to accept email addresses from free email providers.";
$_ADDONLANG['ip_limited_to_login'] = "Your IP address is not allowed to log in to this account.";
$_ADDONLANG['reset_password_disabled'] = "Reset password disabled for your account";
$_ADDONLANG['blocked_banner'] = "Notice: We regret to inform that currently, orders and registrations from your country are not supported on our website.";
$_ADDONLANG['blocked_message'] = "Orders and registrations from your country are not supported on our website.";
$_ADDONLANG['geoiplc_banner_text'] = "We set your language/currency based on your location";
$_ADDONLANG['geoiplc_use_default'] = "Use site default";

$_ADDONLANG['email_2fa_resend_code'] = "Resend Backup Code";

// Security Pack 2.3 — Client Security Center
$_ADDONLANG['security_center_title'] = "Account Security";
$_ADDONLANG['security_center_your_security'] = "Your Security";
$_ADDONLANG['security_center_status_note'] = "Based on the security features available on your account. This is not the same as your provider's internal security configuration.";
$_ADDONLANG['security_center_authentication'] = "Authentication";
$_ADDONLANG['security_center_2fa'] = "Two-Factor Authentication";
$_ADDONLANG['security_center_manage'] = "Manage";
$_ADDONLANG['security_center_password_reset_enabled'] = "Password reset is available (you can disable it in Security Settings)";
$_ADDONLANG['security_center_no_features'] = "No optional account security features are currently enabled by your provider.";
$_ADDONLANG['security_center_current_session'] = "Current Session";
$_ADDONLANG['security_center_current'] = "Current";
$_ADDONLANG['security_center_sessions_note'] = "For security reasons, a full list of other active sessions and the ability to remotely sign them out is not available at this time — only your current session's information is shown. If you believe your account has been accessed without your permission, change your password immediately and contact support.";
$_ADDONLANG['security_center_recent_activity'] = "Recent Activity";
$_ADDONLANG['security_center_view_all_activity'] = "View full login history";
$_ADDONLANG['security_center_no_activity'] = "No recent activity recorded yet.";
$_ADDONLANG['security_center_strength_strong'] = "Strong";
$_ADDONLANG['security_center_strength_good'] = "Good";
$_ADDONLANG['security_center_strength_weak'] = "Needs Attention";
$_ADDONLANG['security_center_strength_unknown'] = "Not enough data";
$_ADDONLANG['security_center_rec_enable_login_notification'] = "Turn on login alerts so you're notified of new sign-ins.";
$_ADDONLANG['security_center_rec_enable_2fa'] = "Two-factor authentication is not enabled — turn it on for stronger protection.";
// Security Pack 3.1.2 — provider-neutral: shown only when NONE of
// Email / DCTLAB WhatsApp / Time-Based Token is active, never when one
// of them already is (see ClientController::twoFactorRecommendation()).
$_ADDONLANG['security_center_rec_enable_2fa_unified'] = "Two-factor authentication is not enabled. Enable Email, DCTLAB WhatsApp, or Time-Based Tokens.";
