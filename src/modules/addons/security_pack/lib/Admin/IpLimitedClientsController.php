<?php



//  file for php version 74.
namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class IpLimitedClientsController
{
    public function index()
    {
        global $aInt;
        global $page;
        global $numrows;
        global $limit;
        // PHASE 3.6D (2026-08-24): smallest safe DCTLAB presentation
        // integration — everything between here and ob_get_clean() below
        // is 100% UNCHANGED (same delete/CSRF/POST guard above this
        // point, same $aInt calls, same global $page/$numrows/$limit,
        // same queries, same search form, same sortableTable() call).
        // Only captures the existing output and places it inside the
        // shared page header + asset load. See the Phase 3.6D report for
        // the one disclosed cosmetic side effect (inherited
        // font-size:13px/color:#333 from the shared .sp-page wrapper).
        ob_start();
        echo $aInt->beginAdminTabs([$aInt->lang("global", "searchfilter")]);
        // Security Pack 2.2 fixed the missing-CSRF-check on this delete;
        // Security Pack 2.3 makes it POST-only too (Step 12/14) — same
        // reasoning as PasswordDisabledController.
        if(isset($_POST["delete_id"]) && $_SERVER["REQUEST_METHOD"] === "POST") {
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_error"] = "Your session token expired — please try again.";
                redir("module=security_pack&c=ipLimitedClients", "addonmodules.php");
            }
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("id", (int) $_POST["delete_id"])->delete();
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("ip_protection.session_ip_limit_removed", "Admin removed a Session IP Security Limit entry.", ["record_id" => (int) $_POST["delete_id"]]);
            }
            redir("module=security_pack&c=ipLimitedClients&deleted=1", "addonmodules.php");
        }
        $csrfToken = security_pack_csrf_token();
        echo "        <style>\r\n            #sortabletbl1 td {\r\n                text-align: center;\r\n            }\r\n        </style>\r\n        <form action=\"\" method=\"post\">\r\n            <input type=\"hidden\" name=\"search\" value=\"1\">\r\n            <table class=\"form\" width=\"100%\" border=\"0\" cellspacing=\"2\" cellpadding=\"3\">\r\n                <tbody>\r\n                <tr>\r\n                    <td class=\"fieldlabel\">User:</td>\r\n                    <td class=\"fieldarea\"><select id=\"selectUser\"\r\n                                                  name=\"user\"\r\n                                                  class=\"form-control selectize selectize-user-search\"\r\n                                                  data-value-field=\"id\"\r\n                                                  data-allow-empty-option=\"0\"\r\n                                                  placeholder=\"Start Typing to Search Users\"\r\n                                                  data-user-label=\"User\"\r\n                                                  data-search-url=\"/";
        echo \App::getApplicationConfig()["customadminpath"];
        echo "/index.php?rp=/";
        echo \App::getApplicationConfig()["customadminpath"];
        echo "/client/0/user/search\"\r\n                        >\r\n                        </select>\r\n                    </td>\r\n                </tr>\r\n                </tbody>\r\n            </table>\r\n            <div class=\"btn-container\">\r\n                <input type=\"submit\" value=\"Search\" class=\"btn btn-default\">\r\n            </div>\r\n        </form>\r\n        ";
        echo $aInt->endAdminTabs();
        $aInt->sortableTableInit("id");
        $numrows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->count();
        if(isset($_REQUEST["user"]) && $_REQUEST["user"]) {
            $numrows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("user_id", $_REQUEST["user"])->count();
        }
        $limit = $aInt->rowLimit;
        $records = $page * $limit;
        $tabledata = [];
        $aInt->deleteJSConfirm("doDelete", "global", "deleteconfirm", "?module=security_pack&c=ipLimitedClients&deleteid=");
        $result = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->leftJoin("tblusers", "dctlab_security_pack_ips.user_id", "=", "tblusers.id")->select("dctlab_security_pack_ips.*", "tblusers.first_name", "tblusers.last_name")->skip($records)->take($limit)->orderBy("id", "DESC");
        if(isset($_REQUEST["user"]) && $_REQUEST["user"]) {
            $result = $result->where("user_id", $_REQUEST["user"]);
        }
        $result = $result->get();
        foreach ($result as $data) {
            $tabledata[] = [$data->user_id, $data->first_name . " " . $data->last_name, $data->start_ip, $data->end_ip, "<form method=\"post\" action=\"?module=security_pack&c=ipLimitedClients\" style=\"display:inline;margin:0;\" onsubmit=\"return confirm('Remove this Session IP Security Limit entry? This cannot be undone.')\"><input type=\"hidden\" name=\"security_pack_token\" value=\"" . htmlspecialchars($csrfToken, ENT_QUOTES, "UTF-8") . "\"><input type=\"hidden\" name=\"delete_id\" value=\"" . (int) $data->id . "\"><button type=\"submit\" class=\"btn btn-danger btn-sm\"><i class=\"fas fa-trash\"></i></button></form>"];
        }
        echo $aInt->sortableTable(["User ID", "Full Name", "Start IP Address", "Start IP Address", ""], $tabledata);
        echo "        <script>\r\n            jQuery(document).ready(function () {\r\n                WHMCS.selectize.userSearch();\r\n            });\r\n        </script>\r\n        ";
        $capturedContent = ob_get_clean();

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "IP Security Limited Clients",
            "pageDescription" => "Clients currently restricted to a specific IP range for their session.",
            "pageActionsHtml" => "",
            "content" => $capturedContent,
        ]);
    }
}

?>