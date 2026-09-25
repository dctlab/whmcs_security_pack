<?php


//  file for php version 74.
namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class LoginLogsController
{
    private function getBrowser($user_agent = "")
    {
        $browser = "N/A";
        $browsers = ["/msie/i" => "Internet explorer", "/firefox/i" => "Firefox", "/safari/i" => "Safari", "/chrome/i" => "Chrome", "/edge/i" => "Edge", "/opera/i" => "Opera", "/mobile/i" => "Mobile browser"];
        foreach ($browsers as $regex => $value) {
            if(preg_match($regex, $user_agent)) {
                $browser = $value;
            }
        }
        return $browser;
    }
    public function getOS($user_agent)
    {
        $os_platform = "N/A";
        $os_array = ["/windows nt 10/i" => "Windows 10", "/windows nt 6.3/i" => "Windows 8.1", "/windows nt 6.2/i" => "Windows 8", "/windows nt 6.1/i" => "Windows 7", "/windows nt 6.0/i" => "Windows Vista", "/windows nt 5.2/i" => "Windows Server 2003/XP x64", "/windows nt 5.1/i" => "Windows XP", "/windows xp/i" => "Windows XP", "/windows nt 5.0/i" => "Windows 2000", "/windows me/i" => "Windows ME", "/win98/i" => "Windows 98", "/win95/i" => "Windows 95", "/win16/i" => "Windows 3.11", "/macintosh|mac os x/i" => "Mac OS X", "/mac_powerpc/i" => "Mac OS 9", "/linux/i" => "Linux", "/ubuntu/i" => "Ubuntu", "/iphone/i" => "iPhone", "/ipod/i" => "iPod", "/ipad/i" => "iPad", "/android/i" => "Android", "/blackberry/i" => "BlackBerry", "/webos/i" => "Mobile"];
        foreach ($os_array as $regex => $value) {
            if(preg_match($regex, $user_agent)) {
                $os_platform = $value;
            }
        }
        return $os_platform;
    }
    public function index()
    {
        global $aInt;
        global $page;
        global $numrows;
        global $limit;
        // PHASE 3.6D (2026-08-24): the smallest safe DCTLAB presentation
        // integration for an AdminInterface-driven page — everything
        // between here and the matching ob_get_clean() below is 100%
        // UNCHANGED from the pre-3.6D controller (same $aInt calls, same
        // global $page/$numrows/$limit reads/writes, same queries, same
        // search form, same sortableTable() call). Nothing about
        // sorting/pagination/search/delete is reimplemented — this only
        // captures the exact HTML $aInt already produces and places it
        // inside the shared page header (title/description) + asset
        // load every other migrated controller already uses. See this
        // file's own investigation notes / the Phase 3.6D report for the
        // one disclosed side effect: the shared .sp-page wrapper sets an
        // inherited font-size:13px/color:#333, which now also applies to
        // this captured markup (previously it inherited the WHMCS admin
        // theme's own default table typography instead).
        ob_start();
        echo $aInt->beginAdminTabs([$aInt->lang("global", "searchfilter")]);
        echo "        <style>\r\n            #sortabletbl1 td {\r\n                text-align: center;\r\n            }\r\n        </style>\r\n        <form action=\"\" method=\"post\">\r\n            <input type=\"hidden\" name=\"search\" value=\"1\">\r\n            <table class=\"form\" width=\"100%\" border=\"0\" cellspacing=\"2\" cellpadding=\"3\">\r\n                <tbody>\r\n                <tr>\r\n                    <td class=\"fieldlabel\">Client:</td>\r\n                    <td class=\"fieldarea\">";
        echo $aInt->clientsDropDown(isset($_REQUEST["userid"]) ? $_REQUEST["userid"] : 0);
        echo "                    </td>\r\n                </tr>\r\n                <tr>\r\n                    <td class=\"fieldlabel\">IP Address:</td>\r\n                    <td class=\"fieldarea\"><input type=\"text\" class=\"form-control\" name=\"ip_address\"\r\n                                                 value=\"";
        // Security Pack 2.2 audit fix: this was echoing the raw
        // $_REQUEST["ip_address"] search value straight into an HTML
        // attribute with no escaping — a reflected-XSS vector via
        // ?module=security_pack&c=LoginLogs&a=index&ip_address=" onmouseover=... or
        // a value containing "><script>. Escape it like every other
        // admin-controller output in this module.
        echo htmlspecialchars(isset($_REQUEST["ip_address"]) ? (string) $_REQUEST["ip_address"] : "", ENT_QUOTES, "UTF-8");
        echo "\">\r\n                    </td>\r\n                </tr>\r\n                </tbody>\r\n            </table>\r\n            <div class=\"btn-container\">\r\n                <input type=\"submit\" value=\"Search\" class=\"btn btn-default\">\r\n            </div>\r\n        </form>\r\n        ";
        echo $aInt->endAdminTabs();
        $aInt->sortableTableInit("id");
        $numrows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->count();
        $limit = $aInt->rowLimit;
        $records = $page * $limit;
        $tabledata = [];
        // Phase 4 QA fix: this was "?module=security_pack&&deleteid="
        // (missing "&c=loginLogs", plus a stray double-ampersand) — a
        // delete redirected the admin to the DashboardController default
        // instead of back to Login History. The sibling
        // IpLimitedClientsController::index() already uses the correct
        // "&c=ipLimitedClients&deleteid=" form; matched to that same
        // pattern here. Delete behavior itself (native WHMCS
        // AdminInterface deleteJSConfirm()/deleteid handling) is
        // completely unchanged — only the post-delete redirect target.
        $aInt->deleteJSConfirm("doDelete", "global", "deleteconfirm", "?module=security_pack&c=loginLogs&deleteid=");
        $result = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->skip($records)->take($limit)->orderBy("id", "DESC");
        if(isset($_REQUEST["userid"]) && $_REQUEST["userid"]) {
            $result = $result->where("client_id", $_REQUEST["userid"]);
        }
        if(isset($_REQUEST["ip_address"]) && $_REQUEST["ip_address"]) {
            $result = $result->where("ip", "LIKE", "%" . $_REQUEST["ip_address"] . "%");
        }
        $result = $result->get();
        $admins = \Illuminate\Database\Capsule\Manager::table("tbladmins")->select("id", "firstname", "lastname")->get();
        $admins_data = [];
        foreach ($admins as $admin) {
            $admins_data[$admin->id] = "Admin - " . $admin->firstname . " " . $admin->lastname;
        }
        foreach ($result as $data) {
            $tabledata[] = [$data->is_admin ? $admins_data[$data->client_id] : $aInt->outputClientLink($data->client_id), $data->ip, $this->getOS($data->browser), $this->getBrowser($data->browser), fromMySQLDate($data->logged_at, true)];
        }
        echo $aInt->sortableTable(["Client/Admin", "IP Address", "OS", "Browser", "Logged At"], $tabledata);
        $capturedContent = ob_get_clean();

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Login History",
            "pageDescription" => "Client and administrator login history collected by DCTLAB Security Pack.",
            "pageActionsHtml" => "",
            "content" => $capturedContent,
        ]);
    }

    /**
     * NOT wrapped — this is the bare-fragment action embedded inside the
     * WHMCS client-profile "Login History" tab pane (it's the one entry
     * in security_pack.php's $bareOutputActions, so it deliberately
     * never gets the NNM_Page_Builder header()/footer() panel either).
     * Adding our own page-title/description/nav shell inside an already-
     * embedded tab pane would nest one page's chrome inside another and
     * visually break that tab — left completely untouched.
     */
    public function user()
    {
        global $aInt;
        global $page;
        global $numrows;
        global $limit;
        if(!isset($_REQUEST["userid"])) {
            // Phase 4 QA fix: this was "module=security_pack" with no
            // "&c=", which per security_pack.php's own router falls back
            // to the DashboardController default — sending an admin who
            // hits this bare fragment without a userid to the Overview
            // page instead of back to Login History. Same class of bug
            // already fixed on the sibling IpLimitedClientsController's
            // delete redirect (see index()/user()'s deleteJSConfirm()
            // calls below) — matched to the same "&c=loginLogs" pattern.
            redir("module=security_pack&c=loginLogs", "addonmodules.php");
        }
        $aInt->setClientsProfilePresets($_REQUEST["userid"]);
        echo "        <style>\r\n            #sortabletbl1 td {\r\n                text-align: center;\r\n            }\r\n        </style>\r\n        ";
        $aInt->sortableTableInit("id");
        $numrows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("client_id", $_REQUEST["userid"])->count();
        $limit = $aInt->rowLimit;
        $records = $page * $limit;
        $tabledata = [];
        // Phase 4 QA fix: this was "?module=security_pack&&deleteid="
        // (missing "&c=loginLogs", plus a stray double-ampersand) — a
        // delete redirected the admin to the DashboardController default
        // instead of back to Login History. The sibling
        // IpLimitedClientsController::index() already uses the correct
        // "&c=ipLimitedClients&deleteid=" form; matched to that same
        // pattern here. Delete behavior itself (native WHMCS
        // AdminInterface deleteJSConfirm()/deleteid handling) is
        // completely unchanged — only the post-delete redirect target.
        $aInt->deleteJSConfirm("doDelete", "global", "deleteconfirm", "?module=security_pack&c=loginLogs&deleteid=");
        $result = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("client_id", $_REQUEST["userid"])->skip($records)->take($limit)->orderBy("id", "DESC");
        $result = $result->get();
        foreach ($result as $data) {
            $tabledata[] = [$data->ip, $this->getOS($data->browser), $this->getBrowser($data->browser), fromMySQLDate($data->logged_at, true)];
        }
        echo $aInt->sortableTable(["IP Address", "OS", "Browser", "Logged At"], $tabledata);
    }
}

?>