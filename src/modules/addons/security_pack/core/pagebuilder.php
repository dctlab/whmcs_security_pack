<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class NNM_Page_Builder
{
    public $modulename = "";
    public $modulelink = "";
    public $helplink = "";
    public $langtablename = "";
    public $havemultaddon_lang = false;
    public $menu = [];

    /**
     * Security Pack 2.3 — Security Center navigation groups.
     *
     * Maps a group label (e.g. "Protection") to an ordered array of
     * $this->menu keys that belong under it. Any $this->menu item NOT
     * listed in any group still renders as a plain top-level link
     * (nothing silently disappears if a future menu item forgets to be
     * grouped). This does NOT change routing at all — every item's
     * "href"/"address" is exactly what it always was, so every existing
     * ?module=security_pack&c=... URL keeps working unchanged; only how
     * the links are visually organized changes (Step 2/3 of the 2.3
     * spec: nested navigation without touching the underlying WHMCS
     * admin framework or breaking bookmarks).
     */
    public $menuGroups = [];

    public function __construct()
    {
    }
    public function startlang()
    {
        if(isset($_REQUEST["getlang"]) && $_REQUEST["getlang"] != "") {
            $this->getlang();
        }
        if(isset($_REQUEST["savelang"]) && $_REQUEST["savelang"] != "") {
            $this->savelang();
        }
    }
    public function getlang()
    {
        global $aInt;
        $aInt->content = "";
        $langinputs = "";
        global $CONFIG;
        $name = $_REQUEST["getlang"];
        $existval = [];
        $existvals = Illuminate\Database\Capsule\Manager::table($this->langtablename)->where("setting", $name . "_lang")->value("values");
        if($existvals != "") {
            $existval = json_decode($existvals, true) ?: [];
        }
        foreach (WHMCS\Language\ClientLanguage::getLanguages() as $lang) {
            if($lang == $CONFIG["Language"]) {
            } else {
                $input = "<input type=\"text\" name=\"" . $lang . "\" class=\"form-control input-sm\" value=\"" . ($existval[$lang] != "" ? $existval[$lang] : "") . "\">";
                if(isset($_REQUEST["outtype"]) && $_REQUEST["outtype"] == "textarea") {
                    $input = "<textarea name=\"" . $lang . "\" class=\"form-control input-sm\">" . ($existval[$lang] != "" ? $existval[$lang] : "") . "</textarea>";
                }
                $langinputs .= "<div class=\"col-md-4 col-sm-6 bottom-margin-5\">\r\n        " . ucfirst($lang) . "<br>\r\n            " . $input . "\r\n    </div>";
            }
        }
        $orgval = $_REQUEST["origvalue"];
        if($orgval == "undefined") {
            $orgval = "";
        }
        $input = "<input type=\"text\" name=\"this_will_not_save\" disabled=\"disabled\" class=\"form-control input-sm\" value=\"" . $orgval . "\">";
        if(isset($_REQUEST["outtype"]) && $_REQUEST["outtype"] == "textarea") {
            $input = "<textarea disabled=\"disabled\" name=\"this_will_not_save\" class=\"form-control input-sm\">" . $orgval . "</textarea>";
        }
        $aInt->setBodyContent(["body" => "<form method=\"post\" action=\"?module=ageverification&savelang=" . $_REQUEST["getlang"] . "\" class=\"form\">\r\n    <p class=\"font-size-sm\">Localise the value of the selected field below. Leave a field empty to use the default value for that language.</p>\r\n    <div class=\"row\">\r\n        <div class=\"col-sm-10 col-sm-offset-1\">\r\n            <div class=\"panel panel-info font-size-sm translate-value\">\r\n                <div class=\"panel-heading\">Default Value</div>\r\n                <div class=\"panel-body\">\r\n                    " . $input . "\r\n                </div>\r\n            </div>\r\n        </div>\r\n    </div>\r\n    <div class=\"row font-size-sm\">\r\n            " . $langinputs . "\r\n    </div>\r\n</form>"]);
        $aInt->output();
        WHMCS\Terminus::getInstance()->doExit();
    }
    public function savelang()
    {
        global $aInt;
        global $CONFIG;
        $aInt->content = "";
        $savearray = [];
        foreach (WHMCS\Language\ClientLanguage::getLanguages() as $lang) {
            if($lang == $CONFIG["Language"]) {
            } elseif(isset($_REQUEST[$lang]) && $_REQUEST[$lang] != "") {
                $savearray[$lang] = $_REQUEST[$lang];
            }
        }
        $name = $_REQUEST["savelang"];
        Illuminate\Database\Capsule\Manager::table($this->langtablename)->updateOrInsert(["setting" => $name . "_lang"], ["setting" => $name . "_lang", "values" => json_encode($savearray)]);
        $aInt->setBodyContent(["dismiss" => true, "successMsgTitle" => "Success!", "successMsg" => "Your changes have been saved."]);
        $aInt->output();
        WHMCS\Terminus::getInstance()->doExit();
    }
    public function menu()
    {
        // Navigation-wiring phase (2026-08-24): the nav item list
        // (previously $this->menulist(), which dispatched to
        // menulistFlat()/menulistGrouped() below) is now rendered by the
        // DCTLAB templates/admin/navigation.tpl component via the same
        // TemplateRenderer every migrated controller already uses.
        // navigation.tpl consumes the SAME $this->menu / $this->menuGroups
        // data (identical shape) and replicates the exact href-building
        // convention ("addonmodules.php?module={modulelink}&{href}"),
        // active-state comparison against $_REQUEST["c"], grouped-dropdown
        // rendering, and single-item-group flattening that
        // menulistFlat()/menulistGrouped() implement below — see
        // navigation.tpl's own docblock. Nothing about $this->menu /
        // $this->menuGroups themselves (populated in security_pack.php) is
        // touched here, so every route/href/address/label/conditional
        // visibility is unchanged. menulistFlat()/menulistGrouped() are
        // intentionally left in place, unused, as a reference/rollback
        // point.
        //
        // istab/target/class per-item variants that menulistFlat() also
        // handles are not reproduced in navigation.tpl because no
        // security_pack.php menu entry sets them (all entries are
        // href/address/istab=false/external=false) — verified by
        // inspection, not assumed.
        $activeAddress = isset($_REQUEST["c"]) ? $_REQUEST["c"] : "";
        $navHtml = \WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer::render("navigation", [
            "menu" => $this->menu,
            "menuGroups" => $this->menuGroups,
            "modulelink" => $this->modulelink,
            "activeAddress" => $activeAddress,
        ]);
        return "<nav class=\"navbar navbar-default nnmnavbar\">\r\n      <div class=\"nnmcontainer\">\r\n        <!-- Brand and toggle get grouped for better mobile display -->\r\n        <div class=\"navbar-header\">\r\n          <button type=\"button\" class=\"navbar-toggle collapsed\" data-toggle=\"collapse\" data-target=\"#navbar-collapse-1\">\r\n            <span class=\"sr-only\">Toggle navigation</span>\r\n            <span class=\"icon-bar\"></span>\r\n            <span class=\"icon-bar\"></span>\r\n            <span class=\"icon-bar\"></span>\r\n          </button>\r\n          <a class=\"navbar-brand\" href=\"#\">" . $this->modulename . "</a>\r\n        </div>\r\n\r\n        <!-- Collect the nav links, forms, and other content for toggling -->\r\n        <div class=\"collapse navbar-collapse\" id=\"navbar-collapse-1\">\r\n          " . $navHtml . "\r\n          <ul class=\"nav navbar-nav navbar-right\">\r\n          <li><a target=\"_blank\" href=\"" . $this->helplink . "\"><i class=\"fa fa-question-circle\" aria-hidden=\"true\"></i> Help</a></li>\r\n          </ul>\r\n        </div><!-- /.navbar-collapse -->\r\n      </div><!-- /.container -->\r\n    </nav><!-- /.navbar -->";
    }
    /**
     * NOT CALLED from menu() as of the navigation-wiring phase
     * (2026-08-24) — menu() now renders templates/admin/navigation.tpl
     * instead. Left in place, unused, as the exact pre-wiring reference
     * implementation / rollback point; still public in case any external
     * code happens to call it directly.
     */
    public function menulist()
    {
        if(count($this->menuGroups)) {
            return $this->menulistGrouped();
        }
        return $this->menulistFlat($this->menu);
    }

    /**
     * Original flat rendering — unchanged behaviour, still used verbatim
     * for any item that isn't part of a group, and as the fallback if no
     * groups are configured at all. NOT CALLED from menu() as of the
     * navigation-wiring phase (2026-08-24) — see menulist()'s docblock.
     */
    private function menulistFlat($items)
    {
        $menu = "";
        if(count($items)) {
            $i = 1;
            foreach ($items as $mkey => $mvalue) {
                $active = "";
                if(!$mvalue["target"]) {
                    if($mvalue["href"] != "") {
                        $mvalue["href"] = "addonmodules.php?module=" . $this->modulelink . "&" . $mvalue["href"];
                        if(isset($_REQUEST["c"]) && $_REQUEST["c"] == $mvalue["address"]) {
                            $active = "active";
                        }
                    } else {
                        $mvalue["href"] = "addonmodules.php?module=" . $this->modulelink;
                        if(!isset($_REQUEST["c"])) {
                            $active = "active";
                        }
                    }
                }
                $tab = "";
                if($mvalue["istab"]) {
                    $tab = "  role=\"tab\" data-toggle=\"tab\" id=\"tabLink" . $i . "\" aria-expanded=\"true\"";
                    if($i == 1) {
                        $active = "active";
                    }
                }
                $menu .= "<li class=\"" . $active . "\"><a href=\"" . $mvalue["href"] . "\" " . (isset($mvalue["class"]) ? "class=\"" . $mvalue["class"] . "\"" : "") . " " . ($mvalue["target"] ? "target=\"_blank\"" : "") . $tab . ">" . $mkey . "</a></li>";
                $i++;
            }
        }
        return $menu;
    }

    /**
     * Security Pack 2.3 — grouped rendering: each configured group
     * becomes a Bootstrap 3 dropdown (the same dropdown component WHMCS's
     * own admin theme already uses elsewhere, so no new CSS/JS framework
     * is introduced and the existing navbar-toggle mobile collapse
     * continues to work unchanged). A group whose current page is active
     * gets an "active" class on the dropdown toggle itself, so the
     * current SECTION is visually clear even when the dropdown is
     * closed — not just the current page.
     */
    private function menulistGrouped()
    {
        $grouped = [];
        foreach ($this->menuGroups as $items) {
            foreach ($items as $key) {
                $grouped[$key] = true;
            }
        }

        $html = "";
        foreach ($this->menuGroups as $groupLabel => $keys) {
            $items = [];
            $groupActive = false;
            foreach ($keys as $key) {
                if(!isset($this->menu[$key])) {
                    continue;
                }
                $items[$key] = $this->menu[$key];
                $mvalue = $this->menu[$key];
                $address = $mvalue["address"] ?? "";
                if(($address === "" && !isset($_REQUEST["c"])) || (isset($_REQUEST["c"]) && $_REQUEST["c"] === $address)) {
                    $groupActive = true;
                }
            }
            if(!$items) {
                continue;
            }
            if(count($items) === 1) {
                // A single-item group doesn't need a dropdown — render it
                // as a plain top-level link instead.
                $html .= $this->menulistFlat($items);
                continue;
            }
            $html .= "<li class=\"dropdown" . ($groupActive ? " active" : "") . "\">"
                . "<a href=\"#\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" role=\"button\" aria-haspopup=\"true\" aria-expanded=\"false\">"
                . htmlspecialchars($groupLabel, ENT_QUOTES, "UTF-8") . " <span class=\"caret\"></span></a>"
                . "<ul class=\"dropdown-menu\">" . $this->menulistFlat($items) . "</ul>"
                . "</li>";
        }

        // Anything not explicitly grouped still renders as a plain
        // top-level link — nothing added to $this->menu in the future
        // can silently vanish just because it wasn't grouped.
        $ungrouped = [];
        foreach ($this->menu as $key => $value) {
            if(!isset($grouped[$key])) {
                $ungrouped[$key] = $value;
            }
        }
        $html .= $this->menulistFlat($ungrouped);

        return $html;
    }
    public function header()
    {
        echo "<div class=\"row\">\r\n        <div class=\"col-md-12\">\r\n            <div class=\"panel panel-default\">\r\n                <div class=\"panel-heading nnmheader\">\r\n                    " . $this->menu() . "\r\n                </div>\r\n                <div class=\"panel-body\">";
    }
    public function footer()
    {
        echo "</div>\r\n                <div class=\"panel-footer\">\r\n                    <div class=\"row\">\r\n                        <div class=\"col-md-12 text-center\">\r\n                            <p class=\"nnmcopyright\">Copyright <a target=\"_blank\" href=\"https://dctlab.directcybertech.com\">DCTLAB</a> - " . date("Y") . "</a></p>\r\n                        </div>\r\n                    </div>\r\n                </div>\r\n            </div>\r\n        </div>\r\n    </div>";
    }
    public function generateTranslateButton($name = "", $title = "")
    {
        return "<a id=\"translate" . $name . "\" href=\"addonmodules.php?module=" . $this->modulelink . "&getlang=" . $name . "\" class=\"btn btn-default btn-translate btn-nnmtranslate\" data-modal-title=\"Translate " . $title . "\"><i class=\"fas fa-edit\"></i> Translate</a>";
    }
}

?>