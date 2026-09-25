<?php

declare(strict_types=1);

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
add_hook("ClientAreaHeaderOutput", 1, function ($vars) {
    $settings = security_pack_settings();
    if(isset($settings["iframe"])) {
        header("X-Frame-Options: SAMEORIGIN");
    }
});
add_hook("ClientAreaFooterOutput", 1, function ($vars) {
    if(isset($_SESSION["adminid"])) {
        return "";
    }
    $settings = security_pack_settings();
    if(isset($settings["right_click"]) || isset($settings["right_click"])) {
        global $CONFIG;
        $main_language = Lang::getName();
        if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
        }
        $codes = "";
        if(isset($settings["right_click"])) {
            $error = $_ADDONLANG["right_click_error"];
            $codes = "<script type=\"text/javascript\">\r\ndocument.addEventListener('contextmenu', function(e) {\r\n    e.preventDefault();\r\n    alert('" . $error . "');    \r\n}, false);\r\n</script>";
        }
        if(isset($settings["copy_paste"])) {
            $error = $_ADDONLANG["copy_paste_disabled"];
            $codes .= "<script type=\"text/javascript\">\r\ndocument.addEventListener('copy', function(e) {\r\n    e.preventDefault();\r\n    alert('" . $error . "');\r\n});\r\ndocument.addEventListener('paste', function(e) {\r\n    e.preventDefault();\r\n    alert('" . $error . "');\r\n});\r\n</script>";
        }
        return $codes;
    }
});
