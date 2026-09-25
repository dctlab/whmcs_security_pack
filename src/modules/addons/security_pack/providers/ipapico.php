<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class ipapico
{
    public function info()
    {
        return ["name" => "ipapi.co", "description" => "Free IP Geolocation service", "website" => "https://ipapi.co/"];
    }
    public function getDetails($ip = "")
    {
        $data = curlCall("https://ipapi.co/" . $ip . "/country_code/", []);
        if($data) {
            return $data;
        }
        return "";
    }
}

?>