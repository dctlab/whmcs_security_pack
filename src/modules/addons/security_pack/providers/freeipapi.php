<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class freeipapi
{
    public function info()
    {
        return ["name" => "freeipapi.com", "description" => "Free, Fast and Reliable IP Geolocation API.", "website" => "https://freeipapi.com/"];
    }
    public function getDetails($ip = "")
    {
        $data = curlCall("https://freeipapi.com/api/json/" . $ip, []);
        if($data) {
            $data = json_decode($data, true);
            if(is_array($data) && isset($data["countryCode"]) && $data["countryCode"]) {
                return $data["countryCode"];
            }
        }
        return "";
    }
}

?>