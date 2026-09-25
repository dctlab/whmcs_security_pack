<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class geojsio
{
    public function info()
    {
        return ["name" => "geojs.io", "description" => "Highly available REST/JSON/JSONP IP Geolocation lookup API ", "website" => "https://freeipapi.com/"];
    }
    public function getDetails($ip = "")
    {
        $data = curlCall("https://get.geojs.io/v1/ip/geo/" . $ip . ".json", []);
        if($data) {
            $data = json_decode($data, true);
            if(is_array($data) && isset($data["country_code"]) && $data["country_code"]) {
                return $data["country_code"];
            }
        }
        return "";
    }
}

?>