$(document).ready(function () {
    if ($('.client-tabs:first').length) {
        $('.client-tabs:first').append('<li class="tab ' + security_pack_active + '"><a href="addonmodules.php?module=security_pack&c=LoginLogs&a=user&userid=' + security_pack_userid + '" id="clientTab-1001">Login History</a></li>');
    }
});