
var timeout = 15000

$.ajaxSetup({xhrFields:{withCredentials:true}});
var checkCred = function(callback){
    $.ajax({
        type: 'GET',
        dataType: 'json',
        url: check_cred_url,
        timeout: timeout
    }).then(callback)
};

var getAuthUrl = function(callback){
    $.ajax({
        type: 'GET',
        dataType: 'json',
        url: auth_req_url,
        timeout: timeout
    }).then(callback)
};

var postTweet = function(tweet, callback){
    var post_body = new Object;
    post_body.message = tweet;
    $.ajax({
        type: 'POST',
        dataType: 'json',
        url: post_url,
        contentType: "application/json",
        data : JSON.stringify(post_body),
        timeout: timeout
    }).then(callback);
};

function getQueryString(query_str){
    console.log(query_str);
    var items = query_str.slice(1).split('&');
    
    var ret = [];
    for (var i = 0; i < items.length; i++){
        item = items[i].split('=');
        ret[item[0]] = item[1];
    }
    
    return ret;
}
