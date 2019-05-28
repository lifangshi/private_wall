$(document).ready(function(){

    $('#usersearch').keyup(function(){
        var data = $("#search").serialize()
        $.ajax({
            method: "GET",
            url: "/usersearch",
            data: data
        })
        .done(function(res){
             $('#usersearchMsg').html(res)
        })
    })

    $('#username').keyup(function(){
        var data = $("#regForm").serialize()
        $.ajax({
            method: "POST",
            url: "/check_username",
            data: data
        })
        .done(function(res){
             $('#usernameMsg').html(res)
        })
    })

})
