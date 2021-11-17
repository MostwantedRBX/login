
//  wait for the page to be fully loaded before executing
document.addEventListener('DOMContentLoaded', function() {
    //  get the first occurrence of "nameh2"
    var userElement = document.getElementsByClassName("nameh2")[0]

    //  if the cookie isn't empty
    if (document.cookie.length > 0) {

        //  send a request to the server to get user-data from a token
        fetch("/authtoken/",{
            method:"POST",
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                //  get loginToken from the cookies
                token:document.cookie.split("=")[1]
            })
        }).then(res => {
            //  if the response is a bad one, throw an error
            if (!res.ok){
                throw Error(res.status)
            }
            return res.json()
        }).then(data => {
            userElement = document.getElementsByClassName("nameh2")
            if (userElement && data.exists) {
                //  add the username to "nameh2"
                userElement[0].innerHTML = data.name
            }
        })
    } else if (document.cookie.length <= 0){
        //  get and hide the logout button if you aren't logged in
        var a = document.getElementById("logout-button");
        a.style.opacity = 0;
    }
}, false);
