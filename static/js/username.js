
var userElement = document.getElementsByClassName("nameh2")[0]

if (document.cookie.length > 0) {
    fetch("/authtoken/",{
        method:"POST",
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            token:document.cookie.split("=")[1]
        })
    }).then(res => {
        if (!res.ok){
            throw Error(res.status)
        }
        return res.json()
    }).then(data => {
        userElement = document.getElementsByClassName("nameh2")
        if (userElement && data.exists) {
            userElement[0].innerHTML = data.name
        }
    })
}

