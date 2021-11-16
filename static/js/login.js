function login() {
    var uname = document.getElementById("loginuname").value, pass = document.getElementById("loginpass").value;

    const data = {
        "username":uname,
        "password":pass,
    };
    fetch('/login/', {
        method: 'POST', // or 'PUT'
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      })
}
