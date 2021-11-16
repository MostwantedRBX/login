function signup() {
    var uname = document.getElementById("signupuname").value, pass = document.getElementById("signuppass").value;

    const data = {
        "username":uname,
        "password":pass,
    };
    fetch('/signup/', {
        method: 'POST', // or 'PUT'
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      }).then(res => {window.location.reload()})
}