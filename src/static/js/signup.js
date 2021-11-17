function signup() {
  //  get the user data from the html form.
  var uname = document.getElementById("signupuname").value, pass = document.getElementById("signuppass").value;

  //  json data
  const data = {
    "username":uname,
    "password":pass,
  };

  //  send a fetch request to server to signup the user
  fetch('/signup/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
    })
    .then(res => {window.location.reload()})
}