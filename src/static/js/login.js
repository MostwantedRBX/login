function login() {
  //  get login data from html form
  var uname = document.getElementById("loginuname").value, pass = document.getElementById("loginpass").value;

  //  json data to send to the server
  const data = {
    "username":uname,
    "password":pass,
  };

  //  send login request to the server
  fetch('/login/', {
    method: 'POST', 
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
  .then(res => {window.location.reload()})
}

function logout() {

  //  find browser cookies
  var cookies = document.cookie.split(";");

  // loop over cookies and set the cookies to expire
  for (var i = 0; i < cookies.length; i++) {
      var cookie = cookies[i];
      var eqPos = cookie.indexOf("=");
      var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
  }
  //  refresh the page to log the user out
  window.location.reload()
}