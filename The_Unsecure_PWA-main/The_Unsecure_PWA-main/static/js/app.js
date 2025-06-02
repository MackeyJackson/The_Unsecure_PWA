if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker
        .register("static/js/serviceWorker.js")
        .then((res) => console.log("service worker registered"))
        .catch((err) => console.log("service worker not registered", err));
    });
  }
function showErrorMessage(message) {
    const errorDiv = document.querySelector('.error');
    errorDiv.innerText = message;
    errorDiv.style.visibility = 'visible'; 

    setTimeout(function() {
        errorDiv.style.visibility = 'hidden';
    }, 2500);
}
//
if (window.location.pathname === "/2fa") {
  document.querySelector(".faa").addEventListener("submit", async function (e) {
    e.preventDefault(); // Prevent normal form submission

    const formData = new FormData(document.querySelector(".faa"));

    try {
      const response = await fetch("/2fa", {
        method: "POST",
        body: formData
      });

      if (response.redirected) {
        window.location.href = response.url;
        return;
      }

      // Attempt to read JSON error response
      const contentType = response.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        const result = await response.json();

        if (response.ok) {
          console.log("2FA successful, proceed to next steps");
        } else {
          showErrorMessage(result.error);
          if (result.csrf_token) {
            document.querySelector("input[name='csrf_token']").value = result.csrf_token;
          }
        }
      } else {
        // Otherwise treat it as HTML (successful page)
        const text = await response.text();
        document.body.innerHTML = text;
      }
    } catch (error) {
      console.error("Error submitting the 2FA form:", error);
      showErrorMessage("An error occurred while submitting the 2FA form.");
    }
  });
}
if (window.location.pathname === "/success") {
  document.querySelectorAll(".cmnt").forEach(form => {
    form.addEventListener("submit", async function (e) {
      e.preventDefault(); // Prevent normal form submission

    const formData = new FormData(form);

    try {
      const response = await fetch("/success", {
        method: "POST",
        body: formData
      });

      if (response.redirected) {
        window.location.href = response.url;
        return;
      }

      // Attempt to read JSON error response
      const contentType = response.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        const result = await response.json();

        if (response.ok) {
          console.log("2FA successful, proceed to next steps");
        } else {
          showErrorMessage(result.error);
          if (result.csrf_token) {
            document.querySelectorAll("input[name='csrf_token']").forEach(input => {
              input.value = result.csrf_token;
            });
          }
        }
      } else {
        // Otherwise treat it as HTML (successful page)
        const text = await response.text();
        document.body.innerHTML = text;
      }
    } catch (error) {
      console.error("Invalid Comment", error);
      showErrorMessage("Invalid comment");
    }
  });
})};
//

const currentPage = window.location.pathname;

document.querySelector(".box").addEventListener("submit", async function (e) {
    e.preventDefault(); // Stop form submit
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    if (currentPage === "/signup") {
      const email = document.getElementById("email").value;
      const EmailError = checkEmail(email);
      if (EmailError) {
        showErrorMessage(EmailError)
        return; // Stop if there's an error
      }
    }


    // username
    const usernameError = validateUsername(username);
    if (usernameError) {
        if (currentPage === "/signup") {
          showErrorMessage(usernameError)
          return;
        }
        showErrorMessage("Incorrect Username or Password")
        return; // Stop if there's an error
    }
    // password
    const passwordError = validatePassword(password);
    if (passwordError) {
        if (currentPage === "/signup") {
          showErrorMessage(passwordError)
          return;
        }
        showErrorMessage("Incorrect Username or Password")
        return;
    }
    const formData = new FormData(document.querySelector(".box"));
    //end of client side errors - submits to server
    try {
      const response = await fetch(currentPage, {
        method: "POST",
        body: formData
      });
      if (response.redirected) { //lets html responses
        window.location.href = response.url;
        return;
      }
      
      const result = await response.json(); // only accepts json (error messages)
      if (response.ok) {
          console.log("Login successful, proceed to next steps");
      } else {
          showErrorMessage(result.error)
          if (result.csrf_token) {
            // Update the CSRF token in the form if it's provided
            document.querySelector("input[name='csrf_token']").value = result.csrf_token;
          }
      }
      } catch (error) {
        console.error("Error submitting the form:", error);
        showErrorMessage("An error occurred while submitting the form.");
    }
});

//client side error check
function checkEmail(email) {
    const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
    const safeCharRegex = /^[a-zA-Z0-9._\-@]+$/;

    if (!emailRegex.test(email)) {
        return "Invalid Email Address";
    }

    if (!safeCharRegex.test(email)) {
        return "Invalid Email Address";
    }
    return;
}

function validatePassword(password) {
  //return
    const specialCharacters = "@$!%*?&";
    if (password.length < 8 || password.length > 20) {
        return "Password must be between 8 and 20 characters";
    }
    if (password.includes(" ")) {
        return "Password cannot contain spaces";
    }
    if (!/[a-z]/.test(password)) {
        return "Password must contain at least one lowercase letter (a–z)";
    }
    if (!/[A-Z]/.test(password)) {
        return "Password must contain at least one uppercase letter (A–Z)";
    }
    if (!/[@$!%*?&]/.test(password)) {
        return "Password must contain at least one special character (@$!%*?&)";
    }
    if (!/\d/.test(password)) {
        return "Password must contain at least one number (0-9)";
    }
    if (!/^[a-zA-Z0-9@$!%*?&]+$/.test(password)) {
        return "Password can only contain letters, numbers and special characters (@$!%*?&)";
    }
    return;
}

function validateUsername(username) {
  //return
    username = username.trim();
    if (username.length < 4 || username.length > 15) {
        return "Username must be between 4 and 15 characters";
    }
    if (!/^[a-zA-Z0-9._]+$/.test(username)) {
        return "Username can only contain letters, numbers, dots, and underscores";
    }
    if (username[0] === '.' || username[0] === '_' || username[username.length - 1] === '.' || username[username.length - 1] === '_') {
        return "Username cannot start or end with a special character";
    }

    return;
}
//2fA
