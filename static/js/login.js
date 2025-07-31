document.getElementById("login-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const form = e.target;
    const body = {
        username: form.username.value,
        password: form.password.value
    };

    const res = await fetch("/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
    });

    if (res.ok) {
        window.location.href = "/home";
    } else {
        alert("Login failed. Please check your credentials.");
    }
});
