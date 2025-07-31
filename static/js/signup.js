document.getElementById("signup-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const form = e.target;
    const body = {
        username: form.username.value,
        password: form.password.value
    };
    const res = await fetch("/signup", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
    });

    if (res.status === 201) {
        window.location.href = "/login";
    } else {
        alert("Signup failed.");
    }
});
