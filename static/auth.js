const auth0 = new window.auth0.Auth0Client({
    domain: 'michael-demo.cic-demo-platform.auth0app.com',
    clientId: 'AQZPoptX8wieik7S4cNUnDZIjXgtzxLM',
    authorizationParams: {
        redirect_uri: 'http://127.0.0.1:3000/pkce-callback'
    }
});

window.addEventListener("DOMContentLoaded", (event) => {
    const el = document.getElementById('login');
    if (el) {
        el.addEventListener('click', async () => {
            await auth0.loginWithRedirect();
        });
    }
});


window.addEventListener('load', async () => {
    if (window.location.search.includes("state=") && window.location.search.includes("code=") || window.location.search.includes("error=")) {
        await auth0.handleRedirectCallback();

        //logged in. you can get the user profile like this:
        const user = await auth0.getUser();
        console.log(user)
    }
});