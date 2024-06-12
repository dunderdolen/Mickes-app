import json, requests
from os import environ as env
from urllib.parse import quote_plus, urlencode,urlparse, parse_qs
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, session

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)

app.secret_key = env.get("APP_SECRET_KEY")
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

@app.route("/authorization-code", methods=["GET","POST"])
def authorize_code_flow():
    auth_url                    = request.args.get('auth_url')
    session['token_url']        = request.args.get('token_url')
    session['token_payload']    = request.args.get('token_payload')
    token_headers               = request.args.get('token_headers')
    token                       = request.args.get('token')
    userinfo                    = request.args.get('userinfo')
    formatted_token             = json.dumps(token, sort_keys = True, indent = 4, separators = (',', ': ')) 
    diagram                     = request.args.get('diagram')

    return render_template("authorization-code.html", auth_state=session.get('auth_state'), userinfo=userinfo, diagram=diagram, auth_url=auth_url, token_url=session.get('token_url'), token_payload=session.get('token_payload'), token_headers=token_headers, token=formatted_token)

@app.route("/get_authorize_code_url")
def get_authorize_code_url():
    session['step'] = 1
    auth_url = oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))
    parsed_url = urlparse(auth_url.location)
    query_params = parse_qs(parsed_url.query)
    session['auth_state'] =  query_params.get('state', [None])[0]

    return redirect(url_for("authorize_code_flow", auth_url=auth_url.location))

@app.route("/clear_session")
def clear_session():
    session.clear()
    session['step'] = 1
    return redirect(url_for("authorize_code_flow"))

@app.route("/callback")
def callback():
    session['response_code'] = request.args.get('code')
    session['response_state'] = request.args.get('state')
    session['step'] = 2   
    token_url = f'https://{env.get("AUTH0_DOMAIN")}/oauth/token'
    payload = {
        'grant_type': 'authorization_code',
        'client_id': env.get("AUTH0_CLIENT_ID"),
        'SECRET': 'CANT LIVE IN THE BROWSER',
        'code': session['response_code'],
        'redirect_uri': 'http://localhost:3000/callback'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    session['token_exchange_url'] = url_for('token_exchange',code=session['response_code'], state=session['response_state'])
    return redirect(url_for("authorize_code_flow", token_url=token_url, token_payload=payload, token_headers=headers))    

@app.route("/token_exchange", methods=["GET", "POST"])
def token_exchange():
    token = oauth.auth0.authorize_access_token()
    session['access_token'] = token['access_token']
    session['userinfo'] = token['userinfo']
    session['step'] = 3

    url = "https://api.swimlanes.io/v1/image-link"

    entries = [
        "title: Authorization Code Flow",
        "User -> Regular Web App: (1) Click Login link",
        "Regular Web App -> Auth0: (2) Authorization Code Request to /authorize",
        "Auth0 -> User: (3) Redirect to login/authorization prompt",
        "User -> Auth0 Tenant: (4) Authenticate and Consent (if needed)",
        "Auth0 -> Regular Web app: (5) Authorization code",
        "Regular Web App -> Auth0: (6) Authorization Code for Application Credentials",
        "Auth0 -> Auth0: (7) Validate Authorization Code + Application Credentials",
        "Auth0 -> Regular Web App: (8) ID Token and Access Token",
        "Regular Web App -> Your API: (9) Request user data with Access Token",
        "Your API -> Regular Web App: (10) Response"
    ]
    combined_text = "\n".join(entries)
    data = {
        "text": combined_text
    }
    response = requests.post(url, json=data)
    
    return redirect(url_for("authorize_code_flow", diagram = response.headers.get('Location')))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/")
def home():
    
    return render_template("home.html")

@app.route("/profile")
def profile():  
    return render_template("profile.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000), debug=True)