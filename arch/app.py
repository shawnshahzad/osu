import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, request, make_response, redirect, render_template, session, url_for
from functools import wraps
application = Flask(__name__)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

application.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(application)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    # authorize_url =f'https://{env.get("AUTH0_DOMAIN")}/authorize',
    # access_token_url=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token',
    # api_base_url=f'https://{env.get("AUTH0_DOMAIN")}'
    server_metadata_url = f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


@application.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@application.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@application.route("/logout")
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


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # auth = request.authorization
        # if auth and auth.username == "username" and auth.password == "password":
        #     return f(*args, **kwargs)
        # return make_response("Wrong Auth!", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'}
        user = session.get('user')
        if user:
            return f(*args, **kwargs)
        return redirect(url_for("login", _external=True))
    return decorated


@application.route("/")
def home():
    user = session.get('user')
    if user:
        # print(json.dumps(user["userinfo"], sort_keys=False, indent=4))
        return "Hello World, " + user["userinfo"]["name"] + "!"
    else:
        return "Hello World, Mrs. Anonymous!"


@application.route("/public")
def public():
    return "A public endpoint"


@application.route("/private")
@auth_required
def private():
    return "A private endpoint"


# @app.route("/login")
# def login():
#     auth = request.authorization
#
#     if auth and auth.username == "username" and auth.password == "password":
#         return "logged in"
#     return make_response("Wrong Auth!",401,{"WWW-Authenticate" : 'Basic realm="Login Required"'})
#

if __name__ == "__main__":
    application.run()
