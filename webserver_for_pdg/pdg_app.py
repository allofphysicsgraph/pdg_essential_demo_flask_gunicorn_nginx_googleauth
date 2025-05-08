#!/usr/bin/env python3
# Ben Payne
# Physics Derivation Graph
# https://allofphysics.com
# Creative Commons Attribution 4.0 International License
# https://creativecommons.org/licenses/by/4.0/

# Python standard libraries
import json
import os
import sqlite3

# Third-party libraries
from flask import Flask, render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# for google auth
from google_auth_sql_db import init_db_command
from google_auth_user import User

# Configuration for google auth
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

web_app = Flask(__name__, static_folder="static")
web_app.config["DEBUG"] = True

web_app.secret_key = os.environ.get("SECRET_KEY") # for googleauth

# User session management setup for google auth
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(web_app)

# Naive database setup for googleauth
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# OAuth 2 client setup for google auth
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from local db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@web_app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@web_app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@web_app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")


@web_app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def OLDindex():
    # https://flask.palletsprojects.com/en/stable/quickstart/#rendering-templates
    return render_template("hello.html")


if __name__ == '__main__':
    web_app.run(debug=True, host="0.0.0.0", ssl_context=('cert.pem', 'key.pem'))

#EOF
