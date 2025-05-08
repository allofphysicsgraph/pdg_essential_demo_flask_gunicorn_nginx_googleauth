#!/usr/bin/env python3
# Ben Payne
# Physics Derivation Graph
# https://allofphysics.com
# Creative Commons Attribution 4.0 International License
# https://creativecommons.org/licenses/by/4.0/

from flask import Flask, render_template


web_app = Flask(__name__, static_folder="static")
web_app.config["DEBUG"] = True



@web_app.route('/', methods=['GET', 'POST'])
def index():
    # https://flask.palletsprojects.com/en/stable/quickstart/#rendering-templates
    return render_template("hello.html")


if __name__ == '__main__':
    web_app.run(debug=True, host="0.0.0.0", ssl_context=('cert.pem', 'key.pem'))

#EOF
