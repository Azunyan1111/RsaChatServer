from flask import Flask, render_template, request, redirect, url_for
import main
import MyMongoDb
import json
app = Flask(__name__)


@app.route('/get_server_public_key_base64')
def get_server_public_key_base64():
    return main.http_get_server_public_key_base64()


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST' or request.method == 'GET':

        username = request.form['username']
        password = request.form['password']
        public_key_base64 = request.form['public_key_base64']
        terminal_hash = request.form['terminal_hash']

        return main.http_signup(username, password, public_key_base64, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST' or request.method == 'GET':

        username = request.form['username']
        password = request.form['password']
        public_key_base64 = request.form['public_key_base64']
        terminal_hash = request.form['terminal_hash']

        return main.http_signin(username, password, public_key_base64, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/set_friend', methods=['GET', 'POST'])
def set_friend():
    if request.method == 'POST' or request.method == 'GET':

        username = request.form['username']
        friend_username = request.form['friend_username']
        terminal_hash = request.form['terminal_hash']

        return main.http_set_friend(username, friend_username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/get_friend', methods=['GET', 'POST'])
def get_friend():
    if request.method == 'POST' or request.method == 'GET':

        username = request.form['username']
        terminal_hash = request.form['terminal_hash']

        return main.http_get_friend(username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


if __name__ == '__main__':
    main.db = MyMongoDb.MyMongoDb("MainDataBase", True)
    app.run(host='0.0.0.0')
