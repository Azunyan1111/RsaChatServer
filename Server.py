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
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        password = data_json['password']
        public_key_base64 = data_json['public_key_base64']
        terminal_hash = data_json['terminal_hash']

        return main.http_signup(username, password, public_key_base64, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request.HOGE"


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        password = data_json['password']
        public_key_base64 = data_json['public_key_base64']
        terminal_hash = data_json['terminal_hash']

        return main.http_signin(username, password, public_key_base64, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/set_friend', methods=['GET', 'POST'])
def set_friend():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        friend_username = data_json['friend_username']
        terminal_hash = data_json['terminal_hash']

        return main.http_set_friend(username, friend_username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/get_friend', methods=['GET', 'POST'])
def get_friend():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        terminal_hash = data_json['terminal_hash']

        return main.http_get_friend(username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/set_chat', methods=['GET', 'POST'])
def set_chat():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        send_username = data_json['send_username']
        receive_username = data_json['receive_username']
        chat_data = data_json['chat_data']
        terminal_hash = data_json['terminal_hash']

        # send_username = request.form['send_username']
        # receive_username = request.form['receive_username']
        # chat_data = request.form['chat_data']
        # terminal_hash = request.form['terminal_hash']

        return main.http_set_chat(send_username, receive_username, chat_data, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/get_chat', methods=['GET', 'POST'])
def get_chat():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        friend_username = data_json['friend_username']
        terminal_hash = data_json['terminal_hash']

        return main.http_get_chat(username, friend_username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/get_new_friend_zone', methods=['GET', 'POST'])
def get_new_friend_zone():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        terminal_hash = data_json['terminal_hash']

        return main.http_get_new_friend_zone(username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/set_new_friend_zone', methods=['GET', 'POST'])
def set_new_friend_zone():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        terminal_hash = data_json['terminal_hash']

        return main.http_set_new_friend_zone(username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"


@app.route('/new_friend_zone_add_friend', methods=['GET', 'POST'])
def http_new_friend_zone_add_friend():
    if request.method == 'POST' or request.method == 'GET':
        data_json = json.loads(request.form['json'])

        username = data_json['username']
        friend_username = data_json['friend_username']
        terminal_hash = data_json['terminal_hash']

        return main.http_new_friend_zone_add_friend(username, friend_username, terminal_hash)
        # return "hello world"
    else:
        return "Error: 400: Bad Request"

if __name__ == '__main__':
    main.db = MyMongoDb.MyMongoDb("MainDataBase", True)
    app.run(host='0.0.0.0')
