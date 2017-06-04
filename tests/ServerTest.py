import unittest
import main
import base64
import hashlib

import pprint
import json
import requests


def get_server_public_key_base64():
    url = 'http://0.0.0.0:5000/get_server_public_key_base64'
    response = requests.get(url)
    print response
    print response.content


def signup(username, password, public_key, terminal_hash):
    url = 'http://0.0.0.0:5000/signup'
    payload = {'username': username, 'password': password,
               'public_key_base64': public_key, 'terminal_hash': terminal_hash}
    response = requests.post(url, data=payload)
    print response.content


def signin():
    url = 'http://0.0.0.0:5000/signin'
    payload = {'username': 'admin', 'password': 'admin', 'public_key_base64': "base64", 'terminal_hash': 'hash'}
    response = requests.post(url, data=payload)
    print response.content


def set_friend():
    url = 'http://0.0.0.0:5000/set_friend'
    payload = {'username': 'admin', 'friend_username': "hoge", 'terminal_hash': 'hash'}
    response = requests.post(url, data=payload)
    print response.content


def get_friend():
    url = 'http://0.0.0.0:5000/get_friend'
    payload = {'username': 'admin', 'terminal_hash': 'hash'}
    response = requests.post(url, data=payload)
    print response.content


def set_chat(username, receive_username, chat_data, terminal_hash):
    url = 'http://0.0.0.0:5000/set_chat'
    payload = {'send_username': username, "receive_username": receive_username,
               "chat_data": chat_data, 'terminal_hash': terminal_hash}
    response = requests.post(url, data=payload)
    print response.content


def get_chat(username, friend_username, hash_):
    url = 'http://0.0.0.0:5000/get_chat'
    payload = {'username': username, "friend_username": friend_username, 'terminal_hash': hash_}
    response = requests.post(url, data=payload)
    print response.content

if __name__ == "__main__":
    get_server_public_key_base64()
    signup("admin", "admin", "base64", "hash")
    signup("hoge", "hogehoge", "base64", "hash")
    signin()
    set_friend()
    get_friend()

    set_chat("admin", "hoge", "fuck", "hash")
    get_chat("admin", "hoge", "hash")
    get_chat("hoge", "admin", "hash")
    set_chat("hoge", "admin", "admin is noob", "hash")
    get_chat("admin", "hoge", "hash")
    get_chat("hoge", "admin", "hash")

