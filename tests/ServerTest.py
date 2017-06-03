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


def signup():
    url = 'http://0.0.0.0:5000/signup'
    payload = {'username': 'admin', 'password': 'password', 'public_key_base64': "base64", 'terminal_hash': 'hash'}
    response = requests.post(url, data=payload)
    print response.content


def signin():
    url = 'http://0.0.0.0:5000/signin'
    payload = {'username': 'admin', 'password': 'password', 'public_key_base64': "base64", 'terminal_hash': 'hash'}
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

if __name__ == "__main__":
    get_server_public_key_base64()
    signup()
    signin()
    set_friend()
    get_friend()
