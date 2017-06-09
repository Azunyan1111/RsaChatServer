import unittest
import main
import base64
import hashlib
import time
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
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def signin():
    url = 'http://0.0.0.0:5000/signin'
    payload = {'username': 'admin', 'password': 'password', 'public_key_base64': "base64", 'terminal_hash': 'hash'}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def set_friend(my, friend):
    url = 'http://0.0.0.0:5000/set_friend'
    payload = {'username': my, 'friend_username': friend, 'terminal_hash': 'hash'}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def get_friend():
    url = 'http://0.0.0.0:5000/get_friend'
    payload = {'username': 'admin', 'terminal_hash': 'hash'}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def set_chat(username, receive_username, chat_data, terminal_hash):
    url = 'http://0.0.0.0:5000/set_chat'
    payload = {'send_username': username, "receive_username": receive_username,
               "chat_data": chat_data, 'terminal_hash': terminal_hash}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def get_chat(username, friend_username, hash_):
    url = 'http://0.0.0.0:5000/get_chat'
    payload = {'username': username, "friend_username": friend_username, 'terminal_hash': hash_}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def set_friend_zone(username, hash_):
    url = 'http://0.0.0.0:5000/set_friend_zone'
    payload = {'username': username, 'terminal_hash': hash_}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content


def http_get_friend_zone_result(username, hash_):
    url = 'http://0.0.0.0:5000/get_friend_zone_result'
    payload = {'username': username, 'terminal_hash': hash_}
    payload = {'json': json.dumps(payload)}
    response = requests.post(url, data=payload)
    print response.content

if __name__ == "__main__":
    # get_server_public_key_base64()
    signup("admin",     "password", "base64", "hash")
    # signup("user",      "password", "base64", "hash")
    # signup("hoge",      "password", "base64", "hash")
    # signup("foo",       "password", "base64", "hash")
    # signup("hogehoge",  "password", "base64", "hash")
    # signup("foofoo",    "password", "base64", "hash")
    # signup("hoge()", "hogehoge", "base64", "hash")
    # signin()
    # set_friend("user", "hoge")
    # set_friend("user", "foo")
    # set_friend("hoge", "foo")
    # set_friend("foofoo", "foo")
    # set_friend("hoge", "foo")
    # set_friend("hoge", "foofoo")
    # set_friend("admin_", "foo")
    # get_friend()

    # set_chat("admin", "hoge", "hoge is fuck", "hash")
    # get_chat("admin", "hoge", "hash")
    # get_chat("hoge", "admin", "hash")
    # set_chat("hoge", "admin", "WTF", "hash")
    # get_chat("admin", "hoge", "hash")
    # get_chat("hoge", "admin", "hash")
    # while True:
    #     set_friend_zone("user", "hash")
    #     set_friend_zone("hoge", "hash")
    #     set_friend_zone("foo", "hash")
    #     set_friend_zone("hogehoge", "hash")
    #     set_friend_zone("foofoo", "hash")
    #     time.sleep(1)
    #     http_get_friend_zone_result("user", "hash")
    #     http_get_friend_zone_result("hoge", "hash")
    #     http_get_friend_zone_result("foo", "hash")
    #     http_get_friend_zone_result("hogehoge", "hash")
    #     http_get_friend_zone_result("foofoo", "hash")


    # set_friend_zone("user", "hash")
    # set_friend_zone("hoge", "hash")
    # set_friend_zone("foo", "hash")
    # set_friend_zone("hogehoge", "hash")
    # set_friend_zone("foofoo", "hash")
    # time.sleep(20)
    # http_get_friend_zone_result("user", "hash")
    # http_get_friend_zone_result("hoge", "hash")
    # http_get_friend_zone_result("foo", "hash")
    # http_get_friend_zone_result("hogehoge", "hash")
    # http_get_friend_zone_result("foofoo", "hash")

