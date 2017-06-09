# -*- coding: utf-8 -*-
import hashlib
import base64
import os
import string
import random
import json
import re
import threading
import time
import random
# my crypt
import MyCrypto
import MyMongoDb
# this is global variable mongodb
db = ""
iv_ = "test_iv"
friend_zone = []
friend_zone_ok = []
debug = True


# def get_post_encrypt(raw_post_data, public_key):
#     password = get_random_string(32)
#     data_base64_aes = get_aes_encrypt(raw_post_data, password, iv_)
#     password = get_rsa_encrypt(password, public_key)
#     data_password_encrypt_json = json.dumps({'data': data_base64_aes, 'password': password})
#     return data_password_encrypt_json


# def get_post_decrypt(encrypt_data_json, private_key):
#     encrypt_data = json.loads(encrypt_data_json)
#     data = encrypt_data['data']
#     password = encrypt_data['password']
#     password = get_rsa_decrypt(password, private_key)
#     decrypt_data = get_aes_decrypt(data, password, iv_)
#     return decrypt_data

def get_random_string(length):
    data = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])
    return data


# http
def http_get_server_public_key_base64():
    try:
        # TODO: rsa
        public_key = MyCrypto.get_rsa_public_key().exportKey()
        public_key_base64 = base64.b64encode(public_key)
        public_key_base64_json = json.loads('{"public_key_base64": "' + public_key_base64 + '"}')
        public_key_base64_json = json.dumps(public_key_base64_json)
        return public_key_base64_json
    except os.error:
        return "ng"


# http
def http_signup(username, password, public_key_base64, terminal_hash):
    # username = signup_data_json['username']
    # password = signup_data_json['password']
    # public_key_base64 = signup_data_json['public_key_base64']
    # terminal_hash = signup_data_json['terminal_hash']

    return db.set_signup(username, password, public_key_base64, terminal_hash)


# http
def http_signin(username, password, public_key_base64, terminal_hash):
    # username = signin_data_json['username']
    # password = signin_data_json['password']
    # public_key_base64 = signin_data_json['public_key_base64']
    # terminal_hash = signin_data_json['terminal_hash']

    return db.set_signin(username, password, public_key_base64, terminal_hash)


# http
def http_get_friend(username, terminal_hash):
    # username = username_terminal_hash_json['username']
    # terminal_hash = username_terminal_hash_json['terminal_hash']
    user_friend_json = db.get_user_friend(username, terminal_hash)
    user_friend = user_friend_json['friend_list']['_1']
    user_friend = json.dumps(user_friend)
    user_friend = re.sub(r'"', '', user_friend)
    user_friend = re.sub(r'\[', '', user_friend)
    user_friend = re.sub(r'\]', '', user_friend)
    user_friend = re.sub(r' ', '', user_friend)
    return user_friend


# http
def http_set_friend(username, friend_username, terminal_hash):
    # username = username_password_json['username']
    # friend_username = username_password_json['friend_username']
    # terminal_hash = username_password_json['terminal_hash']
    # TODO:BASE friend_user
    return db.set_user_friend(username, friend_username, terminal_hash)


def http_set_chat(send_username, receive_username, chat_data, terminal_hash):
    db.set_chat(send_username, receive_username, chat_data, terminal_hash)
    # TODO:BASE to receive_user
    return "ok"


def http_get_chat(my_username, friend_username, terminal_hash):
    chat_data = db.get_chat(my_username, friend_username, terminal_hash)
    chat_data = chat_data['chats']
    chat_data_json = json.dumps(chat_data)
    return chat_data_json

"""
def http_set_new_friend_zone(username, terminal_hash):
    if db.is_username_find(username, terminal_hash) is False:
        return "ng"
    new_friend_zone_remove(username, 0)
    new_fiend_zone.append(username)
    t = threading.Thread(target=new_friend_zone_remove, args=(username, 20,))
    t.start()
    return "ok"


def http_get_new_friend_zone(username, terminal_hash):
    if db.is_username_find(username, terminal_hash) is False:
        return "ng"
    new_fiend_zone_json = json.dumps(new_fiend_zone)
    new_fiend_zone_json = re.sub(r'"', '', new_fiend_zone_json)
    new_fiend_zone_json = re.sub(r'\[', '', new_fiend_zone_json)
    new_fiend_zone_json = re.sub(r'\]', '', new_fiend_zone_json)
    new_fiend_zone_json = re.sub(r' ', '', new_fiend_zone_json)
    return new_fiend_zone_json


def http_new_friend_zone_add_friend(username, friend_name, terminal_hash):
    if db.is_username_find(username, terminal_hash) is False:
        return "ng"
    new_friend_zone_remove(username, 0)
    new_friend_zone_remove(friend_name, 0)
    return http_set_friend(username, friend_name, terminal_hash)


def new_friend_zone_remove(username, time_):
    if new_fiend_zone.count(username) == 0:
        return "can not remove"
    time.sleep(time_)
    try:
        new_fiend_zone.remove(username)
    except os.error:
        return "can not remove"
"""


def http_set_friend_zone(username, terminal_hash):
    # if db.is_username_find(username, terminal_hash) is False:
    #     return "ng"
    if friend_zone.count(username) != 0:
        return "ok"
    friend_zone.append(username)
    return "ok"


def http_get_friend_zone_result(username, terminal_hash):
    # if db.is_username_find(username, terminal_hash) is False:
    #     return "ng"
    if friend_zone_ok.count(username) != 0:
        friend_zone_ok.remove(username)
        return "ok"
    return "ng"


def friend_zone_main(time_):
    global friend_zone
    global friend_zone_ok
    while True:
        try:
            friend_zone = []
            print friend_zone_ok
            time.sleep(time_)
            friend_zone_ok = []
            if len(friend_zone) == 0 or len(friend_zone) == 1:
                continue
            for i in range(0, len(friend_zone) - (len(friend_zone) % 2), 2):
                print len(friend_zone), len(friend_zone) % 2, i
                print friend_zone
                if len(friend_zone) == 1:
                    continue

                username = friend_zone.pop(0)
                friend_username = friend_zone.pop(0)
                # add friend
                print username, friend_username
                db.set_user_friend_no_hash_server_only(username, friend_username)
                # add ok list
                friend_zone_ok.append(username)
                friend_zone_ok.append(friend_username)
                print friend_zone_ok
        except os.error:
            start_friend_zone()


def start_friend_zone():
    t = threading.Thread(target=friend_zone_main, args=(20,))
    t.start()


if __name__ == "__main__":
    db = MyMongoDb.MyMongoDb("MainDataBase", True)

    start_friend_zone()

    # print http_set_friend_zone("hoge", "hash")
    # print http_set_friend_zone("hogehoge", "hash")
    # while True:
    #     print list(friend_zone)
    #     time.sleep(2)
    # print list(friend_zone)
    # print http_set_friend_zone("foo", "hash")
    # print list(friend_zone)
    # print http_set_friend_zone("foofoo", "hash")
    # print list(friend_zone)

    # setup_mongodb()
    # setup_rsa_keys()
    """-------------------NO ENCRYPT-------------------"""

    """ get server public_key_base64"""
    # print "server_public_key:", http_get_server_public_key_base64()

    """ new user signup"""
    # new user post data to server. username password pub_key
    # key = base64.b64encode(MyCrypto.get_rsa_public_key().exportKey())
    # terminal_hash_ = base64.b64encode(hashlib.sha256("this is terminal identification password.").digest())
    # print "terminal_hash:", terminal_hash_
    # user_json = '{"username": "hoge", "password": "hogehoge",' \
    #             ' "public_key_base64": "' + key + '", "terminal_hash": "' + terminal_hash_ + '"}'
    # user_json = json.loads(user_json)
    # print "signup_data      :", user_json
    # server
    # print http_signup("admin", "admin", key, terminal_hash_)
    # print http_signup("hoge", "hogehoge", key, terminal_hash_)
    # print http_signup("foo", "foofoo", key, terminal_hash_)

    """ old user signin"""
    # old user signin
    # user_json = '{"username": "hoge", "password": "hogehoge", ' \
    #             ' "public_key_base64": "' + key + '", "terminal_hash": "' + terminal_hash_ + '"}'
    # user_json = json.loads(user_json)
    # print "signin_data      :", user_json
    # print http_signin("admin", "admin", key, terminal_hash_)
    # print http_signin("hoge", "hogehoge", key, terminal_hash_)
    # print http_signin("foo", "foofoo", key, terminal_hash_)

    """ user get friend"""
    # user_json = '{"username": "hoge", "terminal_hash": "' + terminal_hash_ + '"}'
    # user_json = json.loads(user_json)
    # print "friend_get_data  :", user_json
    # print http_get_friend("admin", terminal_hash_)
    # print http_get_friend("hoge", terminal_hash_)
    # print http_get_friend("foo", terminal_hash_)

    """ user set friend"""
    # user_json = '{"username": "hoge", "friend_username": "foo", "terminal_hash": "' + terminal_hash_ + '"}'
    # user_json = json.loads(user_json)
    # print "friend_add_data  :", user_json
    # print http_set_friend("hoge", "foo", terminal_hash_)

    """ user get friend"""
    # print http_get_friend("admin", terminal_hash_)
    # print http_get_friend("hoge", terminal_hash_)
    # print http_get_friend("foo", terminal_hash_)

    """ hoge send message"""

    # print http_set_chat("hoge", "foo", "I love hoge.", terminal_hash_)
    # print http_get_chat("hoge", "foo", terminal_hash_)
    # print http_set_chat("foo", "hoge", "Fuckin hoge", terminal_hash_)
    # print http_get_chat("foo", "hoge", terminal_hash_)
    # print http_set_chat("foo", "hoge", "foo is my life", terminal_hash_)
    # print http_get_chat("foo", "hoge", terminal_hash_)

    """ set New Friend zone"""

    # print http_set_new_friend_zone("admin", "hash")
    # print http_set_new_friend_zone("hoge", "hash")
    # print http_set_new_friend_zone("foo", "hash")
    # print http_get_new_friend_zone("admin", "hash"), 0
    # time.sleep(1)
    # print http_get_new_friend_zone("admin", "hash"), 1
    # time.sleep(1)
    # print http_get_new_friend_zone("admin", "hash"), 2
    # time.sleep(1)
    # print http_get_new_friend_zone("admin", "hash"), 3
    # time.sleep(1)
    # print http_get_new_friend_zone("admin", "hash"), 4
    # while True:
    #     time.sleep(1)
    #     print http_get_new_friend_zone("admin", "hash")

    """-------------------NO ENCRYPT-------------------"""

    """Crypt POST"""
    # encrypt_data_ = get_post_encrypt("test_message", get_rsa_public_key().exportKey())
    # print encrypt_data_
    # decrypt_data_ = get_post_decrypt(encrypt_data_, get_rsa_private_ket().exportKey())
    # print decrypt_data_
    """POST"""
    # create user
    # print set_now_user_from_post("admin", "password", base64.b16encode(get_rsa_public_key().exportKey()))
    #
    # test new user sent data
    # user_json = '{"username": "hoge", "password": "hogehoge", "public_key":' +  get_rsa_public_key().exportKey() + '}'
    # encrypt_user_json = get_post_encrypt(user_json, http_get_server_rsa_public_key().exportKey())
    #
    # server
    # decrypt_data = get_post_encrypt(encrypt_user_json, get_rsa_private_ket().exportKey())
    # print http_set_new_user(encrypt_user_json)
    # print set_now_user_from_post("hoge", "hogehoge", base64.b16encode(get_rsa_public_key().exportKey()))
    # print set_now_user_from_post("foo", "foofoo", base64.b16encode(get_rsa_public_key().exportKey()))
    # add user
    # print set_new_friend("hoge", "foo")
    # print get_friend_list("hoge")

    # print base64.b64encode(hashlib.sha256(get_rsa_private_ket().exportKey()).digest())
    """mongoDB"""

    # print set_new_user("hoge", "foo").acknowledged
    # print db.name
    # print users_collection.name
    # print friend_collection.name
    # print chat_collection.name
    """AES"""
    # message = "test_message"
    # password = "test_password_hogehogehogehogehogehogehogehogehogehogehogehogehogehogehoge"
    # ivs = "test_iv"
    # encrypt_data = get_aes_encrypt(message, password, ivs)
    # print encrypt_data
    # decrypt_data = get_aes_decrypt(encrypt_data, password, ivs)
    # print decrypt_data

    """RSA"""
    # setup_rsa_keys()
    # rsa_encrypt = get_rsa_encrypt("test_message", get_rsa_public_key().exportKey())
    # print rsa_encrypt
    # print check_rsa_public_key("-----BEGIN PUBLIC KEY-----" +
    #                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAldk/K2mEeqaGcUna23YS" +
    #                             "nYGkb94TnvMt8pp5/3kAKEZGuyS/EBTiUBxk8B0XqV+TzcOxoIVw2I/8rOt7sPnE" +
    #                             "EvOQsyo7If2RpUMdyk6rINwe2jZjpFJnovhmMn5kpDu3JTED1iuHZWFu706VDCMc" +
    #                             "4e1+VqHdTb5BWa/l3PRUURooOBwmW0yqelagk2Diu4C9vSmgHCbo3K52Ng9LpDOQ" +
    #                             "u5PqBXJWa08dyc4uizFUYHJQxObgWhHVCp4VWmgUkh/72JfNZoYLP5/youvjlRPU" +
    #                             "14Eo4KkDEtuk2O7coIkdsfRwYqqWQOdrUgZ8jLsRthZIQM84Wkyq34+ItJbouHGx" +
    #                             "AwIDAQAB" +
    #                             "-----END PUBLIC KEY-----")
    # rsa_decrypt = get_rsa_decrypt(rsa_encrypt, get_rsa_private_ket().exportKey())
    # print rsa_decrypt
