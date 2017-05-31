# -*- coding: utf-8 -*-
import pymongo
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base64
import os
import string
import random
import json
# this is global variable mongodb
db = ""
users_collection = ""
friend_collection = ""
chat_collection = ""
iv_ = "test_iv"

debug = True


def mongodb_connection_test():
    # connection to mongoDB
    connect = pymongo.MongoClient('localhost', 27017)

    # create data base
    dbs = connect['TestDataBase']

    # create collection
    co = dbs['TestCollection']

    # save one test data
    co.insert_one({"test": 1, "test2": 0})

    # print all collection data
    for collection in co.find():
        print collection


def get_aes_encrypt(raw_data, key, iv):
    raw_data_base64 = base64.b64encode(raw_data)
    # 16byte
    if len(raw_data_base64) % 16 != 0:
        raw_data_base64_16byte = raw_data_base64
        for i in range(16 - (len(raw_data_base64) % 16)):
            raw_data_base64_16byte += "_"
    else:
        raw_data_base64_16byte = raw_data_base64
    secret_key = hashlib.sha256(key).digest()
    iv = hashlib.md5(iv).digest()
    crypto = AES.new(secret_key, AES.MODE_CBC, iv)
    cipher_data = crypto.encrypt(raw_data_base64_16byte)
    cipher_data_base64 = base64.b64encode(cipher_data)
    return cipher_data_base64


def get_aes_decrypt(cipher_data_base64, key, iv):
    cipher_data = base64.b64decode(cipher_data_base64)
    secret_key = hashlib.sha256(key).digest()
    iv = hashlib.md5(iv).digest()
    crypto = AES.new(secret_key, AES.MODE_CBC, iv)
    raw_data_base64_16byte = crypto.decrypt(cipher_data)
    raw_data_base64 = raw_data_base64_16byte.split("_")[0]
    raw_data = base64.b64decode(raw_data_base64)
    return raw_data


def check_rsa_public_key(key):
    public_key = get_rsa_public_key().exportKey()
    public_key = public_key.replace('\n', '')
    public_key = public_key.replace('\r', '')
    key = key.replace('\n', '')
    key = key.replace('\r', '')
    if public_key.find(key) == 0:
        return True
    else:
        return False


def get_rsa_public_key():
    rsa = RSA.importKey(open(os.path.join(os.path.dirname(__file__), 'public.pem'), 'r'))
    return rsa


def get_rsa_private_ket():
    rsa = RSA.importKey(open(os.path.join(os.path.dirname(__file__), 'private.pem'), 'r'))
    return rsa


def setup_rsa_keys():
    # no private.pem file. crate private key.
    if os.path.isfile(os.path.join(os.path.dirname(__file__), './private.pem')) is False or\
                    os.path.isfile(os.path.join(os.path.dirname(__file__), './public.pem')) is False:
        rsa = RSA.generate(2048, get_random())
        private_pem = rsa.exportKey(format='PEM')
        with open(os.path.join(os.path.dirname(__file__), 'private.pem'), 'w') as f:
            f.write(private_pem)
        # crate public key.
        public_pem = rsa.publickey().exportKey()
        with open(os.path.join(os.path.dirname(__file__), 'public.pem'), 'w') as f:
            f.write(public_pem)


def get_random():
    return Random.new().read


def get_rsa_encrypt(plain_data, public_key):
    public_key = RSA.importKey(public_key)
    encrypt_data = public_key.publickey().encrypt(plain_data, get_random())[0]
    encrypt_data_base64 = base64.b64encode(encrypt_data)
    return encrypt_data_base64


def get_rsa_decrypt(encrypt_data_base64, private_key):
    private_key = RSA.importKey(private_key)
    encrypt_data = base64.b64decode(encrypt_data_base64)
    plain_data = private_key.decrypt(encrypt_data)
    return plain_data


# mongodb first setup
def setup_mongodb():
    # global variable
    global db
    global users_collection
    global friend_collection
    global chat_collection
    # connection to mongoDB
    connect = pymongo.MongoClient('localhost', 27017)
    # create data base
    if debug:
        connect.drop_database('TestDataBase')
        connect = pymongo.MongoClient('localhost', 27017)
        db = connect['TestDataBase']
    else:
        db = connect['MainDataBase']
    users_collection = db['UsersCollection']
    friend_collection = db['FriendCollection']
    chat_collection = db['CatCollection']


def set_new_user(username, password, rsa_public_base64):
    global users_collection
    # TODO: password security
    return users_collection.insert_one({"username": username, "password": password,
                                        "rsa_public_base64": rsa_public_base64})


def set_new_friend(username, friend_username):
    global friend_collection
    if friend_collection.find_one({"username": username}) is None:
        friend_collection.insert_one({"username": username, "friend_list": {friend_username: 1}})
        return "insert ok"
    friend_collection.update({"username": username}, {"$set": {"friend_list." + friend_username: 1}})
    return "update ok"


def set_now_user_from_post(username, password, rsa_public_key):
    global users_collection
    # check username
    if users_collection.find_one({'username': username}) is not None:
        return "crate  ng"

    set_new_user(username, password, rsa_public_key)
    print set_new_friend(username, "admin")
    print "crate  ok"
    return signin_from_post(username, password)


def signin_from_post(username, password):
    global users_collection
    # check username and passsword
    if users_collection.find_one({'username': username, 'password': password}) is None:
        return "signin ng"
    return "signin ok"


def get_friend_list(username):
    global friend_collection
    return friend_collection.find_one({'username': username}, {'friend_list': True, '_id': False})


def get_random_string(length):
    data = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])
    return data


def get_post_encrypt(raw_post_data, public_key):
    password = get_random_string(32)
    password = get_rsa_encrypt(raw_post_data, public_key)
    data_base64_aes = get_aes_encrypt(raw_post_data, password, iv_)
    data_password_encrypt_json = json.dumps({'data': data_base64_aes, 'password': password})
    return data_password_encrypt_json


def get_post_decrypt(encrypt_data_json):
    encrypt_data = json.loads(encrypt_data_json)
    data = encrypt_data['data']
    password = encrypt_data['password']
    decrypt_data = get_aes_decrypt(data, password, iv_)
    return decrypt_data


# http get
# def http_get_rsa_public_key():
#     try:
#         public_key = get_rsa_public_key()
#         return public_key
#     except os.error:
#         return "ng"
#
#
# http set
# def http_set_new_user(rsa_aes_user_data_json):
#     try:
#         decrypt_user_data = get_post_decrypt(rsa_aes_user_data_json)
#         decrypt_user_data_json = json.loads(decrypt_user_data)
#
#         username = decrypt_user_data_json['username']
#         password = decrypt_user_data_json['password']
#         public_key = decrypt_user_data_json['public_key']
#
#         set_new_user(username, password, public_key)
#         message = get_post_encrypt("ok")
#         return "ok"
#     except os.error:
#         return "ng"


if __name__ == "__main__":
    setup_mongodb()
    setup_rsa_keys()
    """Crypt POST"""
    # encrypt_data_ = get_post_encrypt("test_message")
    # print encrypt_data_
    # decrypt_data_ = get_post_decrypt(encrypt_data_)
    # print decrypt_data_
    """POST"""
    # create user
    # print set_now_user_from_post("admin", "password", base64.b16encode(get_rsa_public_key().exportKey()))
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
    rsa_encrypt = get_rsa_encrypt("test_message", get_rsa_public_key().exportKey())
    print rsa_encrypt
    # print check_rsa_public_key("-----BEGIN PUBLIC KEY-----" +
    #                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAldk/K2mEeqaGcUna23YS" +
    #                             "nYGkb94TnvMt8pp5/3kAKEZGuyS/EBTiUBxk8B0XqV+TzcOxoIVw2I/8rOt7sPnE" +
    #                             "EvOQsyo7If2RpUMdyk6rINwe2jZjpFJnovhmMn5kpDu3JTED1iuHZWFu706VDCMc" +
    #                             "4e1+VqHdTb5BWa/l3PRUURooOBwmW0yqelagk2Diu4C9vSmgHCbo3K52Ng9LpDOQ" +
    #                             "u5PqBXJWa08dyc4uizFUYHJQxObgWhHVCp4VWmgUkh/72JfNZoYLP5/youvjlRPU" +
    #                             "14Eo4KkDEtuk2O7coIkdsfRwYqqWQOdrUgZ8jLsRthZIQM84Wkyq34+ItJbouHGx" +
    #                             "AwIDAQAB" +
    #                             "-----END PUBLIC KEY-----")
    rsa_decrypt = get_rsa_decrypt(rsa_encrypt, get_rsa_private_ket().exportKey())
    print rsa_decrypt
