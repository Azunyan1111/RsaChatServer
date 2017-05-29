# -*- coding: utf-8 -*-
import pymongo
from Crypto.Cipher import AES
import hashlib
import base64

# this is global variable mongodb
db = ""
users_collection = ""
friend_collection = ""
chat_collection = ""

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


# mongodb first setup
def mongodb_setup():
    # global variable
    global db
    global users_collection
    global friend_collection
    global chat_collection
    # connection to mongoDB
    connect = pymongo.MongoClient('localhost', 27017)
    # create data base
    if debug:
        db = connect['TestDataBase']
    else:
        db = connect['MainDataBase']
    users_collection = db['UsersCollection']
    friend_collection = db['FriendCollection']
    chat_collection = db['CatCollection']


def set_new_user(username, password):
    global users_collection
    # TODO: password security
    users_collection.insert_one({"username": username, "password": password})


def get_new_aes_key():
    key = "hoge"


def get_encrypt_data(raw_data, key):
    raw_data_base64 = base64.b64encode(raw_data)
    # 16byte
    if len(raw_data_base64) % 16 != 0:
        raw_data_base64_16byte = raw_data_base64
        for i in range(16 - (len(raw_data_base64) % 16)):
            raw_data_base64_16byte += "_"
    secret_key = hashlib.sha256(key).digest()
    crypto = AES.new(secret_key)
    cipher_data = crypto.encrypt(raw_data_base64_16byte)
    cipher_data_base64 = base64.b64encode(cipher_data)
    return cipher_data_base64


def get_decrypt_data(cipher_base64_data, key):
    cipher_data = base64.b64decode(cipher_base64_data)
    secret_key = hashlib.sha256(key).digest()
    crypto = AES.new(secret_key)
    raw_data_base64_16byte = crypto.decrypt(cipher_data)
    raw_data_base64 = raw_data_base64_16byte.split("_")[0]
    raw_data = base64.b64decode(raw_data_base64)
    return raw_data


if __name__ == "__main__":
    # mongodb_setup()
    # print db.name
    # print users_collection
    # print friend_collection
    # print chat_collection

    message = "114514"
    password = "This is password"
    crypt_data = get_encrypt_data(message, password)
    print crypt_data
    decrypt_data = get_decrypt_data(crypt_data, password)
    print decrypt_data
