# -*- coding: utf-8 -*-
import pymongo
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base64
import os

# this is global variable mongodb
db = ""
users_collection = ""
friend_collection = ""
chat_collection = ""
iv = "test iv"

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
        db = connect['TestDataBase']
    else:
        db = connect['MainDataBase']
    users_collection = db['UsersCollection']
    friend_collection = db['FriendCollection']
    chat_collection = db['CatCollection']


def set_new_user(username, password):
    global users_collection
    # TODO: password security
    return users_collection.insert_one({"username": username, "password": password})


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


def get_rsa_encrypt(plain_data):
    encrypt_data = get_rsa_public_key().publickey().encrypt(plain_data, get_random())[0]
    encrypt_data_base64 = base64.b64encode(encrypt_data)
    return encrypt_data_base64


def get_rsa_decrypt(encrypt_data_base64):
    encrypt_data = base64.b64decode(encrypt_data_base64)
    plain_data = get_rsa_private_ket().decrypt(encrypt_data)
    return plain_data


if __name__ == "__main__":
    # print base64.b64encode(hashlib.sha256(get_rsa_private_ket().exportKey()).digest())
    """mongoDB"""
    # setup_mongodb()

    # print set_new_user("hoge", "foo").acknowledged
    # print db.name
    # print users_collection.name
    # print friend_collection.name
    # print chat_collection.name
    """AES"""
    # message = "test_message"
    # password = "test_password"
    # ivs = "test_iv"
    # encrypt_data = get_aes_encrypt(message, password, ivs)
    # print encrypt_data
    # decrypt_data = get_aes_decrypt(encrypt_data, password, ivs)
    # print decrypt_data

    """RSA"""
    # setup_rsa_keys()
    # rsa_encrypt = get_rsa_encrypt("test_message")
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
    # rsa_decrypt = get_rsa_decrypt(rsa_encrypt)
    # print rsa_decrypt
