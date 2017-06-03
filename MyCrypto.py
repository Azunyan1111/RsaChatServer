import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import os


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