import pymongo
import base64
# from datetime import datetime
import time
import re
from datetime import datetime, timedelta
from collections import OrderedDict


class MyMongoDb:
    """This class is Mongo DB my controller"""

    # setup mongo db
    def __init__(self, data_base_name, debug):
        self.database = ""
        self.users_collection = ""
        self.friend_collection = ""
        self.chat_collection = ""
        self.debug = debug

        # connection to mongoDB
        self.connect = pymongo.MongoClient('localhost', 27017, document_class=OrderedDict)
        # create data base
        if self.debug:
            self.connect.drop_database("Test" + data_base_name)
            self.connect = pymongo.MongoClient('localhost', 27017, document_class=OrderedDict)
            self.database = self.connect["Test" + data_base_name]
        else:
            self.database = self.connect[data_base_name]
        self.users_collection = self.database['UsersCollection']
        self.friend_collection = self.database['FriendCollection']
        self.chat_collection = self.database['CatCollection']
        return

    def set_signup(self, username, password, public_key_base64, terminal_hash):
        # check username
        if re.search(r'^[A-Za-z0-9_]{1,32}$', username) is None:
            return "can not use username."
        # check username
        if self.users_collection.find_one({'username': username}) is not None:
            return "username is used"

        # TODO: password security
        self.users_collection.insert_one({"username": username, "password": password,
                                          "public_key_base64": public_key_base64, "terminal_hash": terminal_hash})
        # add friend admin.
        self.set_add_friend(username, "admin", terminal_hash)
        # signin
        return self.set_signin(username, password, public_key_base64, terminal_hash)

    def set_signin(self, username, password, public_key_base64, terminal_hash):
        # check username and password
        if self.users_collection.find_one({'username': username, 'password': password}) is None:
            return "signin error"
        # update public_key_base64 and terminal hash
        self.users_collection.update({'username': username},
                                     {"$set": {"public_key_base64": public_key_base64, "terminal_hash": terminal_hash}})
        return "ok"

    def set_add_friend(self, username, friend_username, terminal_hash):
        # check username and terminal_hash
        if self.users_collection.find_one({"username": username, "terminal_hash": terminal_hash}) is None:
            return "hacking error"

        # friend collection check
        if self.friend_collection.find_one({"username": username}) is None:
            # new user data insert collection
            self.friend_collection.insert_one({"username": username, "friend_list": {"_1": [friend_username]}})
            # new user data insert collection
            self.friend_collection.insert_one({"username": friend_username, "friend_list": {"_1": [friend_username]}})
            # send user to friend fast chat.
            self.set_chat(username, friend_username, "Hello! Admin!", terminal_hash)
            return "add friend new data ok"
        # check friend_username
        if self.friend_collection.find_one({"username": username, "friend_list._1": friend_username}) is not None:
            return "added"
        # get all friend. add friend
        friend_list = self.friend_collection.find_one({"username": username}, {"_id": False, "friend_list._1": True})
        friend_list = friend_list['friend_list']['_1']
        friend_list.append(friend_username)
        # old user add friend
        self.friend_collection.update({"username": username}, {"$set": {"friend_list._1": friend_list}})
        # friend user add user
        self.friend_collection.update({"username": friend_username}, {"$set": {"friend_list._1": friend_list}})
        # send user to friend fast chat.
        self.set_chat(username, friend_username, "Hello! i added you.", terminal_hash)

        return "ok"

    def get_user_friend(self, username, terminal_hash):
        # check username and terminal_hash
        if self.users_collection.find_one({"username": username, "terminal_hash": terminal_hash}) is None:
            return "hacking error"

        friend_list = self.friend_collection.find_one({'username': username},
                                                      {'friend_list._1': True, 'count': True, '_id': False})
        return friend_list

    # this is server only read
    # post request when used
    def get_user_public_key(self, username):
        public_key_base64 = self.users_collection.find_one({'username': username},
                                                           {'rsa_public_base64': True, '_id': False})
        public_key_base64 = public_key_base64['rsa_public_base64']
        public_key = base64.b64decode(public_key_base64)
        return public_key

    def get_database(self):
        return self.database

    def get_users_collection(self):
        return self.users_collection

    def get_friend_collection(self):
        return self.friend_collection

    def get_chat_collection(self):
        return self.chat_collection

    def set_chat(self, send_username, receive_username, chat_data, send_terminal_hash):
        # check username and password
        if self.users_collection.find_one({'username': send_username, 'terminal_hash': send_terminal_hash}) is None:
            return "send error"
        now_time = str(datetime.now()).replace(".", ",")
        if self.debug:
            time.sleep(0.1)
        # new chat
        if self.chat_collection.find_one({"ids": send_username + "-" + receive_username}) is None:
            result = self.chat_collection.insert_one({"ids": send_username + "-" + receive_username,
                                                      "chats": {now_time:
                                                                {"chat": chat_data,
                                                                 "user": send_username,
                                                                 "data": now_time}}})
            result2 = self.chat_collection.insert_one({"ids": receive_username + "-" + send_username,
                                                      "chats": {now_time:
                                                                {"chat": chat_data,
                                                                 "user": send_username,
                                                                 "data": now_time}}})

            return "set chat fast ok" if result.acknowledged and result2.acknowledged else "set chat fast ng"
        result = self.chat_collection.update({'ids': send_username + "-" + receive_username},
                                             {"$set": {"chats." + now_time: {"chat": chat_data, "user": send_username,
                                                       "data": now_time}}})
        result2 = self.chat_collection.update({'ids': receive_username + "-" + send_username},
                                              {"$set": {"chats." + now_time: {"chat": chat_data, "user": send_username,
                                                        "data": now_time}}})

        return "set chat ok" if result['updatedExisting'] and result2['updatedExisting'] else "set chat ng"

    def is_username_find(self, username, terminal_hash):
        if self.users_collection.find_one({'username': username, 'terminal_hash': terminal_hash}) is None:
            return False
        else:
            return True

    def get_chat(self, my_username, friend_username, terminal_hash):
        # check username and password
        if self.users_collection.find_one({'username': my_username, 'terminal_hash': terminal_hash}) is None:
            return "get error"
        return self.chat_collection.find_one({"ids": my_username + "-" + friend_username}, {"_id": False})


if __name__ == "__main__":
    db = MyMongoDb("Test", True)

    print db.set_chat("hoge", "foo", "I love hoge.", "hash")
    print db.get_chat("hoge", "foo", "hash")
    print db.set_chat("foo", "hoge", "Fuckin foo", "hash")
    print db.get_chat("foo", "hoge", "hash")
    print db.set_chat("foo", "hoge", "foo is my life", "hash")
    print db.get_chat("foo", "hoge", "hash")

