import pymongo

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

if __name__ == "__main__":
    mongodb_setup()
    print db.name
    print users_collection
    print friend_collection
    print chat_collection
