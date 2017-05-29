import pymongo

# this is global variable mongodb
db = ""
users_collection = ""
friend_collection = ""
chat_collection = ""


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


def mongodb_setup():
    # global variable
    global db
    # connection to mongoDB
    connect = pymongo.MongoClient('localhost', 27017)
    # create data base
    db = connect['TestDataBase']


if __name__ == "__main__":
    mongodb_setup()
    print db.name
