import pymongo

# connection to mongoDB
connect = pymongo.MongoClient('localhost', 27017)

# create data base
db = connect['TestDataBase']

# create collection
co = db['TestCollection']

# save one test data
co.insert_one({"test": 1, "test2": 0})

# print all collection data
for collection in co.find():
    print collection
