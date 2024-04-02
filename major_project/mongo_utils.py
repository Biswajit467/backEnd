import pymongo

# Define MongoDB connection settings
MONGO_HOST = 'localhost'
MONGO_PORT = 27017
MONGO_DB_NAME = 'campus_canvas'

# Connect to MongoDB
mongo_client = pymongo.MongoClient(MONGO_HOST, MONGO_PORT)
mongo_db = mongo_client[MONGO_DB_NAME]

# Define the collection name
collection_name = 'semester_marks'
semester_marks_collection = mongo_db[collection_name]
