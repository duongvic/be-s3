from pymongo import MongoClient
from config import CONF

obj = CONF.config['s3_mongo_db']
host = obj.get('host')
port = obj.get('port')
username = obj.get('username')
password = obj.get('password')
db_name = obj.get('db_name')
db_collection = obj.get('db_collection')


def get_database_mongo():
    client = MongoClient(host=host, port=port, username=username, password=password)
    name = client.get_database(db_name)
    collection = name.get_collection(db_collection)

    # client = MongoClient(host='172.16.0.126', port=27017, username='mongo-admin', password='ckM9Ez7xrHQ5yWTA')
    # db_name = client.get_database('s3mongodb')
    # collection = db_name.get_collection('s3mongodb')
    return collection


# def do_mapping_object(data):
#     results = {
#         "id": str(data['_id']),
#         "fnc_name": data['fnc_name'],
#         "user_name": data['user_name'],
#         "msg_status": data['msg_status'],
#         "msg_action": data['msg_action'],
#         "created_at": data['created_at']
#         # "created_at": data.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#     }
#     return results

# def do_mapping_object(data):
#     results = {
#         "id": str(data['_id']),
#         "item": data['item'],
#         "qty": data['qty']
#     }
#     return results


# if __name__ == "__main__":
#
#     # test get the database
#     # db_collection = get_database_mongo()
#     # item_details = db_collection.find()
#     # item_details = db_collection.find({'user_name': 'tuantd'})
#
#     item_details = get_database_mongo().find({'user_name': 'tuantd'})
#     for item in item_details:
#         # This does not give a very readable output
#         print(item)
