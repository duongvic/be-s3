from flask_restful import Resource
import logging
import pyqrcode
from io import BytesIO
# from app.mongodb import get_database_mongo, do_mapping_object
import json


class HelloResource(Resource):
    def get(self):
        # logging.info("A Sample Log Statement")
        # return 'Hello, World222'
        # comment_doc = {'movie_id': 'movie_id'}
        # db_collection = get_database_mongo()
        # db_collection.insert_one(comment_doc)
        return 'Hello, World222'

        # Get the database
        # db_collection = get_database_mongo()
        # item_details = db_collection.find()
        # data = []
        # for item in item_details:
        #     # This does not give a very readable output
        #     print(item)
        #     data.append(item)
        #
        # results = [do_mapping_object(item) for item in data]
        # return {'code': 200, 'message': True, 'data': results, 'total': len(results)}
    #
    # # def do_mapping_object(self, data):
    # #     results = {
    # #         "id": str(data['_id']),
    # #         "item": data['item'],
    # #         "qty": data['qty']
    # #     }
    # #     return results
