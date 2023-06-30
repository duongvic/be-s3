from app.exception import InputDataError
from foxcloud.v1.services.s3 import client
from config import CONF
from app.logging_action import logger
# from datetime import datetime
import datetime
from app.mongodb import get_database_mongo

fox_init = CONF.config['s3_fox_cloud']
use_log_pg = CONF.config['use_log_pg']
use_log_mg = CONF.config['use_log_mg']
endpoint_url = CONF.config['endpoint_url']


class BucketController:

    def do_list_buckets(self, **args):
        try:
            logger.info("do_list_buckets: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            # bucket_name = (args['bucket_name'], None)
            bucket_name = args.get('bucket_name', None)

            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            bucket = bucket.list_buckets(endpoint_url=endpoint_url, bucket_name=bucket_name)._info
            if bucket is None:
                msg_status = 400
                msg_action = 'Bucket is not exists {}.'.format(bucket)
                raise InputDataError(msg_action)
            return bucket
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_list_buckets: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_buckets.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                # db_collection = get_database_mongo()
                get_database_mongo().insert_one(data)
                # db_collection.insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_list_buckets.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_create_bucket(self, **args):
        try:
            logger.info("do_create_bucket: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            acl = args['acl']
            object_lock = args['lock']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.create_bucket(bucket_name=bucket_name, acl=acl, lock=object_lock)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_create_bucket: %s", args['uid'])
            raise error
        finally:
            msg_action = ' create_bucket: ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_buckets.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                # db_collection = get_database_mongo()
                get_database_mongo().insert_one(data)
                # db_collection.insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_create_bucket.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_bucket(self, **args):
        try:
            logger.info("do_delete_bucket: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_bucket(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_bucket: %s", args['uid'])
            raise error
        finally:
            msg_action = 'delete_bucket: ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_buckets.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                # db_collection = get_database_mongo()
                get_database_mongo().insert_one(data)
                # db_collection.insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_bucket.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()
