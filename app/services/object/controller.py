#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from foxcloud.v1.services.s3 import client
from config import CONF
import botocore
from app.logging_action import logger
from app.mongodb import get_database_mongo
import datetime

fox_init = CONF.config['s3_fox_cloud']
use_log_pg = CONF.config['use_log_pg']
use_log_mg = CONF.config['use_log_mg']
static_web_url = CONF.config['static_web_url']


class ObjectController:

    def do_downlod_file(self, **args):
        try:
            logger.info("do_download_file: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            key = args['key']
            version_id = args['version_id']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.download_file(bucket_name=bucket_name, key=key, version_id=version_id)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_download_file: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_downlod_file.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_downlod_file.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_upload_file(self, **args):
        try:
            logger.info("do_upload_file: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            param = dict(args)
            folder_key = args['folder_key']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            for file in param['files']:
                file_byte = file.read()
                key = file.filename
                if folder_key:
                    key = folder_key + '/' + file.filename
                context_type = file.content_type
                bucket_name = param['bucket_name']
                acl = param['acl']
                response = bucket.upload_file(bucket_name=bucket_name, key=key, acl=acl, file_name=file_byte,
                                              content_type=context_type)._info
            return response
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_upload_file: %s", args['uid'])
            raise error
        finally:
            msg_action = ' upload file: ' + str(param['files'])
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_upload_file.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                    "date_test": datetime.datetime.now()
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_upload_file.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_object(self, **args):
        try:
            logger.info("do_delete_object: %s", args['uid'])
            msg_status = 200
            msg_action = ''
            twofa_token = args['twofa_token']
            bucket_name = args['bucket_name']
            key = args['key']
            version_id = args['version_id']

            from app.api.models import Users, ActionLogs, db
            user = Users.query.filter_by(username=args['uid']).first()

            if user.enable_two_factors and not user.verify_totp(twofa_token):
                msg_action = "twofa_token, wrong data: {}.".format(twofa_token)
                msg_status = 404
                return {'code': 404, 'message': msg_action, 'data': None}

            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_object(bucket_name=bucket_name, key=key, version_id=version_id)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_object: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete file: ' + key
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_object.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_object.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_object_all(self, **args):
        try:
            logger.info("do_delete_object_all: %s", args['uid'])
            msg_status = 200
            msg_action = ''
            twofa_token = args['twofa_token']
            bucket_name = args['bucket_name']
            keys = args['keys']

            from app.api.models import Users, ActionLogs, db
            user = Users.query.filter_by(username=args['uid']).first()

            if user.enable_two_factors and not user.verify_totp(twofa_token):
                msg_action = "twofa_token, wrong data: {}.".format(twofa_token)
                msg_status = 404
                return {'code': 404, 'message': msg_action, 'data': None}

            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_object_all(bucket_name=bucket_name, keys=keys)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_object_all: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete multi file: ' + str(keys)
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_object_all.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_object_all.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_create_folder(self, **args):
        try:
            logger.info("do_create_folder: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            folder_key = args['folder_key']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.create_folder(bucket_name=bucket_name, folder_key=folder_key)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_create_folder: %s", args['uid'])
            raise error
        finally:
            msg_action = ' create folder: ' + folder_key
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_create_folder.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_create_folder.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_copy_object(self, **args):
        try:
            logger.info("do_copy_object: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            src_bucket = args['src_bucket']
            src_key = args['src_key']
            des_bucket = args['des_bucket']
            des_key = args['des_key']
            version_id = args['version_id']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.copy_object(src_bucket=src_bucket, src_key=src_key, des_bucket=des_bucket, des_key=des_key,
                                     version_id=version_id)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_copy_object: %s", args['uid'])
            raise error
        finally:
            msg_action = ' copy file to: ' + des_key
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_copy_object.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_copy_object.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_share_file(self, **args):
        try:
            logger.info("do_share_file: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            key = args['key']
            time = args['time']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.share_file(bucket_name=bucket_name, key=key, time=time)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_share_file: %s", args['uid'])
            raise error
        finally:
            msg_action = ' share file: ' + key + ', time: ' + str(time)
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_share_file.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_share_file.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()


    def do_permission_object(self, **args):
        try:
            logger.info("do_permission_object: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            key = args['key']
            acl = args['acl']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.permission_object(bucket_name=bucket_name, key=key, acl=acl)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_permission_object: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set permission : ' + bucket_name + ' key: ' + str(key) + ', acl: ' + acl
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_permission_object.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_permission_object.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()


    def do_get_lifecycle(self, **args):
        try:
            logger.info("do_get_lifecycle: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.get_lifecycle(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_get_lifecycle: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_get_lifecycle.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_get_lifecycle.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_set_lifecycle(self, **args):
        try:
            logger.info("do_set_lifecycle: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            objs = args['objs']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.set_lifecycle(bucket_name=bucket_name, objs=objs)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_set_lifecycle: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set lifecycle : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_set_lifecycle.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_set_lifecycle.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_edit_lifecycle(self, **args):
        try:
            logger.info("do_edit_lifecycle: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            obj = args['obj']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.edit_lifecycle(bucket_name=bucket_name, obj=obj)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_edit_lifecycle: %s", args['uid'])
            raise error
        finally:
            msg_action = ' edit lifecycle : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_edit_lifecycle.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_edit_lifecycle.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_lifecycle(self, **args):
        try:
            logger.info("do_delete_lifecycle: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            config_id = args['config_id']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_lifecycle(bucket_name=bucket_name, config_id=config_id)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_lifecycle: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete lifecycle : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_lifecycle.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_lifecycle.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()


    def do_get_cors(self, **args):
        try:
            logger.info("do_get_cors: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.get_cors(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_get_cors: %s", args['uid'])
            raise error
        finally:
            # msg_action = ' delete lifecycle : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_get_cors.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_get_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_set_cors(self, **args):
        try:
            logger.info("do_set_cors: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            objs = args['objs']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.set_cors(bucket_name=bucket_name, objs=objs)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_set_cors: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set cors : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_set_cors.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_set_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_edit_cors(self, **args):
        try:
            logger.info("do_edit_cors: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            obj = args['obj']
            # objs = args['objs']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.edit_cors(bucket_name=bucket_name, obj=obj)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_edit_cors: %s", args['uid'])
            raise error
        finally:
            msg_action = ' edit cors : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_edit_cors.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_edit_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_cors(self, **args):
        try:
            logger.info("do_delete_cors: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            config_id = args['config_id']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_cors(bucket_name=bucket_name, config_id=config_id)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_cors: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete cors : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_cors.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_get_static_website(self, **args):
        try:
            logger.info("do_get_static_website: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.get_static_website(bucket_name=bucket_name, static_web_url=static_web_url)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_get_static_website: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_get_static_website.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_get_static_website.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_set_static_website(self, **args):
        try:
            logger.info("do_set_static_website: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            index_file = args['index_file']
            error_file = args['error_file']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.set_static_website(bucket_name=bucket_name, index_file=index_file, error_file=error_file,
                                             static_web_url= static_web_url)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_set_static_website: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set static website : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_set_static_website.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_set_static_website.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_static_website(self, **args):
        try:
            logger.info("do_delete_static_website: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_static_website(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_static_website: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete static website : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_static_website.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_static_website.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_list_versioning(self, **args):
        try:
            logger.info("do_list_versioning: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            key = args['key']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.list_versioning(bucket_name=bucket_name, key=key)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_list_versioning: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_versioning.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_list_versioning.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_set_versioning(self, **args):
        try:
            logger.info("do_set_versioning: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            status = args['status']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'HEAT'

            bucket = client.StorageManager(**fox_init)
            return bucket.set_versioning(bucket_name=bucket_name, status=status)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_set_versioning: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set versioning : ' + bucket_name + ' ,status: ' + str(status)
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_set_versioning.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_set_versioning.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()


    def do_list_objects(self, **args):
        try:
            logger.info("do_list_objects: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            prefix = args['prefix']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.list_objects(bucket_name=bucket_name, prefix=prefix)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_list_objects: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_objects.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_list_objects.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_list_folder(self, **args):
        try:
            logger.info("do_list_folder: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            prefix = args['prefix']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.list_folder(bucket_name=bucket_name, prefix=prefix)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_list_folder: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_list_folder.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_list_folder.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_get_policy(self, **args):
        try:
            logger.info("do_get_policy: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.get_policy(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_get_policy: %s", args['uid'])
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_get_policy.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_get_policy.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_set_policy(self, **args):
        try:
            logger.info("do_set_policy: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            effect = args['effect']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.set_policy(bucket_name=bucket_name, effect=effect)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_set_policy: %s", args['uid'])
            raise error
        finally:
            msg_action = ' set policy : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_set_policy.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_set_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_delete_policy(self, **args):
        try:
            logger.info("do_delete_policy: %s", args['uid'])
            msg_status = 200
            msg_action = ''

            bucket_name = args['bucket_name']
            fox_init['access_key'] = args['access_key']
            fox_init['secret_key'] = args['secret_key']
            fox_init['engine'] = 'CONSOLE'

            bucket = client.StorageManager(**fox_init)
            return bucket.delete_policy(bucket_name=bucket_name)._info
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("do_delete_policy: %s", args['uid'])
            raise error
        finally:
            msg_action = ' delete policy : ' + bucket_name
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.do_delete_policy.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=args['uid'], fnc_name=self.do_delete_cors.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()
