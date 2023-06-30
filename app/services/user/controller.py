#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from app.exception import InputDataError
from app.helpers.ultis import gen_key
import requests
import json
import jwt
from config import CONF
from app.logging_action import logger
import datetime
import base64
import os
import pyqrcode
import io
from foxcloud.v1.services.s3 import client
from app.helpers.ultis import check_disk_space, convert_size
from app.mongodb import get_database_mongo
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

use_log_pg = CONF.config['use_log_pg']
use_log_mg = CONF.config['use_log_mg']

obj = CONF.config['s3_api']
request_auth = {
    "username": obj.get('username'),
    "password": obj.get('password')
}
host = obj.get('host')
fox_init = CONF.config['s3_fox_cloud']
jwt_time_out = CONF.config['jwt_time_out']


def auth():
    response_auth = requests.post(host + "/api/auth", json=request_auth)
    dict_user = json.loads(response_auth.text)
    auth_token = dict_user['token']
    headers = {'Authorization': 'Bearer ' + auth_token}
    return headers


class UserController:

    def login_user(self, **args):
        try:
            msg_status = 200
            msg_action = ''
            # check user in database
            uid = args['uid']
            password = args['password']
            logger.info("user login auth: %s", uid)
            from app.api.models import Users, ActionLogs, db
            user = Users.query.filter_by(username=uid).first()
            if user is not None and user.verify_password(password):
                my_secret_jwt = obj.get('my_secret_jwt')
                payload_data = {
                    'uid': uid,
                    'password': password,
                    'logged_in': True,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=jwt_time_out),  # set jwt time out
                    'iat': datetime.datetime.utcnow()
                }
                if user.enable_two_factors is False:
                    payload_data['otp_secret'] = user.otp_secret,
                    payload_data['qrcode'] = user.file_base64_string,
                    payload_data['two_fa'] = user.enable_two_factors,
                #     return {'code': 200, 'message': True, 'data': {}}
                # else:
                #     return {'code': 200, 'message': True, 'data': {'logged_in': True}}
                token = jwt.encode(
                    payload=payload_data,
                    key=my_secret_jwt
                )

                return {'code': 200, 'message': True, 'data': {'access_token': token}}
            else:
                msg_action = 'uid or password wrong'
                msg_status = 404
                raise InputDataError(msg_action)

        # except requests.exceptions.RequestException as error:
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("user login auth: %s", error)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.login_user.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                al = ActionLogs(user_name=uid, fnc_name=self.login_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def authen_twofa_user(self, **args):
        try:
            msg_status = 200
            msg_action = ""
            uid = args['uid']
            twofa_token = args['twofa_token']
            logger.info("user login twofa_token: %s", uid)
            from app.api.models import Users, db
            user = Users.query.filter_by(username=uid).first()
            if not user.verify_totp(twofa_token):
                # logger.info("user : %s", user)
                # logger.info("twofa_token : %s", twofa_token)
                msg_action = 'False'
                msg_status = 404
                return {'code': 404, 'message': "user twofa_token, wrong data: {}.".format(twofa_token), 'data': None}

            user_role = user.role
            user.enable_two_factors = True
            db.session.add(user)
            db.session.commit()

            # check user in s3
            api = host + "/api/rgw/user/{uid}".format(uid=uid)
            response = requests.get(api, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = "user auth, wrong data {}.".format(response.text)
                raise InputDataError(msg_action)

            # check key
            dict_user = json.loads(response.text)
            keys = dict_user['keys']
            for item in keys:
                if item['access_key'] == args['password']:
                    payload_data = {
                        "user_id": item['user'],
                        "uid": item['user'],
                        "access_key": item['access_key'],
                        "secret_key": item['secret_key'],
                        "role": user_role,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=jwt_time_out),  # set jwt time out
                        'iat': datetime.datetime.utcnow()
                    }
                    my_secret_jwt = obj.get('my_secret_jwt')
                    token = jwt.encode(
                        payload=payload_data,
                        key=my_secret_jwt
                    )
            return {'code': 200, 'message': True, 'data': {'access_token': token}}
        except Exception as error:
            msg_status = 500
            msg_action += str(error)
            logger.error("user login twofa_token: %s", error)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.authen_twofa_user.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.authen_twofa_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def create_user(self, **args):
        try:
            data = args
            # data['max_buckets'] = 1000
            data['suspended'] = 0
            data['generate_key'] = 1
            # data['access_key'] = gen_key(size=20)
            # data['access_key'] = args['password']  # unique access_key = password
            # data.pop('password', None)
            data['access_key'] = gen_key(size=10)
            data['secret_key'] = gen_key(size=40)
            max_size_kb = data['max_size_kb']
            data.pop('max_size_kb', None)
            logger.info("create_user: %s", data['uid'])

            msg_status = 200
            msg_action = ""
            # add user to s3
            from app.api.models import Users, ActionLogs, db
            response_create_user = requests.post(host + "/api/rgw/user", json=data, headers=auth())
            if response_create_user.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response_create_user.text)
                raise InputDataError(msg_action)

            # set quota
            quota_rq = {
                'uid': data['uid'],
                'quota_type': 'user',
                'enabled': 1,
                'max_size_kb': max_size_kb,
                'max_objects': -1
            }
            self.set_quota_user(**quota_rq)

            # add user to database (registry user)
            # from app.api.models import Users, ActionLogs, db
            user = Users(username=data['uid'], password=data['access_key'], fullname=data['display_name'],
                         email=data['email'])
            db.session.add(user)
            # db.session.flush()
            db.session.commit()
            return {'code': 201, 'message': True, 'data': {'user_s3': json.loads(response_create_user.text),
                                                           'user_db': user.result}}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("create_user: %s", error)
            raise error
        finally:
            msg_action = ' create user: ' + args['uid']
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.create_user.__name__,
                    "user_name": args['uid'],
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                al = ActionLogs(user_name=args['uid'], fnc_name=self.create_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def create_key_user(self, **args):
        try:
            uid = args['uid']
            logger.info("user login twofa_token: %s", uid)
            msg_status = 200
            msg_action = ""
            args.pop('uid', None)
            api = host + "/api/rgw/user/{}/key".format(uid)
            response = requests.post(api, json=args, headers=auth())

            if response.status_code == 500:
                msg_status = 400
                msg_action = ""
                raise InputDataError('Wrong data {}.'.format(response.text))
            return {'code': 201, 'message': True, 'data': {'key_user': json.loads(response.text)}}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("create_key_user: %s", error)
            raise error
        finally:
            msg_action = ' create key user: ' + uid
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.create_key_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.create_key_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def delete_key_user(self, uid, access_key):
        try:
            logger.info("delete_key_user: %s", uid)
            api = host + "/api/rgw/user/{uid}/key".format(uid=uid)
            payload = {
                'key_type': 's3',
                'subuser': '',
                'access_key': access_key
            }
            msg_status = 200
            msg_action = ""
            response = requests.delete(api, params=payload, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)
            return {'code': 204, 'message': response.ok, 'data': None}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("delete_key_user: %s", uid)
            raise error
        finally:
            msg_action = ' delete key user: ' + uid
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.delete_key_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.delete_key_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def get_info_user(self, uid):
        try:
            logger.info("get_info_user: %s", uid)
            api = host + "/api/rgw/user/{uid}".format(uid=uid)
            msg_status = 200
            msg_action = ""
            response = requests.get(api, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)

            # response
            res = json.loads(response.text)
            # access_key = user_info['data']['user']['keys'][0]['access_key']
            # secret_key = user_info['data']['user']['keys'][0]['secret_key']
            # max_buckets = user_info['data']['user']['max_buckets']

            us = {
                'access_key': res['keys'][0]['access_key'],
                'secret_key': res['keys'][0]['secret_key'],
                'max_buckets': res['max_buckets'],
                # 'max_size_kb': res['user_quota']['max_size_kb'],
                'max_size_kb': res['user_quota']['max_size'],
                'active': True if res['suspended'] == 0 else False,
                'display_name': res['display_name'],
                'email': res['email']
            }
            # return {'code': 200, 'message': True, 'data': {'user': json.loads(response.text)}}
            return {'code': 200, 'message': True, 'data': {'user': us}}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("get_info_user: %s", uid)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.get_info_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.get_info_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def get_quota_user(self, **args):
        try:
            # TODO check uid input
            uid = args['uid']
            logger.info("get_quota_user: %s", uid)
            args.pop('uid', None)
            msg_status = 200
            msg_action = ""

            # get info user
            api = host + "/api/rgw/user/{uid}".format(uid=uid)
            response = requests.get(api, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)

            total_user_disk = json.loads(response.text)['user_quota']['max_size']
            access_key = json.loads(response.text)['keys'][0]['access_key']
            secret_key = json.loads(response.text)['keys'][0]['secret_key']

            # get use quota
            fox_init['access_key'] = access_key
            fox_init['secret_key'] = secret_key
            fox_init['engine'] = 'CONSOLE'
            bucket = client.StorageManager(**fox_init)
            quota = bucket.get_quota()._info['data']
            logger.info("get quota: ", uid, quota)
            # print(("get quota: ", uid, quota))
            if quota:
                quota_use = quota['sum_sizes']
                quota['total_disk'] = total_user_disk
                msg = check_disk_space(quota_use, total_user_disk)
                quota_use_str = convert_size(quota_use)
                quota_total_str = convert_size(total_user_disk)
                quota['msg'] = msg
                quota['quota_use_str'] = quota_use_str
                quota['quota_total_str'] = quota_total_str
                return {'code': 200, 'message': True, 'data': {'quota': quota}}
            return {'code': 400, 'message': False, 'data': None}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("get_quota_user: %s", uid)
            raise error
        finally:
            # msg_action = ' delete key user: ' + args['uid']
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.get_quota_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.get_quota_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def set_quota_user(self, **args):
        try:
            uid = args['uid']
            logger.info("set_quota_user: %s", uid)
            msg_status = 200
            msg_action = ""
            args.pop('uid', None)
            api = host + "/api/rgw/user/{uid}/quota".format(uid=uid)
            response = requests.put(api, json=args, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)
            return {'code': 200, 'message': response.ok, 'data': None}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("set_quota_user: %s", uid)
            raise error
        finally:
            msg_action = ' set quota user: ' + uid + ' , max_size_kb = ' + str(args['max_size_kb'])
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.set_quota_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.set_quota_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def delete_user(self, uid):
        try:
            logger.info("delete_user: %s", uid)
            api = host + "/api/rgw/user/{}".format(uid)
            response = requests.delete(api, headers=auth())
            msg_status = 200
            msg_action = ""
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)
            return {'code': 204, 'message': response.ok, 'data': None}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("delete_user: %s", uid)
            raise error
        finally:
            msg_action = ' delete user: ' + uid
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.delete_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.delete_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def edit_user(self, **args):
        try:
            uid = args['uid']
            logger.info("edit_user: %s", uid)
            msg_status = 200
            msg_action = ""
            args.pop('uid', None)
            api = host + "/api/rgw/user/{}".format(uid)

            response = requests.put(api, json=args, headers=auth())
            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)
            return {'code': 200, 'message': True, 'data': {'user': json.loads(response.text)}}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("edit_user: %s", uid)
            raise error
        finally:
            msg_action = ' edit user: ' + uid
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.edit_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.edit_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def signin_end_user(self, uid):
        try:
            logger.info("signin_end_user: %s", uid)
            msg_status = 200
            msg_action = ""
            from app.api.models import Users, ActionLogs, db
            user = Users.query.filter_by(username=uid).first()
            if user is None:
                msg_status = 400
                msg_action = 'not exists user: {}.'.format(uid)
                raise InputDataError(msg_action)
            user_role = user.role
            # get info user
            api = host + "/api/rgw/user/{uid}".format(uid=uid)
            response = requests.get(api, headers=auth())

            if response.status_code == 500:
                msg_status = 400
                msg_action = 'Wrong data {}.'.format(response.text)
                raise InputDataError(msg_action)

            keys = json.loads(response.text)['keys'][0]
            payload_data = {
                "user_id": keys['user'],
                "uid": keys['user'],
                "access_key": keys['access_key'],
                "secret_key": keys['secret_key'],
                "role": user_role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),  # set jwt time out
                'iat': datetime.datetime.utcnow()
            }
            my_secret_jwt = obj.get('my_secret_jwt')
            token = jwt.encode(
                payload=payload_data,
                key=my_secret_jwt
            )
            return {'code': 200, 'message': True, 'data': {'access_token': token}}

        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("signin_end_user: %s", uid)
            raise error
        finally:
            msg_action = ' signin end user: ' + uid
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.signin_end_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.signin_end_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def get_all_user(self, **args):
        try:
            # check user in database
            uid = args['uid']
            role = args['role']
            logger.info("get_all_user: %s", uid)
            from app.api.models import Users, ActionLogs, db
            # if role and role == 'ADMIN':
            # TODO compare user database # user s3
            user = db.session.query(Users).all()
            msg_status = 200
            msg_action = ''
            if user is not None:
                results = [self.do_mapping_object(item) for item in user]
                # get_info_user
                # print("INFO")
                # print(results)
                logger.info("results: %s", results)
                # data_info = []
                for item in results:
                    user_info = self.get_info_user(item['uid'])
                    # print(user_info)
                    logger.info("user_info: %s", user_info)
                    max_buckets = user_info['data']['user']['max_buckets']
                    max_size_kb = user_info['data']['user']['max_size_kb']
                    active = user_info['data']['user']['active']
                    quota_total_str = convert_size(max_size_kb)

                    # response
                    item['max_buckets'] = max_buckets
                    # item['role'] = role
                    item['quota'] = quota_total_str
                    item['active'] = active
                    item['display_name'] = user_info['data']['user']['display_name']
                    item['email'] = user_info['data']['user']['email']

                return {'code': 200, 'message': True, 'data': results, 'total': len(results)}

        # except requests.exceptions.RequestException as error:
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("get_all_user: %s", error)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.get_all_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                al = ActionLogs(user_name=uid, fnc_name=self.get_all_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def reset_otp_user(self, **args):
        try:
            # check user in database
            uid = args['uid']
            role = args['role']
            logger.info("reset_otp_user: %s", uid)
            msg_status = 200
            msg_action = ''
            from app.api.models import Users, ActionLogs, db
            if role and role == 'ADMIN':
                user = Users.query.filter_by(username=uid).first()

                if user is not None:
                    otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
                    qrcode = 'otpauth://totp/s3.fptvds.vn:{0}?secret={1}&issuer=s3.fptvds.vn'.format(uid, otp_secret)
                    # print(qrcode)
                    url = pyqrcode.create(qrcode)
                    file = io.BytesIO()
                    url.png(file, scale=6)
                    # Insert "encoded" into the database
                    encoded = base64.b64encode(file.getvalue()).decode("ascii")
                    user.otp_secret = otp_secret
                    user.file_base64_string = encoded
                    user.enable_two_factors = False
                    db.session.add(user)
                    db.session.commit()
                    return {'code': 200, 'message': True, 'data': None}
                else:
                    msg_action = 'uid or password wrong'
                    msg_status = 404
                    raise InputDataError(msg_action)

        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("reset_otp_user: %s", error)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.login_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                al = ActionLogs(user_name=uid, fnc_name=self.login_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_mapping_object(self, data):
        results = {
            "uid": data.username,
            # "otp_secret": data.otp_secret,
            "role": data.role,
            # "file_secret": data.file_base64_string
        }
        return results
