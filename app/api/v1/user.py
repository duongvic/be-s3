from flask_restful import Resource
from app.services.user.controller import UserController
from webargs import fields, validate
from webargs.flaskparser import use_args
import json
from app.api.v1 import base
from config import CONF
from flask import session, redirect, url_for

user = UserController()
auth = base.auth

max_buckets = CONF.config['max_buckets']


class UserAuth(Resource):

    login_user_args = {
        'uid': fields.Str(required=True),
        'password': fields.Str(required=True, validate=validate.Length(min=6))      # password=access_key
        # 'secret_key': fields.Str(required=True),
    }

    reset_otp_user = {
        'uid': fields.Str(required=True)
    }

    @use_args(login_user_args, location='headers')
    def get(self, args):
        response = user.login_user(**args)
        # remove cookies session
        # if response['code'] == 200:
        #     session['uid'] = args['uid']
        #     session['password'] = args['password']
        #     session['logged_in'] = True
        return response

    @use_args(reset_otp_user, location='json')
    @auth.login_required
    def post(self, args):
        user_rq = auth.current_user()
        user_rq.update(args)
        if user_rq['role'] == 'ADMIN':
            return user.reset_otp_user(**user_rq)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}


class UserAuthTwoFA(Resource):

    twofa_user_args = {
        # 'uid': fields.Str(required=True),
        # 'password': fields.Str(required=True, validate=validate.Length(min=6)),      # password=access_key
        # 'enable_two_factors': fields.Boolean(required=True),
        'twofa_token': fields.Str(required=True)
    }

    @use_args(twofa_user_args, location='headers')
    @auth.login_required
    def get(self, args):
        # if session and session['logged_in']:
        #     # print(session)
        #     args['uid'] = session['uid']
        #     args['password'] = session['password']
        #     response = user.authen_twofa_user(**args)
        #     return response
        # return {'code': 404, 'message': "You are not logged in", 'data': None}
        user_rq = auth.current_user()
        if user_rq['logged_in']:
            user_rq.update(args)
            return user.authen_twofa_user(**user_rq)
        return {'code': 404, 'message': "You are not logged in", 'data': None}


class UserQuota(Resource):

    set_quota_user_args = {
        'uid': fields.Str(required=True),
        'quota_type': fields.Str(required=False, missing='user'),
        'enabled': fields.Int(required=False, missing=1),
        'max_size_kb': fields.Int(required=True),
        'max_objects': fields.Int(required=False, missing=-1)
    }

    @auth.login_required
    def get(self, uid):
        user_rq = auth.current_user()
        if user_rq['user_id'] == uid:
            return user.get_quota_user(**user_rq)
        else:
            if user_rq['role'] == 'ADMIN':
                user_rq['uid'] = uid
                return user.get_quota_user(**user_rq)
            return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}

    @use_args(set_quota_user_args, location='json')
    @auth.login_required
    def put(self, args):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.set_quota_user(**args)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}


class User(Resource):

    create_user_args = {
        'uid': fields.Str(required=True),
        # 'password': fields.Str(required=True),  # password=access_key
        'display_name': fields.Str(required=True),
        'email': fields.Str(required=True),
        'max_size_kb': fields.Int(required=True),
        'max_buckets': fields.Int(required=False, missing=max_buckets)
    }

    edit_user_args = {
        'uid': fields.Str(required=True),
        'display_name': fields.Str(required=True),
        'email': fields.Str(required=True),
        'max_buckets': fields.Int(required=True),
        'suspended': fields.Boolean(required=True)
    }

    # @use_args(get_info_user_args, location='headers')
    @auth.login_required
    def get(self, uid):
        # response = user.get_info_user(uid)
        # return json.loads(response)
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.get_info_user(uid)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}

    @use_args(create_user_args, location='json')
    @auth.login_required
    def post(self, args):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.create_user(**args)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}

    @use_args(edit_user_args, location='json')
    @auth.login_required
    def put(self, args):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.edit_user(**args)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}

    # @use_args(delete_user_args, location='json')
    @auth.login_required
    def delete(self, uid):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.delete_user(uid)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}


class Users(Resource):

    @auth.login_required
    def get(self):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.get_all_user(**user_rq)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}


class UserKey(Resource):
    create_key_of_user_args = {
        'key_type': fields.Str(required=False, missing='s3'),
        'generate_key': fields.Int(required=False, missing=1),
        'uid': fields.Str(required=True)
    }

    @use_args(create_key_of_user_args, location='json')
    @auth.login_required
    def post(self, args):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.create_key_user(**args)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}

    # @use_args(delete_key_of_user_args, location='json')
    @auth.login_required
    def delete(self, uid, access_key):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.delete_key_user(uid, access_key)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}


class UserAdmin(Resource):
    # signin_end_user_args = {
    #     'uid': fields.Str(required=True)
    # }

    @auth.login_required
    def get(self, uid):
        user_rq = auth.current_user()
        if user_rq['role'] == 'ADMIN':
            return user.signin_end_user(uid)
        return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}
