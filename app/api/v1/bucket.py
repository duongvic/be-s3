from flask_restful import Resource
from app.services.bucket.controller import BucketController
from webargs import fields, validate
from webargs.flaskparser import use_args
from app.api.v1 import base

bucket = BucketController()
auth = base.auth


class Bucket(Resource):

    get_bucket_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=False, missing=None)
    }

    post_bucket_args = {
        'bucket_name': fields.Str(required=True),
        'acl': fields.Str(required=True, validate=validate.OneOf(['private', "public-read"])),
        'lock': fields.Boolean(required=True)
    }

    # search by bucket_name
    @auth.login_required
    # @use_args(get_bucket_args, location='headers')
    def get(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        response = bucket.do_list_buckets(**user)
        return response

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    @use_args(post_bucket_args, location='json')
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        response = bucket.do_create_bucket(**user)
        return response

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    def delete(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        response = bucket.do_delete_bucket(**user)
        return response


class Buckets(Resource):

    # search all
    @auth.login_required
    def get(self):
        user = auth.current_user()
        user['bucket_name'] = None
        response = bucket.do_list_buckets(**user)
        return response
