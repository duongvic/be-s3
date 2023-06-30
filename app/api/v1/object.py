from flask_restful import Resource
from app.services.object.controller import ObjectController
from webargs import fields, validate
from webargs.flaskparser import use_args
from flask import request, make_response
from app.api.v1 import base
from marshmallow import Schema

obj = ObjectController()
auth = base.auth


class Object(Resource):

    upload_objects_args = {
        'bucket_name': fields.Str(required=True),
        'acl': fields.Str(required=True, validate=validate.OneOf(['private', "public-read"])),
        'folder_key': fields.Str(required=False, missing=None)
    }

    files_args = {
        'objs': fields.Field(required=True)
    }

    download_object_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'key': fields.Str(required=True),
        'version_id': fields.Str(required=False, missing=None)
    }

    delete_object_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'key': fields.Str(required=True),
        'version_id': fields.Str(required=False, missing=None),
        'twofa_token': fields.Str(required=False, missing=None)
    }

    @use_args(download_object_args, location='headers')
    @auth.login_required
    def get(self, args):
        user = auth.current_user()
        user.update(args)
        responses = obj.do_downlod_file(**user)
        body = responses['Body']
        response = make_response(body.read())
        response.headers['Content-type'] = responses['ContentType']
        return response

    @use_args(upload_objects_args, location='form')
    @use_args(files_args, location='files')
    @auth.login_required
    def post(self, form_parsed, args_file):
        files = request.files.getlist("objs")
        # form_parsed['files'] = files
        # form_parsed.update(headers_parsed)
        user = auth.current_user()
        user.update(form_parsed)
        user['files'] = files
        response = obj.do_upload_file(**user)
        return response

    @use_args(delete_object_args, location='headers')
    @auth.login_required
    def delete(self, args):
        user = auth.current_user()
        user.update(args)
        response = obj.do_delete_object(**user)
        return response


class Objects(Resource):
    delete_objects_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'keys': fields.DelimitedList(fields.Str(), required=True),  # multi key
        'twofa_token': fields.Str(required=False, missing=None)
    }

    @use_args(delete_objects_args, location='headers')
    @auth.login_required
    def delete(self, args):
        user = auth.current_user()
        user.update(args)
        responses = obj.do_delete_object_all(**user)
        return responses


class ObjectDetails(Resource):
    get_object_details_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'prefix': fields.Str(required=False, missing=None)
    }

    @use_args(get_object_details_args, location='headers')
    @auth.login_required
    def get(self, args):
        user = auth.current_user()
        user.update(args)
        responses = obj.do_list_objects(**user)
        return responses


class ObjectFolder(Resource):

    get_list_folder_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'prefix': fields.Str(required=False, missing=None)
    }

    create_folder_args = {
        'bucket_name': fields.Str(required=True),
        'folder_key': fields.Str(required=True)
    }

    copy_file_args = {
        'src_bucket': fields.Str(required=True),
        'src_key': fields.Str(required=True),
        'des_bucket': fields.Str(required=True),
        'des_key': fields.Str(required=True),
        'version_id': fields.Str(required=False, missing=None)
    }

    @use_args(get_list_folder_args, location='headers')
    @auth.login_required
    def get(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_list_folder(**user)

    @use_args(create_folder_args, location='json')
    @auth.login_required
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_create_folder(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(copy_file_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_copy_object(**user)


class ObjectPermission(Resource):

    set_object_permission_args = {
        'bucket_name': fields.Str(required=True),
        'key': fields.Str(required=False, missing=None),
        'acl': fields.Str(required=True, validate=validate.OneOf(['private', "public-read"]))
    }

    share_object_permission_args = {
        'bucket_name': fields.Str(required=True),
        'key': fields.Str(required=True),
        # 'time': fields.Int(required=True, validate=[validate.Range(min=1, max=43200)])  # 1ph - 12h
        'time': fields.Int(required=True, validate=[validate.Range(min=1)])
    }

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(set_object_permission_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_permission_object(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(share_object_permission_args, location='json')
    @auth.login_required
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_share_file(**user)


class ObjectStaticWeb(Resource):

    set_static_web_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'index_file': fields.Str(required=True),
        'error_file': fields.Str(required=True)
    }

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    def get(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_get_static_website(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(set_static_web_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_set_static_website(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    # @use_args(delete_static_web_args, location='json')
    @auth.login_required
    def delete(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_delete_static_website(**user)


class ObjCorsSchema(Schema):
    ID = fields.Str(required=True)
    AllowedMethods = fields.DelimitedList(fields.Str(), required=True)
    AllowedOrigins = fields.DelimitedList(fields.Str(), required=True)
    AllowedHeaders = fields.DelimitedList(fields.Str(), required=True)
    MaxAgeSeconds = fields.Int(required=True)


class ObjectCors(Resource):

    set_cors_args = {
        'bucket_name': fields.Str(required=True),
        'objs': fields.List(fields.Nested(ObjCorsSchema))
    }

    edit_cors_args = {
        'bucket_name': fields.Str(required=True),
        'obj': fields.Nested(ObjCorsSchema)
    }

    delete_cors_args = {
        # **base.KEY_BUCKET_ARGS,
        'config_id': fields.Str(required=False, missing=None)
    }

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    def get(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_get_cors(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(set_cors_args, location='json')
    @auth.login_required
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_set_cors(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(edit_cors_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_edit_cors(**user)

    @use_args(delete_cors_args, location='headers')
    @auth.login_required
    def delete(self, args, bucket_name):
        user = auth.current_user()
        user.update(args)
        user['bucket_name'] = bucket_name
        return obj.do_delete_cors(**user)


class ExpirationSchema(Schema):
    Days = fields.Int(required=True)


class ObjLifeCycleSchema(Schema):
    ID = fields.Str(required=True)
    Prefix = fields.Str(required=True)
    Status = fields.Str(required=True)
    Expiration = fields.Nested(ExpirationSchema)


class ObjectLifecycle(Resource):

    set_lifecycle_args = {
        'bucket_name': fields.Str(required=True),
        'objs': fields.List(fields.Nested(ObjLifeCycleSchema()))
    }

    edit_lifecycle_args = {
        'bucket_name': fields.Str(required=True),
        'obj': fields.Nested(ObjLifeCycleSchema())
    }

    delete_lifecycle_args = {
        # **base.KEY_BUCKET_ARGS,
        'config_id': fields.Str(required=False, missing=None)
    }

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    def get(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_get_lifecycle(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(set_lifecycle_args, location='json')
    @auth.login_required
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_set_lifecycle(**user)

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(edit_lifecycle_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_edit_lifecycle(**user)

    @use_args(delete_lifecycle_args, location='headers')
    @auth.login_required
    def delete(self, args, bucket_name):
        user = auth.current_user()
        user.update(args)
        user['bucket_name'] = bucket_name
        return obj.do_delete_lifecycle(**user)


class ObjectVersioning(Resource):
    get_list_versioning_args = {
        # **base.KEY_BUCKET_ARGS,
        'bucket_name': fields.Str(required=True),
        'key': fields.Str(required=True)
    }

    set_versioning_args = {
        'bucket_name': fields.Str(required=True),
        'status': fields.Boolean(required=True)
    }

    @use_args(get_list_versioning_args, location='headers')
    @auth.login_required
    def get(self, args):
        user = auth.current_user()
        user.update(args)
        response = obj.do_list_versioning(**user)
        return response

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @use_args(set_versioning_args, location='json')
    @auth.login_required
    def put(self, args):
        user = auth.current_user()
        user.update(args)
        response = obj.do_set_versioning(**user)
        return response


class ObjectPolicy(Resource):

    set_policy_args = {
        'bucket_name': fields.Str(required=True),
        'effect': fields.Str(required=True, validate=validate.OneOf(['Allow', "Deny"]))
    }

    @auth.login_required
    def get(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_get_policy(**user)

    @use_args(set_policy_args, location='json')
    @auth.login_required
    def post(self, args):
        user = auth.current_user()
        user.update(args)
        return obj.do_set_policy(**user)

    @auth.login_required
    def delete(self, bucket_name):
        user = auth.current_user()
        user['bucket_name'] = bucket_name
        return obj.do_delete_policy(**user)
