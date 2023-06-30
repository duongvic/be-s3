from flask_restful import Resource
from app.services.log.controller import LogController
from webargs.flaskparser import use_args
import json
from app.api.v1 import base

log = LogController()
auth = base.auth


class Log(Resource):

    # @use_args(base.KEY_BUCKET_ARGS, location='headers')
    @auth.login_required
    def get(self):
        args = auth.current_user()
        uid = args['uid']
        # if args['role'] == 'ADMIN':
        #     return user.get_all_user(**args)
        # return {'code': 403, 'message': "You are not authorized to perform the requested action", 'data': None}
        return log.log_user(uid)
