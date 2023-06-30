from flask import Flask, jsonify
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import default_exceptions
from flask_cors import CORS
from config import CONF
from app.logging_action import logger
# from models import Users, ActionLogs
from datetime import timedelta

env_host = CONF.config['s3_be_host']
env_port = CONF.config['s3_be_port']

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = CONF.config['uri']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = CONF.config['modifications']
app.config['BUNDLE_ERRORS'] = CONF.config['bundle_errors']
app.config['SECRET_KEY'] = CONF.config['secret']
app.config["sqlalchemy_pool_size"] = CONF.config["sqlalchemy_pool_size"]
app.config["sqlalchemy_max_overflow"] = CONF.config["sqlalchemy_max_overflow"]
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)     # set time out sessions
db = SQLAlchemy(app)
# migrate = Migrate(app, db)
# db.create_all()

# accept CORS
# CORS(app)
CORS(app, resources={r'/api/*': {'origins': '*'}})


@app.errorhandler(Exception)
def handle_error(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
    return jsonify(error=str(e)), code


for ex in default_exceptions:
    app.register_error_handler(ex, handle_error)


# accept API
api = Api(app)
api.prefix = '/api'

from app.api.v1 import hello
from app.api.v1.user import User
from app.api.v1.user import Users
from app.api.v1.user import UserAuth
from app.api.v1.user import UserAuthTwoFA
from app.api.v1.user import UserQuota
from app.api.v1.user import UserKey
from app.api.v1.user import UserAdmin
from app.api.v1.bucket import Bucket
from app.api.v1.bucket import Buckets
from app.api.v1.object import Object
from app.api.v1.object import Objects
from app.api.v1.object import ObjectFolder
from app.api.v1.object import ObjectPermission
from app.api.v1.object import ObjectStaticWeb
from app.api.v1.object import ObjectCors
from app.api.v1.object import ObjectLifecycle
from app.api.v1.object import ObjectVersioning
from app.api.v1.object import ObjectDetails
from app.api.v1.object import ObjectPolicy
from app.api.v1.log import Log


api.add_resource(hello.HelloResource, '/', '/hello')          # test api
api.add_resource(User, '/user/<string:uid>', '/user')
api.add_resource(Users, '/users', '/users')
api.add_resource(UserAdmin, '/admin/signin/<string:uid>', '/admin/signin')  # admin signin end user
api.add_resource(UserAuth, '/user/auth', '/user/auth')
api.add_resource(Log, '/log/<string:uid>', '/log')
api.add_resource(UserAuthTwoFA, '/user/auth/twofactor', '/user/auth/twofactor')
api.add_resource(UserQuota, '/user/quota/<string:uid>', '/user/quota')
api.add_resource(UserKey, '/user/key/<string:uid>/<string:access_key>', '/user/key')
api.add_resource(Bucket, '/bucket/<string:bucket_name>', '/bucket')
api.add_resource(Buckets, '/buckets', '/buckets')
api.add_resource(Object, '/object', '/object')
api.add_resource(Objects, '/objects', '/objects')
api.add_resource(ObjectDetails, '/object/details', '/object/details')
api.add_resource(ObjectFolder, '/object/folder', '/object/folder')
api.add_resource(ObjectPermission, '/object/permission', '/object/permission')
api.add_resource(ObjectStaticWeb, '/object/static/<string:bucket_name>', '/object/static')
api.add_resource(ObjectCors, '/object/cors/<string:bucket_name>', '/object/cors')
api.add_resource(ObjectLifecycle, '/object/lifecycle/<string:bucket_name>', '/object/lifecycle')
api.add_resource(ObjectVersioning, '/object/versioning', '/object/versioning')
api.add_resource(ObjectPolicy, '/object/policy/<string:bucket_name>', '/object/policy')

if __name__ == '__main__':
    # create db
    # from models import ActionLogs
    # al = ActionLogs()
    # db.create_all()
    # db.session.add(al)

    # write log
    # logging.basicConfig(filename='/var/log/s3-be-api/s3-be.log', level=logging.DEBUG)
    # logger.debug('This message should go to the log file')
    # logger.info("This message should go to the log file")
    # logger.warning("This message should go to the log file")

    # run app
    app.run(debug=True, host=env_host, port=env_port)
    # app.run(host='0.0.0.0', port=5002)
