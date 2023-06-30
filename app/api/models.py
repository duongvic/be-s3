import base64
from werkzeug.security import generate_password_hash, check_password_hash
import onetimepass
from datetime import datetime
import bcrypt
import pyqrcode
import png
from pyqrcode import QRCode
from io import BytesIO
import io
import os
from app.logging_action import logger

from app.api.api import db
from app.helpers.ultis import jwt_decode_token


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200))
    email = db.Column(db.String(100), unique=True, nullable=False)
    fullname = db.Column(db.String(200))
    status = db.Column(db.Boolean())
    enable_two_factors = db.Column(db.Boolean(), default=False)
    role = db.Column(db.String(100), default='USER')
    otp_secret = db.Column(db.String(100))
    # otp_secret = db.Column(db.String(100), default=base64.b32encode(os.urandom(10)).decode('utf-8'))
    # file = db.Column(db.LargeBinary(length=2048))
    file_base64_string = db.Column(db.Text)  # luu file qrcode dang base64 string
    # url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow())
    updated_at = db.Column(db.DateTime)

    def __init__(self, **kwargs):
        super(Users, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            # gen qrcode
            qrcode = 'otpauth://totp/s3.fptvds.vn:{0}?secret={1}&issuer=s3.fptvds.vn'.format(self.username,
                                                                                             self.otp_secret)
            url = pyqrcode.create(qrcode)
            file = io.BytesIO()
            url.png(file, scale=6)
            # Insert "encoded" into the database
            encoded = base64.b64encode(file.getvalue()).decode("ascii")
            # print(encoded)
            self.file_base64_string = encoded
            # Retrieve encoded from the database...
            # byteString = base64.b64decode(encoded)
            # print(byteString)

        result = dict()
        for key in kwargs:
            val = getattr(self, key, None)
            if isinstance(val, Users):
                result[key] = val.to_dict(None)
            elif isinstance(val, datetime):
                result[key] = val.strftime('%Y-%m-%d %H:%M')
            else:
                result[key] = val
        result.pop('password', None)
        self.result = result

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        # self.password_hash = generate_password_hash(password)
        password = password.encode('utf-8')
        salt = bcrypt.gensalt(10)
        self.password_hash = bcrypt.hashpw(password, salt)

    def verify_password(self, password):
        # return check_password_hash(self.password_hash, password)
        pass_input = password.encode('utf-8')
        pass_db = self.password_hash.encode('utf-8')
        return bcrypt.checkpw(pass_input, pass_db)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-S3:{0}?secret={1}&issuer=2FA-S3' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        # test token
        # my_secret = 'XUXC7WSXV3WIHEJK'  # secret check
        # my_token = onetimepass.get_totp(my_secret)
        # print(my_token)
        # print(token)
        # logger.info("token : %s", token)
        # logger.info("otp_secret : %s", self.otp_secret)
        return onetimepass.valid_totp(token, self.otp_secret)

    @classmethod
    def verify_token(cls, token):
        # user_id = jwt_decode_token(token, algorithms=['HS256'])['user_id']
        data = jwt_decode_token(token, algorithms=['HS256'])
        # uid, key, role
        # return Users.query.filter_by(username=user_id).first()
        return data


class ActionLogs(db.Model):
    __tablename__ = 'action_logs'
    # __tablename__ = 'system_logs'
    id = db.Column('id', db.Integer, primary_key=True)
    fnc_id = db.Column(db.String(200))
    fnc_name = db.Column(db.String(200))
    fnc_url = db.Column(db.String(200))
    action = db.Column(db.String(200))
    # user_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String(200))
    src = db.Column(db.String(200))
    ip = db.Column(db.String(200))
    msg_status = db.Column(db.String(200))
    msg_action = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow())

    def __init__(self, **kwargs):
        super(ActionLogs, self).__init__(**kwargs)

        result = dict()
        for key in kwargs:
            val = getattr(self, key, None)
            if isinstance(val, ActionLogs):
                result[key] = val.to_dict(None)
            elif isinstance(val, datetime):
                result[key] = val.strftime('%Y-%m-%d %H:%M')
            else:
                result[key] = val
        self.result = result
