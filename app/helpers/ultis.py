# -*- coding: utf-8 -*-
# encoding=utf8
import string
import random
import jwt
from config import CONF
import math

LETTERS = string.ascii_letters
obj = CONF.config['s3_api']


def gen_key(size=10, chars=LETTERS + string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# print(gen_key(size=40))

def jwt_decode_token(token, algorithms=('HS256',)):
    """
    Decode token and return the encoded data.
    :param token:
    :param key: secret key
    :param algorithms: algorithms
    :return:
    """

    my_secret_jwt = obj.get('my_secret_jwt')
    algorithms = ['HS256', ]
    try:
        return jwt.decode(token, key=my_secret_jwt, algorithms=algorithms)
    except Exception as err:
        # print(err)
        return err


def check_disk_space(used, total):
    try:
        percent = (float(used) / total) * 100
    except ZeroDivisionError:
        percent = 0
    # return round(percent, 1)
    disk_space = round(percent, 1)
    # msg = ''
    if disk_space < 80:
        msg = 'AVAILABLE'
    else:
        msg = 'WARNING'
    # print(msg)
    return msg


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])
