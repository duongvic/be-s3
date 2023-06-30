from app.exception import InputDataError
from app.helpers.ultis import gen_key
import requests
import json
import jwt
from config import CONF
from app.logging_action import logger
from app.helpers.data_utils import dump_value
from app.mongodb import get_database_mongo
import datetime

use_log_pg = CONF.config['use_log_pg']
use_log_mg = CONF.config['use_log_mg']


class LogController:

    def log_user(self, uid):
        try:
            # uid = args['uid']
            logger.info("user log_user: %s", uid)
            msg_status = 200
            msg_action = ''

            from app.api.models import Users, ActionLogs, db
            # user = Users.query.filter_by(username=uid).first()
            # if user is not None and user.role == 'ADMIN':
            #     # role = admin show all
            #     # uid = args.get('uid', None)
            #     log = db.session.query(ActionLogs).all()
            # else:

            # show list log by uid == list logs pgsql
            # log = db.session.query(ActionLogs).filter(ActionLogs.user_name == uid).all()
            # results = [self.do_mapping_object(item) for item in log]

            # show list log by uid == list logs mg
            log = get_database_mongo().find({'user_name': uid})
            results = []
            for item in log:
                # This does not give a very readable output
                # print(item)
                obj = self.do_mapping_object_mg(item)
                results.append(obj)

            return {'code': 200, 'message': True, 'data': results, 'total': len(results)}
        except Exception as error:
            msg_action += str(error)
            msg_status = 500
            logger.error("user log_user: %s", error)
            raise error
        finally:
            # insert log mongodb
            if use_log_mg == 1:
                data = {
                    # "id": str(data['_id']),
                    "fnc_name": self.log_user.__name__,
                    "user_name": uid,
                    "msg_status": msg_status,
                    "msg_action": msg_action,
                    "created_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                }
                get_database_mongo().insert_one(data)

            # insert log pgsql
            if use_log_pg == 1:
                from app.api.models import ActionLogs, db
                al = ActionLogs(user_name=uid, fnc_name=self.log_user.__name__, msg_status=msg_status,
                                msg_action=msg_action)
                db.session.add(al)
                db.session.commit()
                db.session.close()

    def do_mapping_object(self, data):
        results = {
            "id": data.id,
            "fnc_name": data.fnc_name,
            "user_name": data.user_name,
            "msg_status": data.msg_status,
            "msg_action": data.msg_action,
            "created_at": data.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }
        return results

    # dict
    def do_mapping_object_mg(self, data):
        results = {
            "id": str(data['_id']),
            "fnc_name": data['fnc_name'],
            "user_name": data['user_name'],
            "msg_status": data['msg_status'],
            "msg_action": data['msg_action'],
            "created_at": data['created_at']
            # "created_at": data['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
        }
        return results
