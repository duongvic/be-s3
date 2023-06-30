#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import logging
from datetime import datetime
from config import CONF

use_log_file = CONF.config['use_log_file']
logger = logging.getLogger(__name__)

# log file by date
# filename = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ".log"
filename = '/var/log/s3-be-api/' + datetime.now().strftime("%Y-%m-%d") + "_cas_s3_be.log"
file_logger = logging.FileHandler(filename)

# NEW_FORMAT = '[%(asctime)s] - [%(levelname)s] - %(message)s'
NEW_FORMAT = '[%(levelname)s]-%(asctime)s-[%(filename)s-%(funcName)s()-%(lineno)d]: %(message)s'
date_fmt = '%Y-%m-%d %H:%M:%S'
file_logger_format = logging.Formatter(NEW_FORMAT, datefmt=date_fmt)

file_logger.setFormatter(file_logger_format)
logger.addHandler(file_logger)
logger.setLevel(logging.DEBUG)

# disabled == 0
if use_log_file == 0:
    logger.disabled = True

# test logging
# logger.debug('I used .debug!')
# logger.info('I used .info!')
# logger.warning('I used .warn!')
# logger.error('I used .error!')
