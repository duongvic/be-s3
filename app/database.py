#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
# from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
import sqlalchemy
import datetime
import enum
import yaml
import os
from pathlib import Path
from app.exception import InputDataError
import urllib.parse

# connection database
# ROOT_DIR = Path(__file__).parent.parent
# fileName = 's3-config.yaml'
# DB_PATH = os.path.join(ROOT_DIR, fileName)
# with open(DB_PATH, 'r') as f:
#     db_config = yaml.safe_load(f)
# DATABASE_URL = db_config['uri']
# db_engine = create_engine(DATABASE_URL, convert_unicode=True, echo=False)

password = urllib.parse.quote_plus('CAS@2020&')
db_engine = create_engine('postgresql://miqportal:' + password + '@58.186.85.19/cas_s3', echo=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
session = SessionLocal()
Base = declarative_base()

# Base.metadata.create_all(bind=db_engine)
# Base.metadata.reflect(db_engine, reflect=True)


# init database
def get_db():
    try:
        return session
    finally:
        session.close()


def save(model):
    try:
        model = session.merge(model)
        session.commit()
        session.flush()
        return model, None
    except BaseException as e:
        session.rollback()
        return None, InputDataError(e)


class ModelBase(object):
    def _validate(self, errors):
        """Subclasses override this to offer additional validation.

        For each validation error a key with the field name and an error
        message is added to the dict.

        """
        pass

    def is_valid(self):
        """Called when persisting data to ensure the format is correct."""
        self.errors = {}
        self._validate(self.errors)
        #        self._validate_columns_type()
        #        self._before_validate()
        #        self._validate()
        return self.errors == {}

    def __init__(self, **kwargs):

        self.merge_attributes(kwargs)
        if not self.is_valid():
            raise

    def merge_attributes(self, values):
        """dict.update() behaviour."""
        for k, v in values.items():
            self[k] = v

    def __setitem__(self, key, value):
        """Overloaded to cause this object to look like a data entity."""
        setattr(self, key, value)

    def __getitem__(self, key):
        """Overloaded to cause this object to look like a data entity."""
        return getattr(self, key)

    def __eq__(self, other):
        """Overloaded to cause this object to look like a data entity."""
        if not hasattr(other, 'id'):
            return False
        return type(other) == type(self) and other.id == self.id

    def __ne__(self, other):
        """Overloaded to cause this object to look like a data entity."""
        return not self == other

    def __hash__(self):
        """Overloaded to cause this object to look like a data entity."""
        return self.id.__hash__()


class DatabaseModel(ModelBase):
    __user__fields__ = []

    @classmethod
    def get_model_attr(cls, attr):
        return attr in cls.__table__.columns.keys()

    @property
    def admin_fields(self):
        return self.__table__.columns.keys()

    @property
    def user_fields(self):
        return self.__user__fields__ if not self.__user__fields__ else self.admin_fields

    def to_user_dict(self):
        result = dict()
        for key in self.__user__fields__:
            val = getattr(self, key, None)
            if isinstance(val, DatabaseModel):
                result[key] = val.to_dict(None)
            elif isinstance(val, enum.Enum):
                result[key] = val.value
            elif isinstance(val, datetime.datetime):
                result[key] = val.strftime('%Y-%m-%d %H:%M')
            else:
                result[key] = val
        return result

    def to_dict(self, ignore_fields=None):
        result = dict()
        ignore_fields = ignore_fields or []

        for key in self.__table__.columns.keys():
            if key in ignore_fields:
                continue
            val = getattr(self, key, None)
            if val is not None:
                if isinstance(val, DatabaseModel):
                    result[key] = val.to_dict(None)
                elif isinstance(val, enum.Enum):
                    result[key] = val.value
                elif isinstance(val, datetime.datetime):
                    result[key] = val.strftime('%Y-%m-%d %H:%M')
                else:
                    result[key] = val
        return result

    @classmethod
    def raw_query(cls):
        return SessionLocal.query(cls)

    @classmethod
    def find_by_id(cls, id):
        obj = SessionLocal.query(cls).filter(cls.id == id).one_or_none()
        return obj

    def create(self):
        return save(self)


class User(Base, DatabaseModel):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    fullname = sqlalchemy.Column(sqlalchemy.String(255), nullable=False)
    email = sqlalchemy.Column(sqlalchemy.String(255), nullable=False)
    user_name = sqlalchemy.Column(sqlalchemy.String(255), nullable=False, unique=True)
    status = sqlalchemy.Column(sqlalchemy.Boolean)
    password = sqlalchemy.Column(sqlalchemy.String(255), nullable=False)
    enable_two_factors = sqlalchemy.Column(sqlalchemy.Boolean)
