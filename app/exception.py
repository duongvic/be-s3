#!/usr/bin/env python
# -*- encoding: utf-8 -*-


class S3Exception(Exception):
    pass


class InputDataError(S3Exception, RuntimeError):
    pass