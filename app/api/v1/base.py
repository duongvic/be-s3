from webargs import fields, validate
from flask_httpauth import HTTPTokenAuth


LIST_ITEMS_PER_PAGE = 10
LIST_MAX_ITEMS_PER_PAGE = 1000

auth = HTTPTokenAuth(scheme='Bearer')


@auth.verify_token
def verify_request_token(token):
    if not token:
        return None
    from app.api.models import Users
    return Users.verify_token(token)

PAGING_ARGS = {
    'page': fields.Int(required=False, missing=0),
    'page_size': fields.Int(
        required=False,
        missing=LIST_ITEMS_PER_PAGE,
        validate=[validate.Range(min=1, max=LIST_MAX_ITEMS_PER_PAGE)]),
    'sort_by': fields.List(fields.Str(), required=False),  # form: col1,col2__desc,col3__asc default asc
}

KEY_BUCKET_ARGS = {
    'access_key': fields.Str(required=True),
    'secret_key': fields.Str(required=True),
    'uid': fields.Str(required=True)
}
