from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask import request, jsonify
from functools import wraps
from models import User

def refresh_access_token(username):
    access_token = create_access_token(identity=username, fresh=False)
    return access_token
    
def get_ipaddr():
    ipaddr = request.access_route[-1]
    return ipaddr

def make_identity_response(message, user):
    return jsonify({
        "msg":message,
        "username":user.username, 
        "email": user.email,
        "acc_verified": user.verified,
        "tfa_enabled": user.tfa_enabled,
        "created_at": user.created  
    })

def two_fa_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user = get_user(get_jwt_identity())
        if not user.tfa_enabled:
            return jsonify({'message': '2FA not enabled'}), 403
        return fn(*args, **kwargs)
    return wrapper

def two_fa_not_setup(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user = get_user(get_jwt_identity())
        if user.tfa_enabled:
            return jsonify({'message': '2FA already setup'}), 403
        return fn(*args, **kwargs)
    return wrapper

def acc_verified_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            user = get_user(get_jwt_identity())
            if user.verified:
                return fn(*args, **kwargs)
            else:
                return jsonify({"msg":"Account not verified"}), 401
        return decorator
    return wrapper

def token_ip_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            ipaddr = get_ipaddr()
            user = get_user(get_jwt_identity())
            if user.check_ipaddress(ipaddr):
                return fn(*args, **kwargs)
            else:
                return jsonify({"msg":"Unknown IP address"}), 401
        return decorator
    return wrapper

def get_user(username):
    return User.query.filter_by(username=username).first()