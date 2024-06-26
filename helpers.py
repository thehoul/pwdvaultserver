from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask import request, jsonify
from functools import wraps

def generate_access_token(username, acc_verified=False, tfa_enabled=False, tfa_verified=False):
    access_token = create_access_token(identity=username, 
        additional_claims={
            "acc_verified": acc_verified,
            "tfa_enabled": tfa_enabled,
            "tfa_verified": tfa_verified
        }
    )
    return access_token

def refresh_access_token(username, old_token):
    access_token = create_access_token(identity=username, 
        fresh=False,
        additional_claims={
            "tfa_enabled": old_token["tfa_enabled"],
            "tfa_verified": old_token["tfa_verified"]
        }
    )
    return access_token
    
def get_ipaddr():
    ipaddr = request.access_route[-1]
    return ipaddr

def make_identity_response(message, user):
    return jsonify({
        "msg":message,
        "username":user[1], 
        "email": user[2],
        "acc_verified": user[3],
        "tfa_enabled": user[4],
        "created_at": user[5]  
    })

# TODO add function to require account to be verified

# TODO add requirement for the account to be verified (i.e. tfa enabled implies account verified)
# Check that the user has enabled 2fa /!\ NOT THAT IT HAS BEEN VERIFIED
def two_fa_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if not claims.get("tfa_enabled"):
            return jsonify({'message': '2FA not enabled'}), 403
        return fn(*args, **kwargs)
    return wrapper

# Check that the user has enabled and verified 2fa
def two_fa_complete(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if not claims.get("tfa_verified"):
            return jsonify({'message': '2FA not verified'}), 403
        return fn(*args, **kwargs)
    return wrapper

def two_fa_not_setup(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get("tfa_enabled"):
            return jsonify({'message': '2FA already setup'}), 403
        return fn(*args, **kwargs)
    return wrapper