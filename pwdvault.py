from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask_jwt_extended import create_refresh_token

from functools import wraps

from helpers import *

from io import BytesIO

from authentication.authenticate import Authenticator
from database.dbmanager import DbManager
from twofa import TwoFAManager

from flask import Flask, make_response
from flask_restful import Resource, reqparse
from flask import jsonify, request
from flask import send_file

from flask_jwt_extended import JWTManager

from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from flask_jwt_extended import set_refresh_cookies, unset_jwt_cookies

app = Flask(__name__)

with open('authpwd.txt', 'r') as f:
    app.config["JWT_SECRET_KEY"] = f.read().strip()

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "None"

db = DbManager()
auth = Authenticator(db)
twofa = TwoFAManager("pwdvaultapp")

jwt = JWTManager(app)

def check_ipaddr(ipaddr, username):
    ipaddresses = db.get_ipaddresses(username)
    for ip in ipaddresses:
        if ipaddr == ip[0]:
            return True
    return False

def token_ip_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            ipaddr = get_ipaddr()
            username = get_jwt_identity()
            if check_ipaddr(ipaddr, username):
                return fn(*args, **kwargs)
            else:
                return jsonify({"msg":"Unknown IP address"}), 401

        return decorator

    return wrapper

@app.route('/checkAuth', methods=['GET'], endpoint='check_if_authed')
@token_ip_required() # Only need to have any valid token
def check_if_auth():
    user = db.get_user_detail(get_jwt_identity())
    if user:
        claims = get_jwt()
        tfa_enabled = claims["tfa_enabled"]
        return make_identity_response("You are authenticated", user[0], user[1], tfa_enabled), 200

@app.after_request
def refresh(res):
    try:
        # Refresh the access token if it is about to expire (< 5 minutes left)
        exp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target = datetime.timestamp(now + timedelta(minutes=5))
        if target > exp:
            current_user = get_jwt_identity()
            access_token = refresh_access_token(current_user, get_jwt())
            set_access_cookies(res, access_token)
        return res
    except (RuntimeError, KeyError):
        return res

@app.route('/logout', methods=['POST'], endpoint='logout_user')
@token_ip_required() # Only need to have any valid token
def logout():
    res = make_response(jsonify({"msg":"Logout successful"}), 200)
    unset_jwt_cookies(res)
    return res

# Endpoints for password management
class Passwords(Resource):

    website_parser = reqparse.RequestParser()
    website_parser.add_argument('website', required=True, help="Website cannot be blank")

    website_password_parser = website_parser.copy()
    website_password_parser.add_argument('password', required=True, help="Password cannot be blank")

    @app.route('/getPassword/<string:website>', methods=['GET'], endpoint='get_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def get(website):
        username = get_jwt_identity()
        pwd = db.get_password(username, website)
        if pwd:
            return jsonify({"accepted": True, "password":pwd}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200
    
    @app.route('/setPassword', methods=['POST'], endpoint='add_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def post():
        username = get_jwt_identity()
        args = Passwords.website_password_parser.parse_args()

        if db.add_password(username, args['website'], args['password']):
            return jsonify({"accepted": True, "msg":"Password added"}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200
        

        return db.add_password(username, args['website'], args['password'])
    
    @app.route('/deletePassword', methods=['DELETE'], endpoint='delete_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def delete():
        username = get_jwt_identity()
        args = Passwords.website_parser.parse_args()

        if db.delete_password(username, args['website']):
            return jsonify({"msg":"Password deleted"}), 200
        else:
            return jsonify({"msg":db.message}), 404
        
    @app.route('/updatePassword', methods=['PUT'], endpoint='update_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def put():
        username = get_jwt_identity()
        args = Passwords.website_password_parser.parse_args()

        if db.update_password(username, args['website'], args['password']):
            return jsonify({"accepted": True, "msg":"Password updated"}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200

# Endpoints for user management
class User(Resource):

    name_pwd_parser = reqparse.RequestParser()
    name_pwd_parser.add_argument('username', required=True, help="Username cannot be blank")
    name_pwd_parser.add_argument('password', required=True, help="Password cannot be blank")

    full_Parser = name_pwd_parser.copy()
    full_Parser.add_argument('email', required=True, help="Email cannot be blank")

    def login(username, password):
        if not auth.authenticate(username, password):
            return jsonify({"msg":"Invalid username or password"}), 401
        
        if not db.get_2fa_secret(username):
            tfa_enabled=False
            tfa_verified=False
        # Check if the user has logged in from this IP address before
        elif not check_ipaddr(get_ipaddr(), username):
            # If not require 2fa verification
            tfa_enabled=True
            tfa_verified=False
        else:
            # Else generate an access token and refresh token with 2fa set to True
            tfa_enabled=True
            tfa_verified=True

        refresh_token = create_refresh_token(identity=username)
        access_token = generate_access_token(username, tfa_enabled=tfa_enabled, tfa_verified=tfa_verified)
        # Generate the response using the user's details
        user = db.get_user_detail(username)
        res = make_response(make_identity_response("Login Sucessfull", user[0], user[1], tfa_enabled), 200)
        set_access_cookies(res, access_token)
        set_refresh_cookies(res, refresh_token)
        return res, 200

    # Create a new user
    @app.route('/createUser', methods=['PUT'], endpoint='register_user')
    def put():
        # Parse the password from the request
        args = User.full_Parser.parse_args()

        # Try to add the user to the auth database
        if auth.register(args['username'], args['email'], args['password']):
            db.register_ipaddress(args['username'], get_ipaddr())
            return User.login(args['username'], args['password'])
        else:   
            return jsonify({"msg":db.message}), 200
        
    # Login a user
    @app.route('/login', methods=['POST'], endpoint='login_user')
    def get():
        # Parse the password from the request
        args = User.name_pwd_parser.parse_args()

        return User.login(args['username'], args['password'])

        
    # Delete a user
    @app.route('/deleteUser', methods=['DELETE'], endpoint='delete_user')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def delete():
        username = get_jwt_identity()        
        if auth.unregister(username):
            return jsonify({"msg":"User removed"}), 200
        else:
            return jsonify({"msg":"User not found"}), 404
        
    @app.route('/2faActivate', methods=['GET'], endpoint='activate_2fa')
    # No need to check the IP address 
    @two_fa_not_setup # Only allow access if 2fa is not enabled
    def tfa_setup():
        username = get_jwt_identity()
        secret = twofa.generate_secret()
        db.register_2fa(username, secret)
        qr_img =  twofa.get_qr(username, secret)
        buffer = BytesIO()
        qr_img.save(buffer)
        buffer.seek(0)

        db.register_ipaddress(username, get_ipaddr())

        # Generate a new access token with 2fa enabled
        res = send_file(buffer, mimetype='image/png')
        access_token = generate_access_token(username, tfa_enabled=True, tfa_verified=False)
        set_access_cookies(res, access_token)
        return res
    
    @app.route('/2faVerify', methods=['POST'], endpoint='verify_2fa')
    @token_ip_required()
    @two_fa_required # Only allow access if 2fa is enabled
    def tfa_verify():
        username = get_jwt_identity()
        secret = db.get_2fa_secret(username) # TODO implement this
        token = request.json['token']
        if twofa.verify(secret, token):
            access_token = generate_access_token(username, tfa_enabled=True, tfa_verified=True)
            res = make_response(jsonify({"msg":"2FA verified"}), 200)
            set_access_cookies(res, access_token)
            return res
        else:
            return jsonify({"msg":"2FA failed"}), 401

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
