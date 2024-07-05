from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask_jwt_extended import create_refresh_token

from functools import wraps

from helpers import *

from io import BytesIO

from authentication.authenticate import Authenticator
from twofa import TwoFAManager

from flask import Flask, make_response
from flask_restful import Resource, reqparse
from flask import jsonify, request
from flask import send_file
from sqlalchemy import exc

from flask_jwt_extended import JWTManager

from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import get_jwt
from flask_jwt_extended import set_refresh_cookies, unset_jwt_cookies
from config import set_flask

from mailman import MailMan
from models import db, User, Vault, Login, IpAddress, TwoFa

app = Flask(__name__)

set_flask(app)

db.init_app(app)
with app.app_context():
    db.create_all()

mailman = MailMan(app)
twofa = TwoFAManager("pwdvaultapp")

jwt = JWTManager(app)

@app.route('/checkAuth', methods=['GET'], endpoint='check_if_authed')
@token_ip_required() # Only need to have any valid token
def check_if_auth():
    user = get_user(get_jwt_identity())
    if user:
        return make_identity_response("You are authenticated", user), 200

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
        user = get_user(get_jwt_identity())
        pwd = user.get_website_password(website)
        if pwd:
            return jsonify({"accepted": True, "password":pwd.password}), 200
        else:
            return jsonify({"accepted": False, "msg":f"No password for {website}"}), 200
    
    @app.route('/setPassword', methods=['POST'], endpoint='add_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def post():
        user = get_user(get_jwt_identity())
        args = Passwords.website_password_parser.parse_args()

        entry = Vault(website=args['website'], password=args['password'])
        try:
            user.passwords.append(entry)
            db.session.commit()
            return jsonify({"accepted": True, "msg":"Password added"}), 200
        except Exception as e:
            return jsonify({"accepted": False, "msg":e}), 200
    
    @app.route('/deletePassword', methods=['DELETE'], endpoint='delete_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def delete():
        username = get_jwt_identity()
        args = Passwords.website_parser.parse_args()
        user = get_user(username)

        try:
            pwd = user.get_website_password(args['website'])
            db.session.delete(pwd)
            db.session.commit()
            return jsonify({"msg":"Password deleted"}), 200
        except Exception as e:
            return jsonify({"msg":e}), 404
        
    @app.route('/updatePassword', methods=['PUT'], endpoint='update_password')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def put():
        username = get_jwt_identity()
        args = Passwords.website_password_parser.parse_args()
        user = get_user(username)

        try:
            pwd = user.get_website_password(args['website'])
            pwd.password = args['password']
            db.session.commit()
            return jsonify({"msg":"Password updated"}), 200
        except Exception as e:
            return jsonify({"msg":e}), 404

# Endpoints for user management
class Users(Resource):

    name_pwd_parser = reqparse.RequestParser()
    name_pwd_parser.add_argument('username', required=True, help="Username cannot be blank")
    name_pwd_parser.add_argument('password', required=True, help="Password cannot be blank")

    full_Parser = name_pwd_parser.copy()
    full_Parser.add_argument('email', required=True, help="Email cannot be blank")

    def login(username, password):
        user = get_user(username)
        if not Authenticator.check_auth(password, user.login.hashpwd, user.login.salt):
            return jsonify({"msg":"Invalid username or password"}), 401
        
        user = get_user(username)
        acc_verified = user.verified
        tfa_enabled = user.tfa_enabled
        tfa_verified = False
        
        if(tfa_enabled):
            # Check if the user has logged in from this IP address before
            # If yes, then no need for 2fa
            tfa_verified = user.check_ipaddress(get_ipaddr())

        refresh_token = create_refresh_token(identity=username)
        access_token = generate_access_token(username, acc_verified=acc_verified,
                                tfa_enabled=tfa_enabled, tfa_verified=tfa_verified)
        
        # Generate the response using the user's details
        res = make_response(make_identity_response("Login Sucessfull", user), 200)
        set_access_cookies(res, access_token)
        set_refresh_cookies(res, refresh_token)
        return res, 200

    # Create a new user
    @app.route('/createUser', methods=['PUT'], endpoint='register_user')
    def put():
        # Parse the password from the request
        args = Users.full_Parser.parse_args()

        try:
            new_user  = User(username=args['username'], email=args['email'])
            (hashpwd, salt) = Authenticator.create_auth(args['password'])
            db.session.add(new_user)
            new_user.login = Login(hashpwd=hashpwd, salt=salt)
            new_user.ipaddresses.append(IpAddress(ipaddress=get_ipaddr()))
            db.session.commit()
            mailman.send_account_verification_email(new_user.username, new_user.email)
            return jsonify({"msg":"User created"}), 200
        except exc.IntegrityError as e:
            return jsonify({"msg":"User already exists"}), 200
        except Exception as e:
            return jsonify({"msg":repr(e)}), 404
        
    # Login a user
    @app.route('/login', methods=['POST'], endpoint='login_user')
    def get():
        # Parse the password from the request
        args = Users.name_pwd_parser.parse_args()
        return Users.login(args['username'], args['password'])
    
    # Verify a user's account
    @app.route('/verifyAccount', methods=['GET'], endpoint='verify_account')
    def verify():
        token = request.args.get('token')
        email = mailman.confirm_token(token)
        if not email:
            return jsonify({"msg":"Invalid or expired token"}), 401
        
        user = User.query.filter_by(email=email).first()
        user.verified = True
        db.session.commit()
        return jsonify({"msg":"Account verified"}), 200
    
    # Resend the verification email
    @app.route('/resendVerification', methods=['GET'], endpoint='resend_verification')
    @token_ip_required()
    def resend():
        user = get_user(get_jwt_identity())
        if not user:
            return jsonify({"msg":"User not found"}), 404
        if user.verified:
            return jsonify({"msg":"Account already verified"}), 200
        mailman.send_account_verification_email(user.username, user.email)
        return jsonify({"msg":"Verification email sent"}), 200

        
    # Delete a user
    @app.route('/deleteUser', methods=['DELETE'], endpoint='delete_user')
    @token_ip_required()
    @two_fa_complete # Only allow access if 2fa is enabled and verified
    def delete():
        username = get_jwt_identity()        
        user = get_user(username)
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"msg":"User deleted"}), 200
        except Exception as e:
            return jsonify({"msg":e}), 404
        
    @app.route('/2faActivate', methods=['GET'], endpoint='activate_2fa')
    # No need to check the IP address 
    @two_fa_not_setup # Only allow access if 2fa is not enabled
    @acc_verified_required() # Only allow access if the account is verified
    def tfa_setup():
        username = get_jwt_identity()
        user = get_user(username)

        # Create the QR code
        secret = twofa.generate_secret()
        qr_img =  twofa.get_qr(username, secret)
        buffer = BytesIO()
        qr_img.save(buffer)
        buffer.seek(0)

        user.tfa_enabled = True
        user.twofa = TwoFa(secret=secret)
        db.session.commit()

        # Generate a new access token with 2fa enabled
        res = send_file(buffer, mimetype='image/png')
        access_token = generate_access_token(username, tfa_enabled=True, tfa_verified=False)
        set_access_cookies(res, access_token)
        return res
    
    @app.route('/2faGet', methods=['GET'], endpoint='get_2fa')
    @two_fa_required # Only allow access if 2fa is enabled
    @acc_verified_required()
    def get_tfa():
        user = get_user(get_jwt_identity())
        qr_img = twofa.get_qr(user.username, user.twofa.secret)
        buffer = BytesIO()
        qr_img.save(buffer)
        buffer.seek(0)

        res = send_file(buffer, mimetype='image/png')
        return res
    
    @app.route('/2faVerify', methods=['POST'], endpoint='verify_2fa')
    @token_ip_required()
    @two_fa_required # Only allow access if 2fa is enabled
    def tfa_verify():
        user = get_user(get_jwt_identity())
        token = request.json['token']
        if twofa.verify(user.twofa.secret, token):
            user.ipaddresses.append(IpAddress(ipaddress=get_ipaddr()))
            access_token = generate_access_token(user.username, tfa_enabled=True, tfa_verified=True)
            res = make_response(jsonify({"msg":"2FA verified"}), 200)
            set_access_cookies(res, access_token)
            return res
        else:
            return jsonify({"msg":"2FA failed"}), 401

if __name__ == "__main__":
    app.run(debug=True)
