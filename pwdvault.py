from datetime import datetime
from datetime import timedelta
from datetime import timezone

from functools import wraps

from authentication.authenticate import Authenticator
from database.dbmanager import DbManager

from flask import Flask, make_response
from flask_restful import Api, Resource, reqparse
from flask import jsonify, request

from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import jwt_required
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

jwt = JWTManager(app)

def login(username, password):
    if auth.authenticate(username, password):
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)

        user = db.get_user_detail(username)

        res = make_response(jsonify({"msg":"Login successful", "username":user[0], "email": user[1]}), 200)
        set_access_cookies(res, access_token)
        set_refresh_cookies(res, refresh_token)
        return res, 200
    else:
        return jsonify({"msg":"Invalid username or password"}), 401
    
def get_ipaddr():
    ipaddr = request.access_route[-1]
    return ipaddr

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

@app.route('/ips', methods=['GET'], endpoint='get_ipaddresses')
@token_ip_required()
def get_ipaddresses():
    username = get_jwt_identity()
    ipaddresses = db.get_ipaddresses(username)
    return jsonify({"ipaddresses":ipaddresses}), 200

@app.route('/checkAuth', methods=['GET'], endpoint='check_if_authed')
@token_ip_required()
def check_if_auth():
    user = db.get_user_detail(get_jwt_identity())
    if user:
        return jsonify({"msg":"You are authenticated", "username":user[0], "email": user[1]}), 200

@app.after_request
def refresh(res):
    try:
        # Refresh the access token if it is about to expire (< 5 minutes left)
        exp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target = datetime.timestamp(now + timedelta(minutes=5))
        if target > exp:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            set_access_cookies(res, access_token)
        return res
    except (RuntimeError, KeyError):
        return res

@app.route('/logout', methods=['POST'], endpoint='logout_user')
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
    def get(website):
        username = get_jwt_identity()
        pwd = db.get_password(username, website)
        if pwd:
            return jsonify({"accepted": True, "password":pwd}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200
    
    @app.route('/setPassword', methods=['POST'], endpoint='add_password')
    @token_ip_required()
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
    def delete():
        username = get_jwt_identity()
        args = Passwords.website_parser.parse_args()

        if db.delete_password(username, args['website']):
            return jsonify({"msg":"Password deleted"}), 200
        else:
            return jsonify({"msg":db.message}), 404
        
    @app.route('/updatePassword', methods=['PUT'], endpoint='update_password')
    @token_ip_required()
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

    # Create a new user
    @app.route('/createUser', methods=['PUT'], endpoint='register_user')
    def put():
        # Parse the password from the request
        args = User.full_Parser.parse_args()

        # Try to add the user to the auth database
        if auth.register(args['username'], args['email'], args['password']):
            db.register_ipaddress(args['username'], get_ipaddr())
            return login(args['username'], args['password'])
        else:   
            return jsonify({"msg":db.message}), 200
        
    # Login a user
    @app.route('/login', methods=['POST'], endpoint='login_user')
    def get():
        # Parse the password from the request
        args = User.name_pwd_parser.parse_args()

        res = login(args['username'], args['password'])

        if res[1] == 200:
            db.register_ipaddress(args['username'], get_ipaddr())

        return res

        
    # Delete a user
    @app.route('/deleteUser', methods=['DELETE'], endpoint='delete_user')
    @token_ip_required()
    def delete():
        username = get_jwt_identity()        
        if auth.unregister(username):
            return jsonify({"msg":"User removed"}), 200
        else:
            return jsonify({"msg":"User not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
