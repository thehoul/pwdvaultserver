from datetime import datetime
from datetime import timedelta
from datetime import timezone

from authentication.authenticate import Authenticator
from database.dbmanager import DbManager

from flask import Flask, make_response
from flask_restful import Api, Resource, reqparse
from flask import jsonify

from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import get_jwt
from flask_jwt_extended import set_refresh_cookies, unset_jwt_cookies


app = Flask(__name__)

with open('authpwd.txt', 'r') as f:
    app.config["JWT_SECRET_KEY"] = f.read().strip()

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "None"

db = DbManager()
authenticator = Authenticator(db)

jwt = JWTManager(app)

def login(username, password):
    if authenticator.authenticate(username, password):
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)

        res = make_response(jsonify({"msg":"Login successful"}), 200)
        set_access_cookies(res, access_token)
        set_refresh_cookies(res, refresh_token)
        return res, 200
    else:
        return jsonify({"msg":"Invalid username or password"}), 401

@app.route('/checkAuth', methods=['GET'], endpoint='check_if_authed')
@jwt_required()
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
    @jwt_required()
    def get(website):
        username = get_jwt_identity()
        pwd = db.get_password(username, website)
        if pwd:
            return jsonify({"accepted": True, "password":pwd}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200
    
    @app.route('/setPassword', methods=['POST'], endpoint='add_password')
    @jwt_required()
    def post():
        username = get_jwt_identity()
        args = Passwords.website_password_parser.parse_args()

        if db.add_password(username, args['website'], args['password']):
            return jsonify({"accepted": True, "msg":"Password added"}), 200
        else:
            return jsonify({"accepted": False, "msg":db.message}), 200
        

        return db.add_password(username, args['website'], args['password'])
    
    @app.route('/deletePassword', methods=['DELETE'], endpoint='delete_password')
    @jwt_required()
    def delete():
        username = get_jwt_identity()
        args = Passwords.website_parser.parse_args()

        if db.delete_password(username, args['website']):
            return jsonify({"msg":"Password deleted"}), 200
        else:
            return jsonify({"msg":db.message}), 404

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
        if authenticator.register(args['username'], args['email'], args['password']):
            return login(args['username'], args['password'])
        else:   
            return jsonify({"msg":db.message}), 200
        
    # Login a user
    @app.route('/login', methods=['POST'], endpoint='login_user')
    def get():
        # Parse the password from the request
        args = User.name_pwd_parser.parse_args()

        return login(args['username'], args['password'])
        
    # Delete a user
    @app.route('/deleteUser', methods=['DELETE'], endpoint='delete_user')
    @jwt_required()
    def delete():
        username = get_jwt_identity()        
        if authenticator.unregister(username):
            return jsonify({"msg":"User removed"}), 200
        else:
            return jsonify({"msg":"User not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
