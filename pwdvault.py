from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import Flask, make_response
from flask_restful import Api, Resource, reqparse, abort
from flask import jsonify
from auth import auth, add_auth, remove_auth, verify_password
from pwdmanager import get_password, add_db_entry, del_db_entry, add_db_user, del_db_user

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
app.config["JWT_COOKIE_SECURE"] = False # allow http

jwt = JWTManager(app)

def login(username, password):
    if(verify_password(username, password)):
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)

        res = make_response(jsonify({"msg":"Login successful"}), 200)
        set_access_cookies(res, access_token)
        set_refresh_cookies(res, refresh_token)
        return res, 200
    else:
        return jsonify({"msg":"Invalid username or password"}), 401

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
    @app.route('/passwords/<string:username>/<string:website>', methods=['GET'], endpoint='get_password')
    @jwt_required()
    def get(username, website):
        identity = get_jwt_identity()
        if identity != username:
            return jsonify({"msg":"You are not authorized to view this user's passwords"}), 403

        return get_password(username, website)
    
    @app.route('/passwords/<string:username>/<string:website>', methods=['POST'], endpoint='add_password')
    @jwt_required()
    def post(username, website):
        identity = get_jwt_identity()
        if identity != username:
            return jsonify({"msg":"You are not authorized to view this user's passwords"}), 403

        parser = reqparse.RequestParser()
        parser.add_argument('password', required=True, help="Password cannot be blank")
        args = parser.parse_args()

        return add_db_entry(username, website, args['password'])
    
    @app.route('/passwords/<string:username>/<string:website>', methods=['DELETE'], endpoint='delete_password')
    @jwt_required()
    def delete(username, website):
        identity = get_jwt_identity()
        if identity != username:
            return jsonify({"msg":"You are not authorized to view this user's passwords"}), 403

        parser = reqparse.RequestParser()
        parser.add_argument('password', required=True, help="Password cannot be blank")
        args = parser.parse_args()

        return del_db_entry(username, website, args['password'])

# Endpoints for user management
class User(Resource):
    # Create a new user
    @app.route('/user/<string:username>', methods=['POST'], endpoint='register_user')
    def post(username):
        # Parse the password from the request
        parser = reqparse.RequestParser()
        parser.add_argument('password', required=True, help="Password cannot be blank")
        args = parser.parse_args()

        # Try to add the user to the auth database
        if add_auth(username, args['password']):
            # Add the user to the data database
            add_db_user(username)
            # Create a JWT token and return it
            return login(username, args['password'])
        else:   
            return jsonify({"msg":"User already exists"}), 200
        
    @app.route('/user/<string:username>', methods=['GET'], endpoint='login_user')
    def get(username):
        # Parse the password from the request
        parser = reqparse.RequestParser()
        parser.add_argument('password', required=True, help="Password cannot be blank")
        args = parser.parse_args()

        return login(username, args['password'])
        
    # Delete a user
    @app.route('/user/<string:username>', methods=['DELETE'], endpoint='delete_user')
    @jwt_required()
    def delete(username):
        # Check if the user exists
        current_user = get_jwt_identity()
        if(current_user != username):
            return jsonify({"msg":"You are not authorized to delete this user"}), 403
        
        if not remove_auth(username):
            return jsonify({"msg":"User not found"}), 404
        
        return del_db_user(username)

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))