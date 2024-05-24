from flask import Flask, make_response
from flask_restful import Api, Resource, reqparse, abort
from flask import jsonify
from auth import auth, add_auth, remove_auth, verify_password
from pwdmanager import get_password, add_db_entry, del_db_entry, add_db_user, del_db_user

from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "terhuefbz"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)

def login(username, password):
    if(verify_password(username, password)):
        access_token = create_access_token(identity=username)
        res = make_response(jsonify({"msg":"Login successful"}), 200)
        res.set_cookie('access_token_cookie', access_token)
        return res
    else:
        return jsonify({"msg":"Invalid username or password"}), 401


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
    app.run(debug=True)