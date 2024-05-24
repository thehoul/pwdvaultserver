from tinydb import TinyDB, Query
from flask import jsonify

datadb = TinyDB('./data.json')

# Add a new password entry to the database for the given user and website
def add_db_entry(username, website, password):
    User = Query()
    # Find the user
    user = datadb.search(User.username == username)
    # Check if the user exists
    if not user:
        return jsonify({"msg":"User not found"}), 404

    # Check if this website already has an entry
    if website in user[0]['passwords']:
        # Check if the password already exists
        if(password in user[0]['passwords'][website]):
            return jsonify({"msg":"Password already exists for this website"}), 200
        # Add the password to the list
        user[0]['passwords'][website].append(password)
    else:
        # Create a new entry for the website
        user[0]['passwords'][website] = [password]
    
    datadb.update(user[0], User.username == username)
    return jsonify({"msg":"Password added successfully"}), 200

def del_db_entry(username, website, password):
    User = Query()
    # Find the user
    user = datadb.search(User.username == username)
    # Check if the user exists
    if not user:
        return jsonify({"msg":"User not found"}), 404
    
    # Check if the website has an entry
    if website not in user[0]['passwords']:
        return jsonify({"msg":"No entries for website"}), 404
    if(password not in user[0]['passwords'][website]):
        return jsonify({"msg":"Password not found"}), 404
    # Remove the password from the list
    user[0]['passwords'][website].remove(password)

    if(len(user[0]['passwords'][website]) == 0):
        # Remove the website entry if there are no more passwords
        del user[0]['passwords'][website]
        
    datadb.update(user[0], User.username == username)
    return jsonify({"msg":"Password deleted successfully"}), 200

# Add a new user to the database
def add_db_user(username):
    User = Query()
    # Check if the user already exists
    if datadb.search(User.username == username):
        # The user already exists so nothing happens
        return jsonify({"msg":"User already exists"}), 200
    
    # Create a new user
    datadb.insert({
        'username': username,
        'passwords': {}
        }
        )
    return jsonify({"msg":"User added successfully"}), 200

def del_db_user(username):
    User = Query()
    # Check if the user exists
    if not datadb.search(User.username == username):
        return jsonify({"msg":"User not found"}), 404
    
    # Remove the user
    datadb.remove(User.username == username)
    return jsonify({"msg":"User deleted successfully"}), 200

def get_password(username, website):
    User = Query()
    # Find the user
    user = datadb.search(User.username == username)
    # Check if the user exists
    if not user:
        return jsonify({"msg":"User not found"}), 404

    # Check if the website has an entry
    if website not in user[0]['passwords']:
        return jsonify({"msg":"No entries for website"}), 404

    return jsonify({"passwords":user[0]['passwords'][website]}), 200