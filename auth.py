import bcrypt
from flask_httpauth import HTTPBasicAuth
from tinydb import TinyDB, Query

auth = HTTPBasicAuth()
authdb = TinyDB('./auth.json')

def find_user(username):
    User = Query()
    query = authdb.search(User.username == username)
    if not query:
        return None
    return query[0]

def verify_password(username, password):

    user = find_user(username)
    if not user:
        return False    
    
    # Retrieve the password salt from the database
    salt = user['salt']
    # Generate the hash of the password using the salt
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

    # Check if the hash is the same as the one in the database
    return hashed == user['passwordhash']

def remove_auth(username):
    user = find_user(username)
    if not user:
        return False

    authdb.remove(doc_ids=[user.doc_id])
    return True

def add_auth(username, password):

    user = find_user(username)
    if user:
        return False
    
    # Generate a salted hash of the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    print(type(username), type(salt.decode('utf-8')), type(hashed.decode('utf-8')))

    # Add the user to the database
    authdb.insert({
        'username': username,
        'passwordhash': hashed.decode('utf-8'),
        'salt': salt.decode('utf-8')
    })

    
    return True