import bcrypt

class Authenticator:
    def __init__(self, db):
        self.db = db

    def check_auth(password, hashpwd, salt):
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
        return hashed == hashpwd

    def create_auth(password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return (hashed.decode('utf-8'), salt.decode('utf-8'))
    
    def register(self, username, email, password):
        hashpwd, salt = Authenticator.create_auth(password)
        return self.db.register(username, email, hashpwd, salt)
    
    def unregister(self, username):
        return self.db.unregister(username)
    
    def authenticate(self, username, password):
        user = self.db.get_login(username)
        if not user:
            return False
        return Authenticator.check_auth(password, user[0], user[1])