import bcrypt

class Authenticator:
    def check_auth(password, hashpwd, salt):
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
        return hashed == hashpwd

    def create_auth(password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return (hashed.decode('utf-8'), salt.decode('utf-8'))