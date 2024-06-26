import sqlite3
from database.scripts import *
from database.dbconfig import *

class DbManager:

    message = ""

    def __init__(self, db_file_loc=db_file_loc):
        self.con = self.connect(db_file_loc)
        self.cursor = self.con.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.executescript(create_table_script)

    def connect(self, db_file_loc):
        con = sqlite3.connect(db_file_loc, check_same_thread=False)
        # Activate foreign keys
        con.execute('PRAGMA foreign_keys = ON;')
        return con
    
    # --- USER MANAGEMENT ---

    # Get the details of a user
    def get_user(self, username):
        userid = self.getUserID(username)
        if not userid:
            return None
        res = self.cursor.execute(get_user.format(userid))
        return res.fetchone()

    # Returns the hash of the password and the salt -> (hash, salt)
    def get_login(self, username):
        userid = self.getUserID(username)
        if not userid:
            self.message = 'User not found'
            return False
        res = self.cursor.execute(get_pwdsalt_script.format(userid))
        return res.fetchone()

    # Register a user. Returns True if the user was added, False if the user already exists
    def register(self, username, email, hashpwd, salt):
        # Add the user to the database
        try:
            self.cursor.execute(
                insert_person_script.format(username, email))
            self.cursor.execute(
                insert_login_script.format(self.cursor.lastrowid, hashpwd, salt))
            self.message = 'User added'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User already exists'
            return False

    # Unregister a user. Returns True if the user was removed, False if the user was not found
    def unregister(self, username):
        # Remove the user from the database
        try:
            userid = self.getUserID(username)
            if not userid:
                return False
            self.cursor.execute(delete_person_script.format(userid))
            self.message = 'User removed'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return False

    # --- USER STATUS MANAGEMENT ---    
    
    # Set the user account as verified
    def set_user_acc_verified(self, username):
        userid = self.getUserID(username)
        if not userid:
            return False
        self.cursor.execute(
            update_user_acc_verified_script.format(userid))
        self.commit()
        return True
    
    # Set the user 2fa has enabled
    def set_user_tfa_enable(self, username):
        userid = self.getUserID(username)
        if not userid:
            return False
        self.cursor.execute(
            update_user_tfa_enabled_script.format(userid))
        self.commit()
        return True
    
    # --- PASSWORD MANAGEMENT ---

    # Add a password to the vault. Returns True if the password was added, False if the user was not found
    def add_password(self, username, website, hashpwd):
        if self.get_password(username, website):
            self.message = 'Password already exists, try updating it instead'
            return False
        try:
            userid = self.getUserID(username)
            if not userid:
                return False
            self.cursor.execute(
                insert_website_password_script.format(userid, website, hashpwd))
            self.message = 'Password added'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return False

    # Get a password from the vault. Returns the password if it was found, False if the user was not found
    def get_password(self, username, website):
        try:
            res = self.cursor.execute(get_website_password_script.format(username, website)).fetchone()
            if not res:
                self.message = 'No password for {}'.format(website)
                return None
            return res[0]
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return None
        
    def get_tfa(self, username):
        userid = self.getUserID(username)
        if not userid:
            return False
        res = self.cursor.execute(get_2fa_bit.format(userid))
        return res.fetchone()
        
    def register_2fa(self, username, secret):
        try:
            userid = self.getUserID(username)
            if not userid:
                return False
            if self.get_2fa_secret(username):
                self.message = '2FA already activated'
                return True
            self.cursor.execute(
                insert_2fa_script.format(userid, secret))
            self.message = '2FA activated'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return False

    def get_2fa_secret(self, username):
        try:
            userid = self.getUserID(username)
            if not userid:
                return False
            res = self.cursor.execute(get_2fa_secret_script.format(userid)).fetchone()
            if not res:
                self.message = '2FA not activated'
                return None
            return res[0]
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return None

    # Register an IP address for the given user. Returns True if the IP address was added or alread existed, False if the user was not found
    def register_ipaddress(self, username, ipaddress):
        try:
            userid = self.getUserID(username)
            if not userid:
                return False

            ipaddresses = self.get_ipaddresses(username)
            if ipaddress in ipaddresses:
                self.message = 'IP address already exists'
                return True

            self.cursor.execute(
                insert_ipaddress_script.format(userid, ipaddress))
            self.message = 'IP address added'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return False
        
    # Get all IP addresses for the given user. Returns a list of IP addresses if the user was found, None if the user was not found
    def get_ipaddresses(self, username):
        userid = self.getUserID(username)
        if not userid:
            return None
        res = self.cursor.execute(get_ipaddress_script.format(userid))
        return res.fetchall()

    # Update a password in the vault. Returns True if the password was updated, False if the user was not found
    def update_password(self, username, website, hashpwd):
        try:
            userid = self.getUserID(username)
            if not userid:
                self.message = 'User not found'
                return False
            self.cursor.execute(
                update_website_password_script.format(hashpwd, userid, website))
            self.message = 'Password updated'
            self.commit()
            return True
        except sqlite3.IntegrityError as e: 
            self.message = 'User not found'
            return False

    # Delete a password from the vault. Returns True if the password was deleted, False if the user was not found
    def delete_password(self, username, website):
        if not self.get_password(username, website):
            # message is set in get_password
            return False
        try:
            userid = self.getUserID(username)
            if not userid:
                return False
            self.cursor.execute(
                delete_website_password_script.format(userid, website))
            self.message = 'Password deleted'
            self.commit()
            return True
        except sqlite3.IntegrityError:
            self.message = 'User not found'
            return False

    # --- HELPERs ---

    def getUserID(self, username):
        res = self.cursor.execute(get_userid_script.format(username))
        userid = res.fetchone()
        if not userid:
            self.message = 'User not found'
            return None
        return userid[0]
        
    def commit(self):
        self.con.commit()

    # Close the connection
    def close(self):
        self.con.commit()
        self.con.close()   