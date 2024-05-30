import sqlite3
import bcrypt
from database.scripts import *
from database.dbconfig import *

class DbManager:

    message = ""

    def __init__(self):
        self.con = self.connect()
        self.cursor = self.con.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.executescript(create_table_script)

    def connect(self):
        con = sqlite3.connect(db_file_loc)
        # Activate foreign keys
        con.execute('PRAGMA foreign_keys = ON;')
        return con
    
    # --- USER MANAGEMENT ---

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
            self.cursor.execute(
                delete_website_password_script.format(username, website))
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