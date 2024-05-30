import sqlite3
import bcrypt
from scripts import *
from dbconfig import *

class DbManager:

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
        res = self.cursor.execute(get_userid_script.format(username))
        userid = res.fetchone()
        if not userid:
            print('User not found')
            return False
        print(userid[0])
        res = self.cursor.execute(get_pwdsalt_script.format(userid[0]))
        return res.fetchone()

    # Register a user. Returns True if the user was added, False if the user already exists
    def register(self, username, email, hashpwd, salt):
        # Add the user to the database
        try:
            self.cursor.execute(
                insert_person_script.format(username, email))
            self.cursor.execute(
                insert_login_script.format(self.cursor.lastrowid, hashpwd, salt))
            print('User added')
            return True
        except sqlite3.IntegrityError:
            print('User already exists')
            return False

    # Unregister a user. Returns True if the user was removed, False if the user was not found
    def unregister(self, username):
        # Remove the user from the database
        try:
            self.cursor.execute(delete_person_script.format(username))
            print('User removed')
            return True
        except sqlite3.IntegrityError:
            print('User not found')
            return False
        
    # --- PASSWORD MANAGEMENT ---

    # Add a password to the vault. Returns True if the password was added, False if the user was not found
    def add_password(self, username, website, hashpwd):
        try:
            res = self.cursor.execute(get_userid_script.format(username))
            userid = res.fetchone()
            if not userid:
                print('User not found')
                return False
            self.cursor.execute(
                insert_website_password_script.format(userid[0], website, hashpwd))
            print('Password added')
            return True
        except sqlite3.IntegrityError:
            print('User not found')
            return False

    # Get a password from the vault. Returns the password if it was found, False if the user was not found
    def get_password(self, username, website):
        try:
            res = self.cursor.execute(get_website_password_script.format(username, website)).fetchone()
            if not res:
                print('Password not found')
                return False
            return res[0]
        except sqlite3.IntegrityError:
            print('User not found')
            return False

    def update_password(self, username, website, hashpwd):
        try:
            res = self.cursor.execute(get_userid_script.format(username))
            userid = res.fetchone()
            if not userid:
                print('User not found')
                return False
            self.cursor.execute(
                update_website_password_script.format(hashpwd, userid[0], website))
            print('Password updated')
            return True
        except sqlite3.IntegrityError:
            print('User not found')
            return False

    def delete_password(self, username, website):
        try:
            self.cursor.execute(
                delete_website_password_script.format(username, website))
            print('Password deleted')
            return True
        except sqlite3.IntegrityError:
            print('User not found')
            return False

    # --- HELPERS ---

    def getlogins(self):
        res = self.cursor.execute('''
            SELECT *
            FROM login;
        ''')
        return res.fetchall()
    
    def getusers(self):
        res = self.cursor.execute('''
            SELECT *
            FROM person;
        ''')
        return res.fetchall()

    def close(self):
        self.con.commit()
        self.con.close()
    
    