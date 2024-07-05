from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String
from dataclasses import dataclass

db = SQLAlchemy()

@dataclass
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username:str = db.Column(String(80), unique=True, nullable=False)
    email:str = db.Column(String(120), unique=True, nullable=False)
    verified:bool = db.Column(db.Boolean, default=False, nullable=False)
    tfa_enabled:bool = db.Column(db.Boolean, default=False, nullable=False)
    created:str = db.Column(db.DateTime, server_default=db.func.now())

    passwords = db.relationship('Vault', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    ipaddresses = db.relationship('IpAddress', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    login = db.relationship('Login', backref='user', lazy=True, cascade='all, delete-orphan', uselist=False)
    twofa = db.relationship('TwoFa', backref='user', lazy=True, cascade='all, delete-orphan', uselist=False)

    def __repr__(self):
        return f'User: {self.username}, email: {self.email}'
    
    def check_ipaddress(self, ipaddress):
        return ipaddress in [ip.ipaddress for ip in self.ipaddresses]
    
    def get_website_password(self, website):
        return self.passwords.filter_by(website=website).first()
    
@dataclass
class Login(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True)
    hashpwd:str = db.Column(db.String(80), nullable=False)
    salt:str = db.Column(db.String(80), nullable=False)
    
@dataclass
class Vault(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True)
    website:str = db.Column(db.String(80), nullable=False, primary_key=True)
    password:str = db.Column(db.String(80), nullable=False)

@dataclass
class IpAddress(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True)
    ipaddress:str = db.Column(db.String(80), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'ipaddress', name='uix_1'),)

@dataclass
class TwoFa(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True)
    secret:str = db.Column(db.String(80), nullable=False)