from os import environ
from dotenv import load_dotenv

def set_flask(app):
    load_dotenv()

    # App config
    app.config['FLASK_APP'] = 'PwdVault App'
    app.config['FLASK_ENV'] = environ.get('FLASK_ENV')

    # JWT config
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False
    app.config["JWT_COOKIE_SECURE"] = True
    app.config["JWT_COOKIE_SAMESITE"] = "None"
    app.config["JWT_SECRET_KEY"] = environ.get('JWT_SECRET_KEY')

    # SQLAlchemy config
    app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///pwdvault.db'

    # Mail config
    app.config["MAIL_SERVER"] = 'smtp.gmail.com'
    app.config["MAIL_PORT"] = '587'
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = environ.get('MAIL_USERNAME')
    app.config["MAIL_PASSWORD"] = environ.get('MAIL_PASSWORD')
    app.config["MAIL_DEFAULT_SENDER"] = (app.config['FLASK_APP'], environ.get('MAIL_USERNAME'))
    app.config["MAIL_SECRET_KEY"] = environ.get('MAIL_SECRET_KEY')
    app.config["MAIL_SALT"] = environ.get('MAIL_SALT')

    # Root URL
    app.config['ROOT_URL'] = 'http://127.0.0.1:5000'
    #app.config['ROOT_URL'] = 'https://pi.thehoul.ch'

