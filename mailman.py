from flask_mail import Mail, Message
from flask import render_template
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer('secretkey') # TODO: Change this to a random string
salt = 'superalt' # TODO: Change this to a random string

root = 'http://127.0.0.1:5000'

mail = Mail()

def generate_token(email):
    return serializer.dumps(email, salt=salt)

def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt=salt,
            max_age=expiration
        )
    except:
        return False
    return email

def send_account_verification_email(username, email):
    token = generate_token(email)
    link = f'{root}/verifyAccount?token={token}'
    html = render_template('mail.html', username=username, link=link)
    msg = Message('Account Verification', recipients=[email], html=html)
    mail.send(msg)


