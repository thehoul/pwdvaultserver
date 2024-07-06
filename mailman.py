from flask_mail import Mail, Message
from flask import render_template
from itsdangerous import URLSafeTimedSerializer, exc

mail = Mail()

class MailMan:

    def __init__(self, app):
        mail.init_app(app)
        self.salt = app.config['MAIL_SALT']
        self.serializer = URLSafeTimedSerializer(app.config['MAIL_SECRET_KEY'])
        self.root = app.config['ROOT_URL']

    def generate_token(self, email):
        return self.serializer.dumps(email, salt=self.salt)

    def confirm_token(self, token, expiration=3600):
        try:
            email = self.serializer.loads(
                token,
                salt=self.salt,
                max_age=expiration
            )
        except exc.SignatureExpired:
            return False
        except exc.BadSignature:
            return False
        return email

    def send_account_verification_email(self, username, email):
        token = self.generate_token(email)
        link = f'{self.root}/verifyAccount?token={token}'
        html = render_template('verify_account_mail.html', username=username, link=link)
        msg = Message('Account Verification', recipients=[email], html=html)
        mail.send(msg)

    def send_password_reset_email(self, email):
        token = self.generate_token(email)
        link = f'{self.root}/getResetPassword?token={token}'
        html = render_template('reset_pwd_mail.html', link=link)
        msg = Message('Password Reset', recipients=[email], html=html)
        mail.send(msg)


