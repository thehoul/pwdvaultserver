import pyotp
import qrcode

class TwoFAManager:

    def __init__(self, issuer_name):
        self.issuer_name = issuer_name

    def get_qr(self, username, secret):
        totp_auth = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name=self.issuer_name)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_auth)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        return img
    
    def generate_secret(self):
        return pyotp.random_base32()
    
    def verify(self, secret, token):
        totp = pyotp.TOTP(secret)
        return totp.verify(token)