from pwdvault import app

if __name__ == '__main__':
    app.run(ssl_context('cert.pem', 'key.pem'))
