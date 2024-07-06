# Description

This is a server program using python Flask to create an API for a password vault. It uses cookies to keep alive connection. Account verification via mail is used and TFA is implemented using google authenticator. TwoFa is only used to verify new IP addresses, otherwise normal login is accetped.

# Endpoints

## Users management
- POST `/createUser`: create a new user using a username, mail address and password given in the JSON payload of the request. It returns a cookie to use for future communications. No two user with the same name or same mail address can exist.
- POST `/login>`: login to the user using the given username and the password given in the body as a json using the key `password`. This return a cookie to use for future communications
- GET `/verifyAccount?token=xxx`: Verify the account of the user by checking that the given token is valid. The token is sent to the mail address of the user. 
- GET `/resendVerification` : resend the verification mail to mail addres of the logged in user.
- GET `/sendResetPassword` : send to the current user a mail with a link to reset its password (master password)
- GET `/getResetPassword?token=xxx` : this is the link sent in the e-mail for resetting the password. It has a token that will be used to verify that the reset can be accepted. This endpoint returns an html page to reset the password.
- POST `/resetPassword?token=xxx` : this is the endpoint used in the reset password page returned in the endpoint above. It sends as a form the new password and the token is the same as the one sent by mail initially.
- GET `/2faActivate` : generate a secret key for the user's two-factor authentication and returns a QR code to scan. When this method is called, the user is considered to have enabled two-factor authentication.
- GET `/2faGet` : resend the QR code for TwoFa. This requires that the user has enabled it first by calling the above endpoint.
- POST `/2faVerify` : verify the TwoFa token given as json body using key `token`.
- DELETE `/deleteUser`: delete the user. This requires the cookie generated when logging in. This delete entirely the user, all saved passwords will be deleted.
- GET `/checkAuth` : Useful endpoint to test if the current cookies are still fresh. It will return user information (username, mail, created date, if the account is vefified and if 2fa is enabled).
- POST `/logout` : logout the user by remove the cookies.

## Passwords management

- GET `/passwords/<username>/<website>`: return the list of passwords used by the user identified by the given username for the given website. This requires the cookie generated when logging in.
- POST `passwords/<username>/<website>`: add to the given user and the given website an entry contaning the password given in the body using json and the key `password`. This requires the cookie generated when logging in.
- DELETE `passwords/<username>/<website>`: delete for the user in the given website the password entry matching the password given in the body using json and the key `password`. This requires the cookie generate in when logging in. 

# Development

see github