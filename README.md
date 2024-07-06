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
- POST `/2faVerify` : verify the TwoFa token given as json body using key `token`. This essentially marks the sender Ip address as a valid IP address to use in the password method below.
- DELETE `/deleteUser`: delete the user. This requires the cookie generated when logging in. This delete entirely the user, all saved passwords will be deleted.
- GET `/checkAuth` : Useful endpoint to test if the current cookies are still fresh. It will return user information (username, mail, created date, if the account is vefified and if 2fa is enabled).
- POST `/logout` : logout the user by remove the cookies.

## Passwords management

- GET `/getPassword/<website>`: return the password registered for the current user for the given website. If a password exist, it is return in the JSON body and the `accepted` field is set to true. Otherwise the field is set to false and a `msg` is sent along.
- POST `passwords/setPassword`: add to the current given user for the website and the password given in the body using json and the keys `website` and `password`. This requires the used IP address to have been verified using 2fa.
- DELETE `passwords/deletePassword`: delete for the current user the password of the website given in the body using json and the key `websote`. This required the IP of the sender to have been verfied using 2fa. 
- PUT `updatePassword` : modify the password of the current user to the new one given for the website given in the json body using keys `website` and `password`. This requires the IP addres of the sender to have been verified using 2fa

# Development

see github