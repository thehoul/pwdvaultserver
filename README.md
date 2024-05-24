# Description

This is a server program using python to create an API for a password vault. Run `pwdvault.py` to run the app. You need to install the requirements first.

# Endpoints

## Users management
- POST `/user/<username>`: create a new user using the given username. The password needs to be provided in the body as a json using the key `password`. This will return a cookie to use for future communications
- GET `/user/<username>`: login to the user using the given username and the password given in the body as a json using the key `password`. This return a cookie to use for future communications
- DELETE `/user/<username>`: delete the user. This requires the cookie generated when logging in. This delete entirely the user, all saved passwords will be deleted.

For now, there is now way to modify users (i.e. can't change the username of the password)

## Passwords management

- GET `/passwords/<username>/<website>`: return the list of passwords used by the user identified by the given username for the given website. This requires the cookie generated when logging in.
- POST `passwords/<username>/<website>`: add to the given user and the given website an entry contaning the password given in the body using json and the key `password`. This requires the cookie generated when logging in.
- DELETE `passwords/<username>/<website>`: delete for the user in the given website the password entry matching the password given in the body using json and the key `password`. This requires the cookie generate in when logging in. 

# Development

- [ ] Add CSRF to JWT cookies
- [ ] Add user modifications (change password, username)
    - [ ] Add email to users for changing password
- [ ] TBD