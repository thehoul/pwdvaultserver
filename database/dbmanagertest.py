from database.dbmanager import DbManager

uname = 'admin'
email = 'admin@localhost'
hashpwd = '1234'
salt = '5678'


def test_register_unregister(db):
    assert db.register(uname, email, hashpwd, salt), "User not registered"
    assert db.unregister(uname), "User not unregistered"
    assert not db.get_login(uname), "User not logged in"

def test_get_password(db):
    db.register(uname, email, hashpwd, salt)

    pwd = 'password'
    domain = 'google.com'

    db.add_password(uname, domain, pwd)
    res = db.get_password(uname, domain)

    assert res == pwd, f"Expected {pwd}, got {res}"

def test_update_password(db):
    db.register(uname, email, hashpwd, salt)

    pwd = 'password'
    domain = 'google.com'

    db.add_password(uname, domain, pwd)

    new_pwd = 'newpassword'
    db.update_password(uname, domain, new_pwd)
    res = db.get_password(uname, domain)

    assert res == new_pwd, f"Expected {new_pwd}, got {res}"

def test_delete_password(db):
    db.register(uname, email, hashpwd, salt)

    pwd = 'password'
    domain = 'google.com'

    db.add_password(uname, domain, pwd)
    db.delete_password(uname, domain)

    res = db.get_password(uname, domain)
    assert not res, f"Expected None, got {res}"

def test_two_domain_delete_password(db):
    db.register(uname, email, hashpwd, salt)

    pwd1 = 'password1'
    pwd2 = 'password2'
    domain1 = 'google.com'
    domain2 = 'facebook.com'

    db.add_password(uname, domain1, pwd1)
    db.add_password(uname, domain2, pwd2)

    assert db.get_password(uname, domain1) == pwd1, f"Expected {pwd1}, got {res}"
    assert db.get_password(uname, domain2) == pwd2, f"Expected {pwd2}, got {res}"

    db.delete_password(uname, domain1)

    res = db.get_password(uname, domain1)
    assert not res, f"Expected None, got {res}"

    res = db.get_password(uname, domain2)
    assert res == pwd2, f"Expected {pwd2}, got {res}"

    db.delete_password(uname, domain2)

    res = db.get_password(uname, domain2)
    assert not res, f"Expected None, got {res}"

def test_get_ipaddress(db):
    db.register(uname, email, hashpwd, salt)

    ip = '192.168.1.1'
    db.add_ipaddress(uname, ip)

    res = db.get_ipaddresses(uname)[0][0]
    assert res == ip, f"Expected {ip}, got {res}"

def test_two_ipaddress(db):
    db.register(uname, email, hashpwd, salt)

    ip1 = '192.168.1.2'
    ip2 = '192.168.1.3'

    db.add_ipaddress(uname, ip1)
    db.add_ipaddress(uname, ip2)

    res = db.get_ipaddresses(uname)

    assert res[0][0] != res[1][0], f"Expected {ip1} and {ip2} to be different"
    assert res[0][0] == ip1 or res[0][0] == ip2, f"Expected {ip1}, got {res[0][0]}"
    assert res[1][0] == ip2 or res[1][0] == ip1, f"Expected {ip2}, got {res[1][0]}"

# Make main method
def main():
    db = DbManager('.tmp.db')
    #test_register_unregister(db)
    #print("------")
    #test_get_password(db)
    #print("------")
    #test_update_password(db)
    #print("------")
    #test_delete_password(db)
    #print("------")
    #test_two_domain_delete_password(db)
    #print("------")
    #test_get_ipaddress(db)
    #print("------")
    test_two_ipaddress(db)

if __name__ == "__main__":
    main()
