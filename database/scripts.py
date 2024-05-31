# ---------- USER MANAGEMENT ----------
insert_person_script = '''
    INSERT INTO person (username, email)
    VALUES(\"{}\", \"{}\");
'''
insert_login_script = '''
    INSERT INTO login (userid, hashpwd, salt)
    VALUES(\"{}\" , \"{}\", \"{}\");
'''
get_userid_script = '''
    SELECT p.userid
    FROM person p
    WHERE p.username = \"{}\";
'''
get_user_detail_script = '''
    SELECT p.username, p.email
    FROM person p
    WHERE p.userid = \"{}\";
'''
get_pwdsalt_script = '''
    SELECT l.hashpwd, l.salt
    FROM login l
    WHERE l.userid = \"{}\";
'''
delete_person_script = '''
    DELETE 
    FROM person
    WHERE userid = \"{}\";
'''
# ---------- PASSWORD MANAGEMENT ----------
get_website_password_script = '''
    SELECT v.hashpwd
    FROM person p
    JOIN vault v
    ON p.userid = v.userid
    WHERE p.username = \"{}\" AND v.website = \"{}\";
'''
insert_website_password_script = '''
    INSERT INTO vault (userid, website, hashpwd)
    VALUES(\"{}\", \"{}\", \"{}\");
'''
update_website_password_script = '''
    UPDATE vault
    SET hashpwd = \"{}\"
    WHERE userid = \"{}\" AND website = \"{}\";
'''
delete_website_password_script = '''
    DELETE 
    FROM vault 
    WHERE userid = \"{}\" AND website = \"{}\";
'''

create_table_script = '''
    BEGIN;
    CREATE TABLE IF NOT EXISTS person(
        userid INTEGER PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL);
    CREATE TABLE IF NOT EXISTS login(
        userid INT NOT NULL PRIMARY KEY, 
        hashpwd VARCHAR(255) NOT NULL, 
        salt VARCHAR(255) NOT NULL,
        FOREIGN KEY(userid) REFERENCES person(userid) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS vault(
        userid INT NOT NULL, 
        website VARCHAR(255) NOT NULL, 
        hashpwd VARCHAR(255) NOT NULL,
        FOREIGN KEY(userid) REFERENCES person(userid),
        UNIQUE(userid, website));
    COMMIT;
'''