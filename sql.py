import sqlite3
import classes
import uuid
import classes

#this function creates client and files tables


#this function creates client and files tables
def create():
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients (
                    id text,
                    name text,
                    public_key blob,
                    last_seen text,
                    AES_key blob,
                    primary key(id)
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                    id text,
                    file_name text,
                    path_name text,
                    verified bool,
                    primary key(id, file_name)
                )''')
    conn.close()

#this function insert new client with new uuid, name, and last_seen
def insert_client(name, lastseen):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    cl = classes.Client(uuid.uuid4().bytes, name, '', lastseen, '')
    client = [
        (cl.cid, cl.name, cl.public_key, cl.last_seen, cl.aes)
    ]
    c.executemany("INSERT INTO clients VALUES(?, ?, ?, ?, ?)", client)
    conn.commit()
    c.close()
    conn.close()
    return cl

#this function insert new file with id of client, file name and file path
def insert_file(id, filename, pathname):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    f = classes.File(id, filename, pathname, False)
    file = [
        (f.cid, f.file_name, f.path_name, f.verified)
    ]
    c.executemany("INSERT INTO files VALUES(?, ?, ?, ?)", file)
    conn.commit()
    c.close()
    conn.close()
    return f

#this function add public key to client
def add_pub_key(id, pub_key):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("UPDATE clients SET public_key = ? WHERE id = ?", (pub_key, id))
    c.close()
    conn.close()

#this function add aes key to client
def add_aes_key(id, aes):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("UPDATE clients SET AES_key = ? WHERE id = ?", (aes, id))
    c.close()
    conn.close()

#this function update the last seen of client
def update_lastseen(id, lastseen):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("UPDATE clients SET last_seen = ? WHERE id = ?", (lastseen, id))
    c.close()
    conn.close()

#this function update the verified of file
def update_file(id, name, ver):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("UPDATE files SET verified = ? WHERE id = ? and file_name = ?", (ver, id, name))
    c.close()
    conn.close()

#this function delete file if verified is False after 3 times of sended crc
def delete_file(id, name):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE id = ? AND file_name = ?", (id, name))
    c.close()
    conn.close()

# this function delete file if verified is False after 3 times of sended crc
def delete_client(id, name):
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute("DELETE FROM clients WHERE id = ? AND file_name = ?", (id, name))
    c.close()
    conn.close()

#this function execute all clients (to insert them to client_list)
def execute_clients():
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    query = c.execute("SELECT * FROM clients")
    results = query.fetchall()
    c.close()
    conn.close()
    return results

#this function execute all files (to insert them to file_list)
def execute_files():
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    query = c.execute("SELECT * FROM files")
    results = query.fetchall()
    c.close()
    conn.close()
    return results

