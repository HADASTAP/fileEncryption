from constants import *
from functions import *
from datetime import datetime
import sql
import os
import Crypto.Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util import Padding
import cksum

def registration_request(conn, code, name):
    try:
        for c in client_list:
            if c.name == name:  # Client already exists
                print(f"{name}, your request to register as a new user (request code: {code}) not accepted (name already exists).")
                sql.update_lastseen(c.cid, str(datetime.now()))
                send_header(conn, REGIST_NOT_SUCCEED_ANS, 0)
                print("closing", conn)
                sel.unregister(conn)
                conn.close()
                return  # Exit the function to avoid further execution

        print(f"{name}, your request to register as a new user (request code: {code}) accepted.")
        new_client = registration(name, str(datetime.now()))  # Create new client with name, last_seen, and uuid (created in the db)
        client_list.append(new_client)  # Add client to client_list
        size_client_id = len(new_client.cid)
        send_header(conn, REGIST_SUCCEED_ANS, size_client_id)  # Send header (version, code, payload_size)
        write_byte(conn, new_client.cid, size_client_id)  # Send payload - client ID
        print(f"name: {name}. UUID (in hex): {new_client.cid.hex()}")

    except Exception as e:
        print(f"An error occurred: {e}")

def send_pub_key_request(conn, code, name, pub_key):
    print(f'{name}, your request to send a public key (request code: {code}) accepted.')
    aes_key = Crypto.Random.get_random_bytes(AES_KEY_SIZE)  # create aes key
    encrypted_aes_key = public_key(aes_key, pub_key)
    lastseen = str(datetime.now())
    for c in client_list:
        if c.name == name:  # looking for current client. (name must be unique)
            c.public_key = pub_key
            c.aes = aes_key
            c.last_seen = lastseen
            sql.add_pub_key(c.cid, pub_key)
            sql.add_aes_key(c.cid, aes_key)
            sql.update_lastseen(c.cid, lastseen)
            size = len(c.cid) + len(encrypted_aes_key)
            send_header(conn, PUB_KEY_SEND_ENCRYPTED_AES, size)  # send header (version, code, payload_size)
            write_byte(conn, c.cid, len(c.cid))
            write_byte(conn, encrypted_aes_key, len(encrypted_aes_key))

def reconnect_request(conn, code, name):
    try:
        find = False
        for c in client_list:
            if c.name == name:
                print(f"{name}, your request to reconnect (request code: {code}) accepted.")
                sql.update_lastseen(c.cid, str(datetime.now()))  # Last seen = current time
                encrypted_aes_key = public_key(c.aes, c.public_key)
                size = len(c.cid) + len(encrypted_aes_key)
                send_header(conn, VALID_RECONNECT_SEND_AES, size)  # Send header (version, code, payload_size)
                write_byte(conn, c.cid, len(c.cid))
                write_byte(conn, encrypted_aes_key, len(encrypted_aes_key))
                find = True
                break  # Exit the loop once the client is found and processed

        if not find:
            print(f"{name}, your request to reconnect (request code: {code}) not accepted (name doesn't exist. Please register from the beginning).")
            new_client = registration(name, str(datetime.now()))  # Create new client with name, last_seen, and uuid (created in the db)
            client_list.append(new_client)  # Add client to client_list
            size_client_id = len(new_client.cid)
            send_header(conn, REGIST_SUCCEED_ANS, size_client_id)  # Send header (version, code, payload_size)
            write_byte(conn, new_client.cid, size_client_id)  # Send payload - client ID

    except Exception as e:
        print(f"An error occurred: Client {name} does not exist in the system.")

def send_file_request(conn, code, client_id, file_name, file_content, content_size):
    path = folder_name + '/' + file_name
    f = open(path, "wb")
    file_exists = False
    for c in client_list:
        hex_id = c.cid.hex()
        if hex_id == client_id:
            cipher = AES.new(c.aes, AES.MODE_CBC, iv=bytes(AES_KEY_SIZE))
            content = Padding.unpad(cipher.decrypt(file_content), AES.block_size)
            f.write(content)
            crc = cksum.memcrc(content)
            sql.update_lastseen(c.cid, str(datetime.now()))
            print(f'{c.name}, your request to send an encrypted file: {file_name} (request code: {code}) accepted.')
            for f in file_list:
                if f.cid == c.cid and f.file_name == file_name:
                    file_exists = True
                    if f.verified:
                        print(f'{c.name}, notice: {file_name} almost exists. change the old file with the new file')
            if not file_exists:
                new_file = sql.insert_file(c.cid, file_name, path)
                file_list.append(new_file)
            send_header(conn, VALID_FILE_WITH_CRC, (CONTENT_FILE_SIZE + FILE_NAME_SIZE))
            conn.sendall(convert_int_to_byte(content_size, CONTENT_FILE_SIZE))
            padding_file_name = file_name.ljust(FILE_NAME_SIZE)
            send_message(conn, padding_file_name, len(padding_file_name))
            write_byte(conn, c.cid, len(c.cid))
            conn.sendall(convert_int_to_byte(crc, CRC_SIZE))

def valid_crc_request(conn, code, file_name, client_id):
    name = ''
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'{name}, your request to send valid CRC (request code: {code}) for: "{file_name}" file accepted.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            f.verified = True
            sql.update_file(f.cid, f.file_name, True)
            sql.update_lastseen(f.cid, str(datetime.now()))
            print(f'{name}, The {file_name} file decoded successfuly. Good bye.')
            send_header(conn, MESSAGE_ANSWER, len(f.cid))
            write_byte(conn, f.cid, len(f.cid))

def invalid_crc_request(conn, code, file_name, client_id):
    name = ''
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'server responded with an error: {name}, your request to send invalid CRC (request code: {code}) for: "{file_name}" file accepted. Try to send again.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            sql.update_lastseen(f.cid, str(datetime.now()))
            sql.update_file(f.cid, f.file_name, False)

def last_invalid_crc_request(conn, code, file_name, client_id):
    name = ''
    byte_id = b""
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'{name}, your request to send invalid CRC in the last time (request code: {code}) for: "{file_name}" file accepted. Exit.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            byte_id = f.cid
            sql.update_lastseen(f.cid, str(datetime.now()))
            sql.delete_file(f.cid, f.file_name)
            path = folder_name + '/' + file_name
            os.remove(path)
    send_header(conn, MESSAGE_ANSWER, len(byte_id))
    write_byte(conn, byte_id, len(byte_id))