import os
import Crypto.Random
import struct
import selectors
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import sql
from base64 import b64decode
from Crypto.Util import Padding
import cksum
from datetime import datetime
from constants import *
from functions import *
from requests import *

sel = selectors.DefaultSelector()
file_content = b''

def connection(sock, mask):
    conn, addr = sock.accept()
    print('accepted from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, sort_question)

try:
    with open('port.info', 'r') as f:
        print("Opened port.info successfully.")
        lines = f.readlines()
        if not lines:
            print(f'Working on default port: {DEFAULT_PORT}')
            port_number = DEFAULT_PORT
        else:
            port_number = int(lines[0].strip())  # Convert to integer if valid
        print(f'Port number: {port_number}')
except FileNotFoundError:
    print("port.info not found, using default port.")
    port_number = DEFAULT_PORT
except ValueError:
    print("Invalid port number in file, using default port.")
    port_number = DEFAULT_PORT
except Exception as e:
    print(f"An unexpected error occurred: {e}. Using default port.")
    port_number = DEFAULT_PORT

def sort_question(conn, mask):
    global file_content

    # Get header
    b_client_id = conn.recv(CLIENT_ID_SIZE)
    b_version = conn.recv(VERSION_SIZE)
    b_code = conn.recv(CODE_SIZE)
    b_payload = conn.recv(PAYLOAD_SIZE_IN_BYTES)

    if not (b_client_id and b_version and b_code and b_payload):  # Simplified check
        print('Closing server for current user.')
        sel.unregister(conn)
        conn.close()
        return

    client_id = b_client_id.hex()
    version = convert_byte_to_int(b_version)
    code = convert_byte_to_int(b_code)
    payload = convert_byte_to_int(b_payload)

    if code == REGISTRATION_REQUEST:
        print(f"Registration request: {code}")
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '')
        registration_request(conn, code, name)

    elif code == SEND_PUB_KEY_REQUEST:
        print(f"Send public key request: {code}")
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '')
        pub_key = conn.recv(PUBLIC_KEY_SIZE)
        send_pub_key_request(conn, code, name, pub_key)

    elif code == RECONNECT_REQUEST:
        print(f"Reconnect request: {code}")
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '')
        reconnect_request(conn, code, name)

    elif code == SEND_FILE_REQUEST:
        print(f"send file request: {code}")

        byte_content_size = conn.recv(PAYLOAD_SIZE_IN_BYTES)
        byte_orig_file_size = conn.recv(ORIG_FILE_SIZE)
        byte_packet_number = conn.recv(PACKET_NUMBER_SIZE)
        byte_total_packets = conn.recv(TOTAL_PACKETS_SIZE)
        content_size = convert_byte_to_int(byte_content_size)
        packet_number = convert_byte_to_int(byte_packet_number)
        total_packets = convert_byte_to_int(byte_total_packets)
        print(f"accept packet number : {packet_number} from : {total_packets}")
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        current_size = payload - PAYLOAD_REQUEST_FILE_SIZE
        file_content += conn.recv(current_size)
        if packet_number == total_packets:
            send_file_request(conn, code, client_id, file_name, file_content, content_size)
            file_content = b""

    elif code == VALID_CRC_REQUEST:
        print(f"valid crc request: {code}")
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        valid_crc_request(conn, code, file_name, client_id)

    elif code == INVALID_CRC_REQUEST:
        print(f"invalid crc request: {code}")
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        invalid_crc_request(conn, code, file_name, client_id)

    elif code == LAST_INVALID_CRC_REQUEST:
        print(f"last invalid crc request: {code}")
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        last_invalid_crc_request(conn, code, file_name, client_id)

if __name__ == "__main__":
    load_DB()
    try:
        sock = socket.socket()
        sock.bind(('', port_number))
        sock.listen(MAX_CLIENTS)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, connection)
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    except OSError as e:
        delete_files()
        print(f'Socket error occurred: {e}. Exiting.')
        exit(1)

    finally:
        sock.close()



