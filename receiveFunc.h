
#pragma once

#include <string>
#include <boost/endian.hpp>
#include <iostream>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

#define PATH_SIZE 255
#define FILE_NAME_SIZE 255
#define ID_SIZE 16
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define CONTENT_FILE_SIZE 4
#define CRC_SIZE 4
#define SEND_CRC 3
#define CODE_SIZE 2
#define VALID_CRC_REQUEST 900
#define INVALID_RECONNECT_ANSWER 1606
#define GENERAL_ANSWER 1607
#define SEND_PUB_KEY_REQUEST 826


extern boost::asio::io_context io_context;
extern tcp::socket s;
extern tcp::resolver resolver;

extern std::string path;
extern std::string _aes_key;
extern std::string _priv_key;
uint32_t aes_size = 0;
int _trying_to_send_crc = 0;
unsigned long _crc = 0;

std::string load_file(std::string path);
void build_encrypted_file_request(std::string encrypt, uint8_t* id_address, std::string all_file);
std::string encrypt_file(std::string, std::string);
void build_not_success_message(uint8_t*);
void build_success_message(uint8_t*);
void build_abort_message(uint8_t*);
uint8_t* receive_server_key(uint8_t[]);