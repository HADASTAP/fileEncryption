#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <boost/endian.hpp>
#include <vector>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

#define MAX_FILE_SIZE_PER_TIME 1024
#define NAME_SIZE 255
#define FILE_NAME_SIZE 255
#define ID_SIZE 16
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define VERSION 3
#define CODE_SIZE 2
#define PUBLIC_KEY_SIZE 160
#define SEND_PUB_KEY_REQUEST 826
#define CONTENT_FILE_SIZE 4
#define SEND_FILE_REQUEST 828
#define VALID_CRC_REQUEST 900
#define INVALID_CRC_REQUEST 901
#define LAST_INVALID_CRC_REQUEST 902
#define PACKET_NUMBER_SIZE 2
#define TOTAL_PACKETS_SIZE 2
#define ORIG_FILE_SIZE 4

extern boost::asio::io_context io_context;
extern tcp::socket s;
extern tcp::resolver resolver;

extern char _name_[NAME_SIZE];
extern char _file_[FILE_NAME_SIZE];
extern std::string _priv_key;

std::string HexToBytes(const std::string&);
std::vector <uint8_t> insert_header(std::vector <uint8_t>, int, int);
void sendDataToServer(std::vector <uint8_t>, int);
void receive_crc();
void receive_answer(uint16_t);


