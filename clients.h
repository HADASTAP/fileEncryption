#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <boost/endian.hpp>
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

#define PATH_SIZE 255
#define NAME_SIZE 255
#define FILE_NAME_SIZE 255
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define CODE_SIZE 2
#define ID_SIZE 16
#define VERSION 3
#define REGIST_SUCCEED_ANS 1600
#define INVALID_RECONNECT_ANS 1606
#define REGIST_REQUEST 825
#define RECONNECT_REQUEST 827

boost::asio::io_context io_context;
tcp::socket s(io_context);
tcp::resolver resolver(io_context);

std::string load_file(std::string path);
std::string encrypt_file(std::string, std::string);
std::vector <uint8_t> insert_header(std::vector <uint8_t>, int, int);
uint16_t receive_header();
uint8_t* receive_server_key(uint8_t[]);
void build_priv_info(Base64Wrapper, std::string);
void build_me_info(Base64Wrapper, char[], std::string, uint8_t[]);
void sendDataToServer(std::vector <uint8_t>, int);
std::string toHexStr(const uint8_t*, int);
void build_encrypted_file_request(std::string encrypt, uint8_t* id_address, std::string all_file);


