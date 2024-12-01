#pragma once

#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <boost/endian.hpp>
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "cksum.h"

#define ID_SIZE 16
#define NAME_SIZE 255
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define VERSION 3
#define CODE_SIZE 2
#define REGISTRATION_REQUEST 825

extern unsigned long _crc;
extern std::string path;
extern std::string _priv_key;



