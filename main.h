#pragma once

#include <string>
#include <fstream>
#include <iostream>

#define INVALID_RECONNECT_ANS 1606
#define REGISTRATION_REQUEST 825
#define RECONNECT_REQUEST 827
#define PUB_KEY_REQUEST 826


void connection();
std::string loadPrivateKey();
int reconnect(std::string);
std::string regist_for_server();
std::string build_public_key(std::string);
void receive_pub_key(std::string);

