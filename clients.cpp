
#include "clients.h"

char _name_[NAME_SIZE] = { '\0' };
char _file_[FILE_NAME_SIZE] = { '\0' };
char _path_[PATH_SIZE] = { '\0' };
std::string path;
std::string _aes_key;
std::string _priv_key;

/*this function sends the data to the server*/
void sendDataToServer(std::vector<uint8_t> message, int messageSize) {
	try {
		boost::asio::write(s, boost::asio::buffer(message, messageSize)); // Send the vector to the server
	}
	catch (std::exception& ex) {
		std::cerr << "Error: " << ex.what() << "\n"; // Print exception message
	}
}

/*this function read data from 'transfer.info' file (including ip and port) and connect to server*/
void connection()
{
	std::ifstream trans;
	std::string ip_port, ip, port, file_name, name;
	trans.open("transfer.info");
	if (trans.is_open()) /*succeed to open transfer file*/
	{
		getline(trans, ip_port);
		getline(trans, name);
		getline(trans, path);
		size_t pos_file_name = path.find_last_of('/');
		size_t pos = ip_port.find(':');
		ip = ip_port.substr(0, pos);
		port = ip_port.substr(pos + 1);
		if (pos_file_name == std::string::npos) /*path name is simply the file name*/
		{
			file_name = path;
		}
		else
		{
			file_name = path.substr(pos_file_name + 1);
		}
		strcpy_s(_name_, name.data());
		strcpy_s(_file_, file_name.data());
		for (int i = name.size(); i < NAME_SIZE; i++) /*padding _name_line to be size of 255 with character '\0'*/
		{
			_name_[i] = '\0';
		}
		for (int i = file_name.size(); i < FILE_NAME_SIZE; i++) /*padding _file_name to be size of 255 with character '\0'*/
		{
			_file_[i] = '\0';
		}
		trans.close();
	}
	else
	{
		std::cout << "not found 'transfer.info' file. exit.\n";
		exit(1);
	}
	boost::asio::connect(s, resolver.resolve(ip, port)); /*connect with ip and port*/
	std::cout << "client sucssed connect to server.\n";

}


/*user registed already*/
int reconnect(std::string priv_key)
{
	std::vector <uint8_t> messege;
	uint8_t enc_id[ID_SIZE];
	std::ifstream me_f;
	std::string name, id;
	me_f.open("me.info"); /*me exists (checked in main function)*/
	getline(me_f, name);
	getline(me_f, id);
	me_f.close();
	strcpy_s(_name_, name.data());
	for (int i = name.size(); i < NAME_SIZE; i++) /*padding _name_line to be size of 255 with character '\0'*/
	{
		_name_[i] = '\0';
	}
	for (int i = 0; i < ID_SIZE; i++) /*insert id to the vector will be sent to server*/
	{
		messege.push_back(id[i]);
	}
	messege = insert_header(messege, RECONNECT_REQUEST, NAME_SIZE);
	for (int i = 0; i < NAME_SIZE; i++) /*insert payload (name) to the vector will be sent to server*/
	{
		messege.push_back(_name_[i]);
	}
	std::cout << "you are almost regist, ask to reconnect question code : " << RECONNECT_REQUEST << std::endl;
	sendDataToServer(messege, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE); /*send vector to server*/
	uint8_t* id_add = receive_server_key(enc_id);
	if (id_add == NULL) /*server didn't find name, regist from beginning*/
	{
		std::cout << "server didn't find your name, try to regist from beginning.\n";
		return INVALID_RECONNECT_ANS;
	}
	std::string all_file = load_file(path);
	std::string encrypt = encrypt_file(_aes_key, priv_key);
	build_encrypted_file_request(encrypt, enc_id,all_file);
	return 0;
}

/*this function regists new user to the system*/
std::string regist_for_server()
{
	uint8_t reply_id[ID_SIZE] = { '\0' };
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*user not exists - there is no uuid - send 0*/
	{
		send_mes.push_back('0');
	}
	send_mes = insert_header(send_mes, REGIST_REQUEST, NAME_SIZE);
	for (int i = 0; i < NAME_SIZE; i++)  /*insert payload (name) to the vector will be sent to server*/
	{
		send_mes.push_back(_name_[i]);
	}
	sendDataToServer(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE); /*send vector to server*/
	uint16_t answer_code = receive_header(); /*get header from server*/
	if (answer_code == REGIST_SUCCEED_ANS)
	{
		try
		{
			size_t id_length = boost::asio::read(s, boost::asio::buffer(reply_id, ID_SIZE));
			std::cout << "Registration succeeded. uuid (in hex) is: " << toHexStr(reply_id, ID_SIZE) << std::endl;
		}
		catch (std::exception& e)
		{
			std::cerr << "Exception: " << e.what() << "\n";
		}
	}
	else
	{
		std::cout << "Registration failed. exit.\n";
		exit(1);
	}
	/*create keys*/
	RSAPrivateWrapper* priv_key = new RSAPrivateWrapper();
	const std::string private_key = priv_key->getPrivateKey();
	const std::string public_key = priv_key->getPublicKey();
	Base64Wrapper base64;
	build_me_info(base64, _name_, private_key, reply_id);
	build_priv_info(base64, private_key);
	return public_key;
}



