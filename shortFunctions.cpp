#include "shortFunctions.h"

std::string toHexStr(const uint8_t* data, int len);


/*this function creates 'me.info' file and write to the file the client name, the uuid get from server and the private key in base 64*/
void build_me_info(Base64Wrapper base64, char name[NAME_SIZE], std::string private_key, uint8_t id[ID_SIZE])
{
	std::ofstream me_file;
	me_file.open("me.info");
	me_file << name << std::endl;
	me_file << toHexStr(id, ID_SIZE) << std::endl;
	me_file << base64.encode(private_key) << std::endl;
	me_file.close();
}

/*this function creates 'priv.key' file and write to the file the private key in base 64*/
void build_priv_info(Base64Wrapper base64, std::string private_key)
{
	std::ofstream priv_file;
	priv_file.open("priv.key");
	priv_file << base64.encode(private_key) << std::endl;
	priv_file.close();
}


/*this function read private key from 'priv.key' file*/
std::string loadPrivateKey()
{
	std::ifstream priv_file;
	priv_file.open("priv.key");
	std::string line, private_key;
	while (getline(priv_file, line))
	{
		private_key += line;
	}
	_priv_key = private_key;
	priv_file.close();
	return private_key;
}

/*this function read the file that need to be encrypted*/
std::string load_file(std::string path)
{
	std::ifstream my_file;
	std::string line, all_file;
	my_file.open(path);
	if (my_file.good()) {
		while (getline(my_file, line))
		{
			all_file += line;
			all_file += '\n';
		}
		my_file.close();
	}
	else
	{
		std::cout << "file not exists. exit.\n";
		exit(1);
	}
	return all_file;
}

/*this function push the version, code, and payload size to the vector that will be sent to the server*/
std::vector <uint8_t> insert_header(std::vector <uint8_t> send_mes, int code_num, int size)
{
	uint8_t version[VERSION_SIZE], code[CODE_SIZE], payload_size[PAYLOAD_SIZE];
	version[0] = VERSION;
	boost::endian::store_little_u16(code, (uint16_t)code_num);
	boost::endian::store_little_u32(payload_size, (uint32_t)size);
	send_mes.push_back(version[0]);
	for (int i = 0; i < CODE_SIZE; i++)
	{
		send_mes.push_back(code[i]);
	}
	for (int i = 0; i < PAYLOAD_SIZE; i++)
	{
		send_mes.push_back(payload_size[i]);
	}
	return send_mes;
}


/*this file gets the aes key from server and private key and encrypt the file that need to be encrypted*/
std::string encrypt_file(std::string reply_aes, std::string private_key)
{
	Base64Wrapper b64wrapper;
	RSAPrivateWrapper* priv_key = new RSAPrivateWrapper(b64wrapper.decode(private_key));
	std::string open_private_key = priv_key->decrypt(reply_aes); /*open the aes key with the private key*/
	AESWrapper* aes_key = new AESWrapper((unsigned char*)open_private_key.data(), (unsigned int)size(open_private_key));
	std::string all_file = load_file(path); /*read the file*/
	_crc = memcrc(all_file.data(), all_file.size()); /*get crc of file*/
	std::string encrypt = aes_key->encrypt(all_file.data(), all_file.size()); /*encrypt file*/
	return encrypt;
}


/*this function convert string to hex string*/
std::string toHexStr(const uint8_t* data, int len)
{
	try
	{
		std::stringstream res;
		res << std::hex;
		for (int i = 0; i < len; ++i)
		{
			res << std::setw(2) << std::setfill('0') << (int)data[i];
		}
		return res.str();
	}
	catch (...)
	{
		std::cout << "Erorr to convert to hex" << std::endl;
		return "";
	}
}


/*this function convert hex string to bytes string*/
std::string HexToBytes(const std::string& hex)
{
	std::string res;
	for (auto i = 0u; i < hex.length(); i += 2)
	{
		std::string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, ID_SIZE);
		res += byte;
	}
	return res;
}
