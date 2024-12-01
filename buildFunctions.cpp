#include "buildFunctions.h"

/*this function send the encrypted file to server.*/
void build_encrypted_file_request(std::string encrypt, uint8_t* id_address, std::string all_file)
{
	
	uint16_t total_packets = std::ceil(static_cast<double>(encrypt.size()) / MAX_FILE_SIZE_PER_TIME);
	std::cout << "ancrypt  " << static_cast<double>(encrypt.size())<<std::endl;
	std::cout << "  " << std::endl;
	int  current_content_size = 0;
	std::vector <uint8_t> send_mes;
	std::vector <uint8_t> temp_messege;
	std::vector <uint8_t> final_messege;
	uint8_t content[CONTENT_FILE_SIZE];
	uint8_t orig_content[ORIG_FILE_SIZE];
	uint8_t tot_packet[ORIG_FILE_SIZE];
	uint8_t current_pack_bytes[ORIG_FILE_SIZE];
	boost::endian::store_little_u32(content, (uint32_t)encrypt.size());
	boost::endian::store_little_u32(orig_content, (uint32_t)all_file.size());
	boost::endian::store_little_u16(tot_packet, total_packets);
	int j;
	current_content_size = encrypt.size();

	for (int i = 0; i < total_packets; i++)
	{
		int currentSize = std::min(MAX_FILE_SIZE_PER_TIME, current_content_size);
		
		boost::endian::store_little_u16(current_pack_bytes, static_cast<uint16_t>(i+1));

		for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
		{
			send_mes.push_back(id_address[i]);
		}
		send_mes = insert_header(send_mes, SEND_FILE_REQUEST, currentSize + FILE_NAME_SIZE + CONTENT_FILE_SIZE + PACKET_NUMBER_SIZE + TOTAL_PACKETS_SIZE + ORIG_FILE_SIZE);
		/*insert payload (content file size, file name and encrypted content) to vector will be sent to server.*/
		for (int i = 0; i < CONTENT_FILE_SIZE; i++)
		{
			send_mes.push_back(content[i]);
		}
		for (int i = 0; i < ORIG_FILE_SIZE; i++)
		{
			send_mes.push_back(orig_content[i]);
		}
		for (int i = 0; i < PACKET_NUMBER_SIZE; i++)
		{
			temp_messege.push_back(current_pack_bytes[i]);
		}
		for (int i = 0; i < TOTAL_PACKETS_SIZE; i++)
		{
			temp_messege.push_back(tot_packet[i]);
		}
		for (int i = 0; i < FILE_NAME_SIZE; i++)
		{
			temp_messege.push_back(_file_[i]);
		}
		for (j = 0; j < currentSize; j++)
		{
			temp_messege.push_back(encrypt[j+ i* MAX_FILE_SIZE_PER_TIME]);
		}
		final_messege.insert(final_messege.end(), send_mes.begin(), send_mes.end());
		final_messege.insert(final_messege.end(), temp_messege.begin(), temp_messege.end());
		sendDataToServer(final_messege, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + CONTENT_FILE_SIZE + FILE_NAME_SIZE + currentSize + PACKET_NUMBER_SIZE + TOTAL_PACKETS_SIZE + ORIG_FILE_SIZE); /*send vector to server*/
		std::cout << "send packet : " << i+1<< " from " << total_packets << " packets" << std::endl;
		temp_messege.clear();
		final_messege.clear();
		send_mes.clear();
        current_content_size -= MAX_FILE_SIZE_PER_TIME;
	}
	std::cout << "complete sending file  " << std::endl;

	receive_crc(); /*get crc from server to compare. send 0 to sign that client still didn't try to send crc*/

}

/*this function send public key to server*/
std::string build_public_key(std::string public_key)
{
	std::ifstream my_file;
	std::string name, private_key, priv_key, id_str;
	std::vector <uint8_t> send_mes;
	my_file.open("me.info");
	getline(my_file, name);
	getline(my_file, id_str);
	while (getline(my_file, priv_key))
	{
		private_key += priv_key;
	}
	_priv_key = private_key;
	std::string id_new = HexToBytes(id_str);
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_new.data()[i]);
	}
	send_mes = insert_header(send_mes, SEND_PUB_KEY_REQUEST, NAME_SIZE + PUBLIC_KEY_SIZE);
	/*insert payload (name and public key) to vector will be sent to server.*/
	for (int i = 0; i < NAME_SIZE; i++)
	{
		send_mes.push_back(_name_[i]);
	}
	for (int i = 0; i < PUBLIC_KEY_SIZE; i++)
	{
		send_mes.push_back(public_key[i]);
	}
	sendDataToServer(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE + PUBLIC_KEY_SIZE); /*send vector to server*/
	my_file.close();
	return private_key;
}

/*this function send success message to server to sign crc are equals*/
void build_success_message(uint8_t* id_address)
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = insert_header(send_mes, VALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_[i]);
	}
	sendDataToServer(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE); /*send vector to server*/
	receive_answer(VALID_CRC_REQUEST); /*get answer from server*/
}

/*this function send not success message to server to sign crc are not equals*/
void build_not_success_message(uint8_t* id_address)
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = insert_header(send_mes, INVALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_[i]);
	}
	sendDataToServer(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE); /*send vector to server*/
}

/*this function send not success message to server to sign crc are not equals*/
void build_abort_message(uint8_t* id_address)
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = insert_header(send_mes, LAST_INVALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_[i]);
	}
	sendDataToServer(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE);
	receive_answer(LAST_INVALID_CRC_REQUEST); /*get answer from server*/
}