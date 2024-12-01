#include "main.h"

int main(int argc, char* argv[])
{
	int status = 0;
	std::string pub_key, priv_key;
	connection(); /*connect to server (using ip and port from 'transfer.info' file*/
	std::ifstream me_f("me.info");
	if (me_f.good()) /*almost regised*/
	{
		priv_key = loadPrivateKey();
		status = reconnect(priv_key);
	}
	if (!me_f.good() || status == INVALID_RECONNECT_ANS) /*me file not exists. new client*/
	{
		std::cout << "ask to regist : " << REGISTRATION_REQUEST << std::endl;
		pub_key = regist_for_server(); /*regist from beginning*/
		priv_key = build_public_key(pub_key);
		std::cout << "ask to accept public key: " << PUB_KEY_REQUEST << std::endl;
		receive_pub_key(priv_key);
	}
}
