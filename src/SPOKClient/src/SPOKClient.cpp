#include "SPOKClient.h"


SPOKClient::SPOKClient()
{
}

SPOKClient::~SPOKClient()
{
}

void SPOKClient::AIKCreate(std::wstring name, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce)
{
	NCryptUtil::CreateAik(name, flag, nonce);
}

void SPOKClient::AIKDelete(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	NCryptUtil::DeleteKey(name, flag);
}

bool SPOKClient::AIKExists(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	return NCryptUtil::DoesAikExists(name, flag);
}
