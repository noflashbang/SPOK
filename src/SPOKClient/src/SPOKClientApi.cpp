#include "SPOKClientApi.h"
#include "SPOKClient.h"


SPOK_Handle SPC_Create()
{
	SPOKCore core;
	return core.GetVersion();
}

void SPC_AIKCreate(std::wstring name, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce)
{
	SPOKClient client;
	client.AIKCreate(name, flag, nonce);
}

void SPC_AIKDelete(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	SPOKClient client;
	client.AIKDelete(name, flag);
}

bool SPC_AIKExists(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	SPOKClient client;
	return client.AIKExists(name, flag);
}

