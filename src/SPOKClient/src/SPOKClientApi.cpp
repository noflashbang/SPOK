#include "SPOKClientApi.h"
#include "SPOKClient.h"
#include "Blob.h"


SPOK_Handle SPC_Create()
{
	SPOKCore core;
	return core.GetVersion();
}

void SPC_AIKCreate(std::wstring name, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	client.AIKCreate(key, nonce);
}

void SPC_AIKDelete(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	client.AIKDelete(key);
}

bool SPC_AIKExists(std::wstring name, NCRYPT_MACHINE_KEY flag)
{
	auto key = SPOK_PlatformKey { name, flag };
	SPOKClient client;
	return client.AIKExists(key);
}

void SPC_AIKGetPublicKey(std::wstring name, NCRYPT_MACHINE_KEY flag, unsigned char* pBytesOut, size_t cbBytesOut, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	auto blob = client.AIKGetPublicKey(key);
	
	CopySpokBlob2CStylePtr(blob, pBytesOut, cbBytesOut, sizeOut);
}

void SPC_AIKGetChallengeBinding(std::wstring name, NCRYPT_MACHINE_KEY flag, unsigned char* pBytesOut, size_t cbBytesOut, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	auto blob = client.AIKGetChallengeBinding(key);

	CopySpokBlob2CStylePtr(blob, pBytesOut, cbBytesOut, sizeOut);
}