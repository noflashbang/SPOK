#include "SPOKClientApi.h"
#include "SPOKClient.h"

SPOK_Handle SPC_Create()
{
	return 0;
}

void SPC_AIKCreate(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* nonce, const size_t cbNonce)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto spokNonce = SPOK_Nonce::Make(nonce, cbNonce);
	SPOKClient client;
	client.AIKCreate(key, spokNonce);
}

void SPC_AIKDelete(const wchar_t* name, const NCRYPT_MACHINE_KEY flag)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	client.AIKDelete(key);
}

bool SPC_AIKExists(const wchar_t* name, const NCRYPT_MACHINE_KEY flag)
{
	auto key = SPOK_PlatformKey { name, flag };
	SPOKClient client;
	return client.AIKExists(key);
}

void SPC_AIKGetPublicKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	auto blob = client.AIKGetPublicKey(key);
	
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_AIKGetChallengeBinding(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	auto blob = client.AIKGetChallengeBinding(key);

	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_GetPCRTable(uint8_t* pPcrTable, const size_t cbPcrTable, size_t& sizeOut)
{
	SPOKClient client;
	auto pcrTable = client.GetPCRTable();
	SPOK_Blob::Copy2CStylePtr(pcrTable.GetBlob(), pPcrTable, cbPcrTable, sizeOut);
}