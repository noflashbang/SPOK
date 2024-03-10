#include "SPOKClientApi.h"
#include "SPOKClient.h"
#include "StandardLib.h"

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

void SPC_AIKGetKeyAttestation(const wchar_t* aikName, const NCRYPT_MACHINE_KEY aikFlag, const uint8_t* nonce, const size_t cbNonce, const wchar_t* keyName, const NCRYPT_MACHINE_KEY keyFlag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto aik = SPOK_PlatformKey{ aikName, aikFlag };
	auto key = SPOK_PlatformKey{ keyName, keyFlag };
	auto spokNonce = SPOK_Nonce::Make(nonce, cbNonce);
	SPOKClient client;
	auto blob = client.AIKGetKeyAttestation(aik, spokNonce, key);
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_AIKGetPlatformAttestation(const wchar_t* aikName, const NCRYPT_MACHINE_KEY aikFlag, const uint8_t* nonce, const size_t cbNonce, const uint32_t pcrsToInclude, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto aik = SPOK_PlatformKey{ aikName, aikFlag };
	auto spokNonce = SPOK_Nonce::Make(nonce, cbNonce);
	SPOKClient client;
	auto blob = client.AIKGetPlatformAttestation(aik, spokNonce, pcrsToInclude);
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}


void SPC_GetEndorsementPublicKey(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	SPOKClient client;
	auto blob = client.GetEndorsementPublicKey();
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
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
void SPC_AIKActivateChallenge(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pChallenge, const size_t cbChallenge, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto challenge = SPOK_Blob::New(pChallenge, cbChallenge);
	SPOKClient client;
	auto secret = client.AIKActivateChallenge(key, challenge);
	SPOK_Blob::Copy2CStylePtr(secret, pBytes, cbBytes, sizeOut);
}

void SPC_GetBootLog(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	SPOKClient client;
	auto blob = client.GetBootLog();
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_GetFilteredBootLog(const uint32_t pcrsToInclude, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	SPOKClient client;
	auto blob = client.GetBootLog(pcrsToInclude);
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_GetPCRTable(uint8_t* pPcrTable, const size_t cbPcrTable, size_t& sizeOut)
{
	SPOKClient client;
	auto pcrTable = client.GetPCRTable();
	SPOK_Blob::Copy2CStylePtr(pcrTable, pPcrTable, cbPcrTable, sizeOut);
}

void SPC_GetStorageRootKey(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	SPOKClient client;
	auto blob = client.GetStorageRootKey();
	SPOK_Blob::Copy2CStylePtr(blob, pBytes, cbBytes, sizeOut);
}

void SPC_PlatformImportWrappedKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pKeyBlob, const size_t cbKeyBlob)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto blob = SPOK_Blob::New(pKeyBlob, cbKeyBlob);
	SPOKClient client;
	client.PlatformImportKey(key, blob, KeyBlobType::WRAPPED);
}

void SPC_CreatePlatformKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag)
{
	auto key = SPOK_PlatformKey{ name, flag };
	SPOKClient client;
	client.PlatformCreateKey(key);
}

void SPC_PlatformDecrypt(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto blob = SPOK_Blob::New(pBytes, cbBytes);
	SPOKClient client;
	auto decrypted = client.PlatformDecrypt(key, blob);
	SPOK_Blob::Copy2CStylePtr(decrypted, pData, cbData, sizeOut);
}
void SPC_PlatformEncrypt(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto blob = SPOK_Blob::New(pBytes, cbBytes);
	SPOKClient client;
	auto encrypted = client.PlatformEncrypt(key, blob);
	SPOK_Blob::Copy2CStylePtr(encrypted, pData, cbData, sizeOut);

}
void SPC_PlatformSign(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pHash, const size_t cbhash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto hash = SPOK_Blob::New(pHash, cbhash);
	SPOKClient client;
	auto signature = client.PlatformSign(key, hash);
	SPOK_Blob::Copy2CStylePtr(signature, pSignature, cbSignature, sizeOut);

}
bool SPC_PlatformVerifySignature(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pHash, const size_t cbhash, const uint8_t* pSignature, const size_t cbSignature)
{
	auto key = SPOK_PlatformKey{ name, flag };
	auto hash = SPOK_Blob::New(pHash, cbhash);
	auto signature = SPOK_Blob::New(pSignature, cbSignature);
	SPOKClient client;
	return client.PlatformVerifySignature(key, hash, signature);
}