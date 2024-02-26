#include "SPOKServerApi.h"
#include "SPOKServer.h"
#include "SPOKCore.h"

//Basic Crypto Operations
void SPS_Decrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto data = SPOK_Blob::New(pBytes, cbBytes);
	auto server = SPOKServer();
	auto decrypted = server.Decrypt(blob, data);
	SPOK_Blob::Copy2CStylePtr(decrypted, pData, cbData, sizeOut);
}
void SPS_Encrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pData, const size_t cbData, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto data = SPOK_Blob::New(pData, cbData);
	auto server = SPOKServer();
	auto encrypted = server.Encrypt(blob, data);
	SPOK_Blob::Copy2CStylePtr(encrypted, pBytes, cbBytes, sizeOut);
}
void SPS_Sign(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto hash = SPOK_Blob::New(pHash, cbHash);
	auto server = SPOKServer();
	auto signature = server.Sign(blob, hash);
	SPOK_Blob::Copy2CStylePtr(signature, pSignature, cbSignature, sizeOut);
}
bool SPS_VerifySignature(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto hash = SPOK_Blob::New(pHash, cbHash);
	auto signature = SPOK_Blob::New(pSignature, cbSignature);
	auto server = SPOKServer();
	return server.VerifySignature(blob, hash, signature);
}

//Key Helpers
void SPS_GenerateRSAKeyPair(const uint16_t keySizeBits, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto server = SPOKServer();
	auto keySize = static_cast<KeySize>(keySizeBits);
	auto keyPair = server.GenerateRSAKeyPair(keySize);
	SPOK_Blob::Copy2CStylePtr(keyPair, pData, cbData, sizeOut);
}
