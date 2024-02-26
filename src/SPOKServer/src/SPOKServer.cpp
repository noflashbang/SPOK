#include "SPOKServer.h"

SPOKServer::SPOKServer()
{
}

SPOKServer::~SPOKServer()
{
}

//Basic Crypto Operations
SPOK_Blob::Blob SPOKServer::Decrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Decrypt(data);
}

SPOK_Blob::Blob SPOKServer::Encrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Encrypt(data);
}
SPOK_Blob::Blob SPOKServer::Sign(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Sign(data);
}
bool SPOKServer::VerifySignature(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature)
{
	BCryptKey keyHandle(key);
	return keyHandle.Verify(data, signature);
}

//Key Helpers
SPOK_Blob::Blob SPOKServer::GenerateRSAKeyPair(KeySize keySize)
{
	return BCryptUtil::GenerateRsaKeyPair(keySize);
}
