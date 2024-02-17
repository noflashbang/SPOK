#include "SPOKClient.h"
#include "StandardLib.h"

SPOKClient::SPOKClient()
{
}

SPOKClient::~SPOKClient()
{
}

void SPOKClient::AIKCreate(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce)
{
	NCryptUtil::CreateAik(aik, nonce);
}

void SPOKClient::AIKDelete(const SPOK_PlatformKey& aik)
{
	NCryptUtil::DeleteKey(aik);
}

bool SPOKClient::AIKExists(const SPOK_PlatformKey& aik)
{
	return NCryptUtil::DoesAikExists(aik);
}

SPOK_Blob::Blob SPOKClient::AIKGetPublicKey(const SPOK_PlatformKey& aik)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.GetPublicKey();
}

SPOK_Blob::Blob SPOKClient::GetEndorsementPublicKey()
{
	return NCryptUtil::GetTpmPublicEndorsementKey();
}

SPOK_Blob::Blob SPOKClient::AIKGetChallengeBinding(const SPOK_PlatformKey& aik)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.GetIdBinding();
}

SPOK_Blob::Blob SPOKClient::AIKActivateChallenge(const SPOK_PlatformKey& aik, const SPOK_Blob::Blob& challenge)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.ActiveChallenge(challenge);
}

SPOK_Blob::Blob SPOKClient::GetBootLog()
{
	return NCryptUtil::GetBootLog();
}

SPOK_Blob::Blob SPOKClient::GetPCRTable()
{
	return NCryptUtil::GetPcrTable();
}

SPOK_Blob::Blob SPOKClient::GetStorageRootKey()
{
	return NCryptUtil::GetTpmSrk();
}

void SPOKClient::PlatformImportKey(const SPOK_PlatformKey& aik, const SPOK_Blob::Blob& key, KeyBlobType type)
{
	NCryptUtil::ImportPlatformKey(aik, key, type);
}

SPOK_Blob::Blob SPOKClient::PlatformDecrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data)
{
	return NCryptUtil::Decrypt(key, data);
}

SPOK_Blob::Blob SPOKClient::PlatformEncrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data)
{
	return NCryptUtil::Encrypt(key, data);
}

SPOK_Blob::Blob SPOKClient::PlatformSign(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data)
{
	return NCryptUtil::Sign(key, data);
}

bool SPOKClient::PlatformVerifySignature(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature)
{
	return NCryptUtil::Verify(key, data, signature);
}