#include "SPOKClient.h"
#include "StandardLib.h"
#include "TPM_20.h"

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
	return NCryptUtil::DoesPlatformKeyExists(aik);
}

SPOK_Blob::Blob SPOKClient::AIKGetKeyAttestation(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest)
{
	return TPM_20::CertifyKey(aik, nonce, keyToAttest);
}

SPOK_Blob::Blob SPOKClient::AIKGetPlatformAttestation(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude)
{
	return TPM_20::AttestPlatform(aik, nonce, pcrsToInclude);
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
	return NCryptUtil::GetTbsLog();
}

SPOK_Blob::Blob SPOKClient::GetBootLog(const uint32_t pcrsToInclude)
{
	return NCryptUtil::GetFilteredTbsLog(pcrsToInclude);
}

SPOK_Blob::Blob SPOKClient::GetPCRTable()
{
	return NCryptUtil::GetPcrTable();
}

SPOK_Blob::Blob SPOKClient::GetStorageRootKey()
{
	return NCryptUtil::GetTpmSrk();
}

void SPOKClient::PlatformImportKey(const SPOK_PlatformKey& platformKey, const SPOK_Blob::Blob& key, KeyBlobType type)
{
	NCryptUtil::ImportPlatformKey(platformKey, key, type);
}

void SPOKClient::PlatformCreateKey(const SPOK_PlatformKey& platformKey)
{
	NCryptUtil::CreatePlatformKey(platformKey);
}

bool SPOKClient::PlatformKeyExists(const SPOK_PlatformKey& platformKey)
{
	return NCryptUtil::DoesPlatformKeyExists(platformKey);
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