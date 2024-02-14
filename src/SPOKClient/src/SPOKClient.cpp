#include "SPOKClient.h"


SPOKClient::SPOKClient()
{
}

SPOKClient::~SPOKClient()
{
}

void SPOKClient::AIKCreate(const SPOK_PlatformKey& aik, SPOK_Nonce nonce)
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

SPOK_Blob SPOKClient::AIKGetPublicKey(const SPOK_PlatformKey& aik)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.GetPublicKey();
}

SPOK_Blob SPOKClient::AIKGetChallengeBinding(const SPOK_PlatformKey& aik)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.GetIdBinding();
}