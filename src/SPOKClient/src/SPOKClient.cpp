#include "SPOKClient.h"


SPOKClient::SPOKClient()
{
}

SPOKClient::~SPOKClient()
{
}

void SPOKClient::AIKCreate(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce nonce)
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

SPOK_Blob::Blob SPOKClient::AIKGetChallengeBinding(const SPOK_PlatformKey& aik)
{
	auto aiKey = PlatformAik(aik);
	return aiKey.GetIdBinding();
}

SPOK_Pcrs SPOKClient::GetPCRTable()
{
	auto pcrs = NCryptUtil::GetPcrTable();
	return SPOK_Pcrs(pcrs);
}