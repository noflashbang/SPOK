#pragma once

#include "SPOKCore.h"
#include "NCryptUtil.h"

#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

class SPOKClient
{
public:
	SPOKClient();
	~SPOKClient();

	void AIKCreate(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce);
	void AIKDelete(const SPOK_PlatformKey& aik);
	bool AIKExists(const SPOK_PlatformKey& aik);

	void AIKGetKeyAttestation();
	void AIKGetPlatformAttestation();

	SPOK_Blob::Blob AIKGetPublicKey(const SPOK_PlatformKey& aik);
	SPOK_Blob::Blob GetEndorsementPublicKey();
	SPOK_Blob::Blob AIKGetChallengeBinding(const SPOK_PlatformKey& aik);
	SPOK_Blob::Blob AIKActivateChallenge(const SPOK_PlatformKey& aik, const SPOK_Blob::Blob& challenge);
	SPOK_Blob::Blob GetBootLog();
	SPOK_Blob::Blob GetPCRTable();
	SPOK_Blob::Blob GetStorageRootKey();
	void PlatformImportKey(const SPOK_PlatformKey& aik, const SPOK_Blob::Blob& key, KeyBlobType type);
	SPOK_Blob::Blob PlatformDecrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob PlatformEncrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob PlatformSign(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	bool PlatformVerifySignature(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);
};