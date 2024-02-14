#pragma once

#include "standardlib.h"
#include "SPOKCore.h"
#include "NCryptUtil.h"


class SPOKClient
{
public:
	SPOKClient();
	~SPOKClient();

	void AIKCreate(const SPOK_PlatformKey& aik, SPOK_Nonce nonce);
	void AIKDelete(const SPOK_PlatformKey& aik);
	bool AIKExists(const SPOK_PlatformKey& aik);

	void AIKGetKeyAttestation();
	void AIKGetPlatformAttestation();
	SPOK_Blob AIKGetPublicKey(const SPOK_PlatformKey& aik);
	void GetEndorsementPublicKey();
	SPOK_Blob AIKGetChallengeBinding(const SPOK_PlatformKey& aik);
	void AIKActivateChallenge();
	void GetBootLog();
	void GetPCRTable();
	void GetStorageRootKey();

	void PlatformImportKey();
	
	void PlatformDecrypt();
	void PlatformEncrypt();
	void PlatformSign();
	void PlatformVerifySignature();
};