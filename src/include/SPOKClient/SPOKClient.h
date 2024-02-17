#pragma once

#include "standardlib.h"
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

	void AIKCreate(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce nonce);
	void AIKDelete(const SPOK_PlatformKey& aik);
	bool AIKExists(const SPOK_PlatformKey& aik);

	void AIKGetKeyAttestation();
	void AIKGetPlatformAttestation();
	SPOK_Blob::Blob AIKGetPublicKey(const SPOK_PlatformKey& aik);
	void GetEndorsementPublicKey();
	SPOK_Blob::Blob AIKGetChallengeBinding(const SPOK_PlatformKey& aik);
	void AIKActivateChallenge();
	void GetBootLog();
	SPOK_Pcrs GetPCRTable();
	void GetStorageRootKey();

	void PlatformImportKey();
	
	void PlatformDecrypt();
	void PlatformEncrypt();
	void PlatformSign();
	void PlatformVerifySignature();
};