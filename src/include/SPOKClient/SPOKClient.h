#pragma once

#include "standardlib.h"
#include "SPOKCore.h"
#include "NCryptUtil.h"


class SPOKClient
{
public:
	SPOKClient();
	~SPOKClient();

	void AIKCreate(std::wstring name, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce);
	void AIKDelete(std::wstring name, NCRYPT_MACHINE_KEY flag);
	bool AIKExists(std::wstring name, NCRYPT_MACHINE_KEY flag);

	void AIKGetKeyAttestation();
	void AIKGetPlatformAttestation();
	void AIKGetPublicKey();
	void GetEndorsementPublicKey();
	void AIKGetChallengeBinding();
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