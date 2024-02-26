#pragma once

#include "SPOKCore.h"
#include "BCryptUtil.h"
#include "NCryptUtil.h"

#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

class SPOKServer
{
public:
	SPOKServer();
	~SPOKServer();


	//AIK Platform Attestation
	void AIKAttestationDecode();
	void AIKAttestationGetPCR();
	void AIKAttestationGetTcgLog();
	void AIKAttestationVerify();

	//AIK Attestation
	void AIKDecodeBinding();
	void AIKFreeBinding();
	void AIKGetChallenge();

	//AIK Key Attestation
	void AIKKeyAttestationDecode();
	void AIKKeyAttestationVerify();
	void AIKRawVerifyNonce();
	void AIKRawVerifySignature();

	//Basic Crypto Operations
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	bool VerifySignature(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

	//Key Helpers
	SPOK_Blob::Blob GenerateRSAKeyPair(KeySize keySize);
	void SPS_WrapKeyForPlatformImport();
};