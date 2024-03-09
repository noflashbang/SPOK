#pragma once

#include "SPOKCore.h"
#include "BCryptUtil.h"
#include "NCryptUtil.h"

#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

#include "IAttestation.h"

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

	//AIK TPM Attestation
	SPOK_AIKTpmAttestation AIKTpmAttestationDecode(const SPOK_Blob::Blob& idBinding);
	void AIKGetTpmAttestationChallenge();

	//AIK Key Attestation
	void AIKKeyAttestationDecode();
	void AIKKeyAttestationVerify();

	bool AttestationVerify(IAttestation& attestation, const SPOK_Nonce::Nonce& nonce);
	bool AttestationVerifyNonce(IAttestation& attestation, const SPOK_Nonce::Nonce& nonce);
	bool AttestationVerifySignature(IAttestation& attestation);

	//Basic Crypto Operations
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	bool VerifySignature(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

	//Key Helpers
	SPOK_Blob::Blob GenerateRSAKeyPair(KeySize keySize);
	void SPS_WrapKeyForPlatformImport();
};