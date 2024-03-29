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
	SPOK_AIKPlatformAttestation AIKAttestationDecode(const SPOK_Blob::Blob& attQuote);
	SPOK_Pcrs AIKAttestationGetPCR(IAttestation& attestation);
	SPOK_Blob::Blob AIKAttestationGetTcgLog(IAttestation& attestation);

	//AIK TPM Attestation
	SPOK_AIKTpmAttestation AIKTpmAttestationDecode(const SPOK_Blob::Blob& idBinding);
	SPOK_Blob::Blob AIKGetTpmAttestationChallenge(const uint16_t ekNameAlgId, const SPOK_Blob::Blob& ekPub, const SPOK_Blob::Blob& aikName, const SPOK_Blob::Blob& secret);

	//AIK Key Attestation
	void AIKKeyAttestationDecode();
	void AIKKeyAttestationVerify();

	SPOK_VerifyResult AttestationVerify(IAttestation& attestation, const SPOK_AttestationVerify& verify);

	//Basic Crypto Operations
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data);
	bool VerifySignature(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

	//Key Helpers
	SPOK_Blob::Blob GenerateRSAKeyPair(KeySize keySize);
	void SPS_WrapKeyForPlatformImport();
};