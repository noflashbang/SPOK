#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "SPOKBlob.h"
#include "SPOKNonce.h"
#include "TPM_20.h"

class SPOK_AIKTpmAttestation
{
public:
	SPOK_AIKTpmAttestation(SPOK_Blob::Blob idBinding);
	~SPOK_AIKTpmAttestation();

	TPM2B_IDBINDING GetData() const;

	SPOK_Blob::Blob GetPublicRSABlob() const;
	SPOK_Blob::Blob GetPublicName() const;
	SPOK_Blob::Blob GetCreationDigest() const;

	bool VerifyName() const;
	bool VerifyCreation() const;
	bool VerifyNonce(const SPOK_Nonce::Nonce& nonce) const;
	bool VerifySignature() const;

	bool Verify(const SPOK_Nonce::Nonce& nonce) const;
	
private:
	TPM2B_IDBINDING m_idBinding;
};

