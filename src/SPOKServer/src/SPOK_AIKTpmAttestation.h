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
	SPOK_Blob::Blob GetCreationDigest(uint16_t algId) const;
	SPOK_Blob::Blob GetAttestationDigest(uint16_t algId) const;

	bool VerifyNonce(const SPOK_Nonce::Nonce& nonce) const;
	bool VerifySignature(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature) const;

private:
	SPOK_Blob::Blob m_idBinding;
};

