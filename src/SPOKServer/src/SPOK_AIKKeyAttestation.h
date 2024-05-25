#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include <SPOKBlob.h>
#include <TPM_20.h>
#include <AttestationVariants.h>

class SPOK_AIKKeyAttestation
{
public:
	SPOK_AIKKeyAttestation(SPOK_Blob attQuote);
	~SPOK_AIKKeyAttestation();

	SPOK_Blob GetCertifyDigest() const;

	bool VerifyNonce(const SPOK_Nonce::Nonce& nonce) const;
	bool VerifyName(const SPOK_Blob& name) const;
	bool VerifySignature(SPOK_Blob aikPubBlob) const;

	SPOK_VerifyResult Verify(const SPOK_AIKKeyVerify& verify) const;

private:
	SPOK_KEY_ATT_BLOB m_KeyBlobHeader;
	TPM2B_ATTEST_CERTIFY m_KeyCertify;
	SPOK_Blob m_Signature;
};
