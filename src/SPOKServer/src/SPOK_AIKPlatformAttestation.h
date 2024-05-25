#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "AttestationVariants.h"
#include "SPOKBlob.h"
#include "SPOKNonce.h"
#include "TPM_20.h"

class SPOK_AIKPlatformAttestation
{
public:
	SPOK_AIKPlatformAttestation(SPOK_Blob attQuote);
	~SPOK_AIKPlatformAttestation();

	SPOK_Blob GetQuoteDigest() const;
	SPOK_Blob GetTrustedPcrs() const;
	SPOK_Blob GetTrustedTsbLog() const;

	bool VerifyNonce(const SPOK_Nonce::Nonce& nonce) const;
	bool VerifySignature(SPOK_Blob aikPubBlob) const;
	bool VerifyPcrs() const;

	SPOK_VerifyResult Verify(const SPOK_AIKPlatformVerify& verify) const;

private:
	SPOK_PLATFORM_ATT_BLOB m_AttBlobHeader;
	TPM2B_ATTEST_QUOTE m_Quote;
	SPOK_Blob m_pcrs;
	SPOK_Blob m_Signature;
	SPOK_Blob m_tsbLog;
};
