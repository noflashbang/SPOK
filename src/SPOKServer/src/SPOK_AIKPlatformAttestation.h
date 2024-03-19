#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "SPOKBlob.h"
#include "SPOKNonce.h"
#include "TPM_20.h"

class SPOK_AIKPlatformAttestation
{
	SPOK_AIKPlatformAttestation(SPOK_Blob::Blob attQuote);
	~SPOK_AIKPlatformAttestation();

	SPOK_Blob::Blob GetQuoteDigest() const;
	SPOK_Blob::Blob GetTrustedPcrs() const;
	SPOK_Blob::Blob GetTrustedTsbLog() const;

	bool VerifyNonce(const SPOK_Nonce::Nonce& nonce) const;
	bool VerifySignature(SPOK_Blob::Blob aikPubBlob) const;
	bool VerifyPcrs() const;

	bool Verify(const SPOK_Nonce::Nonce& nonce, SPOK_Blob::Blob aikPubBlob) const;

private:
	SPOK_PLATFORM_ATT_BLOB m_AttBlobHeader;
	TPM2B_ATTEST_QUOTE m_Quote;
	SPOK_Blob::Blob m_pcrs;
	SPOK_Blob::Blob m_Signature;
	SPOK_Blob::Blob m_tsbLog;
};

