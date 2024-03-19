#include "SPOK_AIKPlatformAttestation.h"
#include <HasherUtil.h>
#include <SPOKPcrs.h>
#include <TcgLog.h>


SPOK_AIKPlatformAttestation::SPOK_AIKPlatformAttestation(SPOK_Blob::Blob attQuote)
{
	auto attQuoteReader = SPOK_BinaryReader(attQuote);
	m_AttBlobHeader.Magic = attQuoteReader.LE_Read32();

	if (m_AttBlobHeader.Magic != SPOK_PLATFORM_ATT_MAGIC)
	{
		throw std::invalid_argument("Invalid Magic");
	}

	m_AttBlobHeader.TpmVersion = attQuoteReader.LE_Read32();
	if (m_AttBlobHeader.TpmVersion != TPM_VERSION_20)
	{
		throw std::invalid_argument("Invalid TPM Version");
	}

	m_AttBlobHeader.HeaderSize = attQuoteReader.LE_Read32();
	if (m_AttBlobHeader.HeaderSize != sizeof(SPOK_PLATFORM_ATT_BLOB))
	{
		throw std::invalid_argument("Invalid Header Size");
	}

	//we can be reasonably sure that the attQuote is valid at this point
	m_AttBlobHeader.PcrValuesSize = attQuoteReader.LE_Read32();
	m_AttBlobHeader.QuoteSize = attQuoteReader.LE_Read32();
	m_AttBlobHeader.SignatureSize = attQuoteReader.LE_Read32();
	m_AttBlobHeader.TsbSize = attQuoteReader.LE_Read32();

	//read the rest of the attQuote
	m_pcrs = SPOK_Blob::Blob(attQuoteReader.Read(m_AttBlobHeader.PcrValuesSize));
	m_Quote = TPM2B_ATTEST_QUOTE::Decode(attQuoteReader.Read(m_AttBlobHeader.QuoteSize));
	m_Signature = SPOK_Blob::Blob(attQuoteReader.Read(m_AttBlobHeader.SignatureSize));
	m_tsbLog = SPOK_Blob::Blob(attQuoteReader.Read(m_AttBlobHeader.TsbSize));
}
SPOK_AIKPlatformAttestation::~SPOK_AIKPlatformAttestation()
{

}

SPOK_Blob::Blob SPOK_AIKPlatformAttestation::GetQuoteDigest() const
{
	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA1);
	return hasher.OneShotHash(m_Quote.Raw);
}
SPOK_Blob::Blob SPOK_AIKPlatformAttestation::GetTrustedPcrs() const
{
	auto table = SPOK_Pcrs(m_pcrs);
	if (m_Quote.PcrSelection.size() != 1)
	{
		throw std::invalid_argument("Invalid PcrSelection");
	}

	auto mask = m_Quote.PcrSelection[0].GetMask();
	auto trustedPcrs = table.GetFiltered(mask);
	return trustedPcrs;
}
SPOK_Blob::Blob SPOK_AIKPlatformAttestation::GetTrustedTsbLog() const
{
	auto log = TcgLog::Parse(m_tsbLog);
	if (m_Quote.PcrSelection.size() != 1)
	{
		throw std::invalid_argument("Invalid PcrSelection");
	}

	auto mask = m_Quote.PcrSelection[0].GetMask();
	auto trustedLog = TcgLog::Filter(log, mask);
	return TcgLog::Serialize(trustedLog);
}

bool SPOK_AIKPlatformAttestation::VerifyNonce(const SPOK_Nonce::Nonce& nonce) const
{

}
bool SPOK_AIKPlatformAttestation::VerifySignature(SPOK_Blob::Blob aikPubBlob) const
{

}
bool SPOK_AIKPlatformAttestation::VerifyPcrs() const
{

}
bool SPOK_AIKPlatformAttestation::Verify(const SPOK_Nonce::Nonce& nonce, SPOK_Blob::Blob aikPubBlob) const
{
	auto nonceVerify = VerifyNonce(nonce);
	auto sigVerify = VerifySignature(aikPubBlob);
	auto pcrsVerify = VerifyPcrs();
	return nonceVerify && sigVerify && pcrsVerify;
}



