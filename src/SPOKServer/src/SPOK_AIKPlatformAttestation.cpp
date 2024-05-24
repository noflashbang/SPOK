#include "SPOK_AIKPlatformAttestation.h"
#include "SPOKError.h"
#include <HasherUtil.h>
#include <SPOKPcrs.h>
#include <TcgLog.h>

SPOK_AIKPlatformAttestation::SPOK_AIKPlatformAttestation(SPOK_Blob::Blob attQuote)
{
	auto attQuoteReader = SPOK_BinaryReader(attQuote);
	m_AttBlobHeader.Magic = attQuoteReader.LE_Read32();

	if (m_AttBlobHeader.Magic != SPOK_PLATFORM_ATT_MAGIC)
	{
		auto fmtError = std::format("Invalid Magic: {}", m_AttBlobHeader.Magic);
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	m_AttBlobHeader.TpmVersion = attQuoteReader.LE_Read32();
	if (m_AttBlobHeader.TpmVersion != SPOK_TPM_VERSION_20)
	{
		auto fmtError = std::format("Invalid TPM Version: {}", m_AttBlobHeader.TpmVersion);
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	m_AttBlobHeader.HeaderSize = attQuoteReader.LE_Read32();
	if (m_AttBlobHeader.HeaderSize != sizeof(SPOK_PLATFORM_ATT_BLOB))
	{
		auto fmtError = std::format("Invalid Header Size: {}", m_AttBlobHeader.HeaderSize);
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
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
		auto fmtError = std::format("Invalid PcrSelection: {}", m_Quote.PcrSelection.size());
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	auto mask = m_Quote.PcrSelection[0].GetMask();
	auto trustedPcrs = table.GetFiltered(mask);
	return trustedPcrs.GetBlob();
}
SPOK_Blob::Blob SPOK_AIKPlatformAttestation::GetTrustedTsbLog() const
{
	auto log = TcgLog::Parse(m_tsbLog);
	if (m_Quote.PcrSelection.size() != 1)
	{
		auto fmtError = std::format("Invalid PcrSelection: {}", m_Quote.PcrSelection.size());
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	auto mask = m_Quote.PcrSelection[0].GetMask();
	auto trustedLog = TcgLog::Filter(log, mask);
	return TcgLog::Serialize(trustedLog);
}

bool SPOK_AIKPlatformAttestation::VerifyNonce(const SPOK_Nonce::Nonce& nonce) const
{
	auto quoteNonce = m_Quote.CreationNonce;
	return SPOK_Nonce::Equal(quoteNonce, nonce);
}
bool SPOK_AIKPlatformAttestation::VerifySignature(SPOK_Blob::Blob aikPubBlob) const
{
	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA1);
	auto digest = hasher.OneShotHash(m_Quote.Raw);

	auto key = BCryptUtil::Open(aikPubBlob);
	key.SetSignHashAlg(TPM_API_ALG_ID_SHA1); //set the correct hash algorithm for padding

	auto verified = key.Verify(digest, m_Signature);
	return verified;
}
bool SPOK_AIKPlatformAttestation::VerifyPcrs() const
{
	auto trustedPcrs = SPOK_Pcrs(GetTrustedPcrs());
	auto hashSize = trustedPcrs.GetDigestSize();
	auto pcrMask = trustedPcrs.GetMask();
	auto pcrBuffer = SPOK_Blob::Blob();

	bool equal = true;
	for (int i = 0; i < TPM_PCRS_CNT; i++)
	{
		if (!(pcrMask & (1 << i)))
		{
			continue;
		}
		auto pcr = trustedPcrs.GetPcr(i);
		std::copy(pcr.begin(), pcr.end(), std::back_inserter(pcrBuffer));
	}

	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA1);
	auto pcrsDigest = hasher.OneShotHash(pcrBuffer);

	if (pcrsDigest.size() != m_Quote.PcrDigest.size())
	{
		return false;
	}

	//compare the pcrs digest to the quote digest
	for (size_t i = 0; i < pcrsDigest.size(); i++)
	{
		equal &= (pcrsDigest[i] == m_Quote.PcrDigest[i]);
	}

	//exit early if the pcrs don't match, no need to compute the log
	if (!equal)
	{
		return false;
	}

	//check that the tcg log pcrs match the quoted pcrs
	auto log = TcgLog::Parse(m_tsbLog);

	//check that the log is valid
	auto validLog = TcgLog::VerifyLogIntegrity(log);
	if (!validLog)
	{
		return false;
	}

	//compute the pcrs from the log - this is trustable as we just verified the log
	auto logPcrs = SPOK_Pcrs(TcgLog::ComputeSoftPCRTable(log, trustedPcrs.GetAlgId() == TPM_API_ALG_ID_SHA1 ? TPM_ALG_ID::TPM_ALG_SHA1 : TPM_ALG_ID::TPM_ALG_SHA256));

	if (trustedPcrs.GetDigestSize() != logPcrs.GetDigestSize())
	{
		return false;
	}

	//compare the pcrs from the log to the trusted pcrs
	for (int i = 0; i < TPM_PCRS_CNT; i++)
	{
		auto pcr = trustedPcrs.GetPcr(i);
		auto trustedPcr = logPcrs.GetPcr(i);

		//check the pcrs match to hash size, check them all and do it in constant time
		//to avoid timing attacks
		for (size_t ii = 0; ii < hashSize; ii++)
		{
			equal &= (pcr[ii] == trustedPcr[ii]);
		}
	}

	//if this is true then the quoted pcrs and the related events in the log are valid and trustworthy
	return equal;
}
SPOK_VerifyResult SPOK_AIKPlatformAttestation::Verify(const SPOK_AIKPlatformVerify& verify) const
{
	auto nonceVerify = VerifyNonce(verify.Nonce);
	auto sigVerify = VerifySignature(verify.AIKBlob);
	auto pcrsVerify = VerifyPcrs();
	return SPOK_AIKPlatformVerifyResult{ nonceVerify, sigVerify, pcrsVerify };
}