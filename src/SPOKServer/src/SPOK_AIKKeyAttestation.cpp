#include "SPOK_AIKKeyAttestation.h"
#include <HasherUtil.h>


SPOK_AIKKeyAttestation::SPOK_AIKKeyAttestation(SPOK_Blob::Blob attCertify)
{
	auto certifyReader = SPOK_BinaryReader(attCertify);
	m_KeyBlobHeader.Magic = certifyReader.LE_Read32();

	if (m_KeyBlobHeader.Magic != SPOK_KEY_ATT_MAGIC)
	{
		throw std::invalid_argument("Invalid Magic");
	}

	m_KeyBlobHeader.TpmVersion = certifyReader.LE_Read32();
	if (m_KeyBlobHeader.TpmVersion != SPOK_TPM_VERSION_20)
	{
		throw std::invalid_argument("Invalid TPM Version");
	}

	m_KeyBlobHeader.HeaderSize = certifyReader.LE_Read32();
	if (m_KeyBlobHeader.HeaderSize != sizeof(SPOK_KEY_ATT_BLOB))
	{
		throw std::invalid_argument("Invalid Header Size");
	}

	//we can be reasonably sure that the attQuote is valid at this point
	m_KeyBlobHeader.KeyAttestSize = certifyReader.LE_Read32();
	m_KeyBlobHeader.SignatureSize = certifyReader.LE_Read32();

	//read the rest of the attQuote
	m_KeyCertify = TPM2B_ATTEST_CERTIFY::Decode(certifyReader.Read(m_KeyBlobHeader.KeyAttestSize));
	m_Signature = SPOK_Blob::Blob(certifyReader.Read(m_KeyBlobHeader.SignatureSize));
}

SPOK_AIKKeyAttestation::~SPOK_AIKKeyAttestation()
{

}

SPOK_Blob::Blob SPOK_AIKKeyAttestation::GetCertifyDigest() const
{
	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA1);
	return hasher.OneShotHash(m_KeyCertify.Raw);
}

bool SPOK_AIKKeyAttestation::VerifyNonce(const SPOK_Nonce::Nonce& nonce) const
{
	auto quoteNonce = m_KeyCertify.CreationNonce;
	return SPOK_Nonce::Equal(quoteNonce, nonce);
}

bool SPOK_AIKKeyAttestation::VerifyName(const SPOK_Blob::Blob& name) const
{
	auto keyName = m_KeyCertify.Name;
	return (keyName == name);
}

bool SPOK_AIKKeyAttestation::VerifySignature(SPOK_Blob::Blob aikPubBlob) const
{
	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA1);
	auto digest = hasher.OneShotHash(m_KeyCertify.Raw);

	auto key = BCryptUtil::Open(aikPubBlob);
	key.SetSignHashAlg(TPM_API_ALG_ID_SHA1); //set the correct hash algorithm for padding

	auto verified = key.Verify(digest, m_Signature);
	return verified;
}

SPOK_VerifyResult SPOK_AIKKeyAttestation::Verify(const SPOK_AIKKeyVerify& verify) const
{
	auto nonceVerify = VerifyNonce(verify.Nonce);
	auto nameVerify = VerifyName(verify.Name);
	auto sigVerify = VerifySignature(verify.AikBlob);
	return SPOK_AIKKeyVerifyResult{ nonceVerify, nameVerify, sigVerify };
}


