#include "SPOK_AIKTpmAttestation.h"
#include "TPM_20.h"
#include "HasherUtil.h"
#include "BCryptUtil.h"
#include "Util.h"

SPOK_AIKTpmAttestation::SPOK_AIKTpmAttestation(SPOK_Blob::Blob idBinding)
{
	m_idBinding = TPM_20::DecodeIDBinding(idBinding);
}

SPOK_AIKTpmAttestation::~SPOK_AIKTpmAttestation()
{
}

TPM2B_IDBINDING SPOK_AIKTpmAttestation::GetData() const
{
	return m_idBinding;
}

SPOK_Blob::Blob SPOK_AIKTpmAttestation::GetPublicRSABlob() const
{
	auto rsaBlob = SPOK_Blob::New(24 + m_idBinding.Public.Exponent.size() + m_idBinding.Public.Modulus.size());
	auto bw = SPOK_BinaryWriter(rsaBlob);

	bw.LE_Write32(BCRYPT_RSAPUBLIC_MAGIC); //magic
	bw.LE_Write32(m_idBinding.Public.KeyBits); //bitlen
	bw.LE_Write32(SAFE_CAST_TO_UINT32(m_idBinding.Public.Exponent.size())); //exponent size
	bw.LE_Write32(SAFE_CAST_TO_UINT32(m_idBinding.Public.Modulus.size())); //modulus size
	bw.LE_Write32(0); //Prime1 size
	bw.LE_Write32(0); //Prime2 size

	bw.Write(m_idBinding.Public.Exponent);
	bw.Write(m_idBinding.Public.Modulus);

	return rsaBlob;
}

SPOK_Blob::Blob SPOK_AIKTpmAttestation::GetPublicName() const
{
	auto hasher = Hasher::Create(m_idBinding.Public.NameAlg);
	auto nameHash = hasher.OneShotHash(m_idBinding.Public.Raw);

	auto nameBlob = SPOK_Blob::New(2 + nameHash.size());
	auto bw = SPOK_BinaryWriter(nameBlob);

	bw.BE_Write16(m_idBinding.Public.NameAlg);
	bw.Write(nameHash);

	return nameBlob;
}

SPOK_Blob::Blob SPOK_AIKTpmAttestation::GetCreationDigest() const
{
	auto hasher = Hasher::Create(m_idBinding.Public.NameAlg);
	return hasher.OneShotHash(m_idBinding.CreationData.Raw);
}

bool SPOK_AIKTpmAttestation::VerifyCreation() const
{
	auto creationDigest = GetCreationDigest();
	return std::equal(creationDigest.begin(), creationDigest.end(), m_idBinding.Attest.CreationHash.begin());
}

bool SPOK_AIKTpmAttestation::VerifyName() const
{
	auto name = GetPublicName();
	return std::equal(name.begin(), name.end(), m_idBinding.Attest.ObjectName.begin());
}

bool SPOK_AIKTpmAttestation::VerifyNonce(const SPOK_Nonce::Nonce& nonce) const
{
	auto creation = SPOK_Nonce::Equal(nonce, m_idBinding.CreationData.CreationNonce);
	auto attestation = SPOK_Nonce::Equal(nonce, m_idBinding.Attest.CreationNonce);
	return creation && attestation;
}
bool SPOK_AIKTpmAttestation::VerifySignature() const
{
	auto hasher = Hasher::Create(m_idBinding.Public.SignHash);
	auto digest = hasher.OneShotHash(m_idBinding.Attest.Raw);
	auto rsaBlob = GetPublicRSABlob();

	auto key = BCryptUtil::Open(rsaBlob);
	key.SetSignHashAlg(m_idBinding.Public.SignHash); //set the correct hash algorithm for padding

	auto verified = key.Verify(digest, m_idBinding.Signature.Signature);
	return verified;
}

SPOK_VerifyResult SPOK_AIKTpmAttestation::Verify(const SPOK_AIKTpmVerify& verify) const
{
	auto creation = VerifyCreation();
	auto name = VerifyName();
	auto nonceCheck = VerifyNonce(verify.Nonce);
	auto signature = VerifySignature();
	return SPOK_TpmVerifyResult{ creation, name, nonceCheck, signature };
}