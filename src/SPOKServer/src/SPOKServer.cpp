#include "SPOKServer.h"
#include "SPOKError.h"
#include "TPM_20.h"

SPOKServer::SPOKServer()
{
}

SPOKServer::~SPOKServer()
{
}

SPOK_AIKPlatformAttestation SPOKServer::AIKAttestationDecode(const SPOK_Blob::Blob& attQuote)
{
	return SPOK_AIKPlatformAttestation(attQuote);
}
SPOK_Pcrs SPOKServer::AIKAttestationGetPCR(IAttestation& attestation)
{
	if (!std::holds_alternative<SPOK_AIKPlatformAttestation>(attestation))
	{
		auto fmtError = std::format("Attestation is not an AIK Platform Attestation");
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	auto aikPlatformAttestation = std::get<SPOK_AIKPlatformAttestation>(attestation);
	return aikPlatformAttestation.GetTrustedPcrs();
}
SPOK_Blob::Blob SPOKServer::AIKAttestationGetTcgLog(IAttestation& attestation)
{
	if (!std::holds_alternative<SPOK_AIKPlatformAttestation>(attestation))
	{
		auto fmtError = std::format("Attestation is not an AIK Platform Attestation");
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	auto aikPlatformAttestation = std::get<SPOK_AIKPlatformAttestation>(attestation);
	return aikPlatformAttestation.GetTrustedTsbLog();
}

SPOK_AIKTpmAttestation SPOKServer::AIKTpmAttestationDecode(const SPOK_Blob::Blob& idBinding)
{
	return SPOK_AIKTpmAttestation(idBinding);
}

SPOK_Blob::Blob SPOKServer::AIKGetTpmAttestationChallenge(const uint16_t ekNameAlgId, const SPOK_Blob::Blob& ekPub, const SPOK_Blob::Blob& aikName, const SPOK_Blob::Blob& secret)
{
	auto challenge = TPM_20::GenerateChallengeCredential(ekNameAlgId, ekPub, aikName, secret);
	return challenge;
};

SPOK_AIKKeyAttestation SPOKServer::AIKKeyAttestationDecode(const SPOK_Blob::Blob& attKey)
{
	return SPOK_AIKKeyAttestation(attKey);
}

SPOK_VerifyResult SPOKServer::AttestationVerify(IAttestation& attestation, const SPOK_AttestationVerify& verify)
{
	// Use the visitor on a variant
	return std::visit(IAttestationVerifyVisitor(verify), attestation);
}

//Basic Crypto Operations
SPOK_Blob::Blob SPOKServer::Decrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Decrypt(data);
}

SPOK_Blob::Blob SPOKServer::Encrypt(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Encrypt(data, false);
}
SPOK_Blob::Blob SPOKServer::Sign(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data)
{
	BCryptKey keyHandle(key);
	return keyHandle.Sign(data);
}
bool SPOKServer::VerifySignature(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature)
{
	BCryptKey keyHandle(key);
	return keyHandle.Verify(data, signature);
}

//Key Helpers
SPOK_Blob::Blob SPOKServer::GenerateRSAKeyPair(KeySize keySize)
{
	return BCryptUtil::GenerateRsaKeyPair(keySize);
}

SPOK_Blob::Blob SPOKServer::WrapKeyForPlatformImport(const SPOK_Blob::Blob& keyToWrap, const SPOK_Blob::Blob& srk, const SPOK_Pcrs& boundPcrs)
{
	return TPM_20::WrapKey(keyToWrap, srk, boundPcrs);
}

SPOK_Blob::Blob SPOKServer::GetWrappedKeyName(const SPOK_Blob::Blob& keyWrap)
{
	return TPM_20::GetWrappedKeyName(keyWrap);
}
