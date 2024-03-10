#include "SPOKServerApi.h"
#include "SPOKServer.h"
#include "SPOKCore.h"
#include "AttestationManager.h"


void SPS_AttestationDestroy(SPOK_Handle hAttestationHandle)
{
	AttestationManager::Destroy(hAttestationHandle);
}

SPOK_Handle SPS_AIKTpmAttest_Decode(const uint8_t* pBlob, const size_t cbBlob)
{
	auto blob = SPOK_Blob::New(pBlob, cbBlob);
	auto server = SPOKServer();
	auto attestation = server.AIKTpmAttestationDecode(blob);
	return AttestationManager::Add(attestation);
}

void SPS_AIKTpmAttest_GetChallenge(SPOK_Handle hAttest, const uint16_t ekNameAlgId, const uint8_t* pEkPub, const size_t cbEkPub, const uint8_t* pSecret, const size_t cbSecret, uint8_t* pChallenge, const size_t cbChallenge, size_t& sizeOut)
{
	auto attestation = AttestationManager::Get(hAttest);
	if (!attestation.has_value())
	{
		throw std::runtime_error("Attestation not found");
	}
	if (!std::holds_alternative<SPOK_AIKTpmAttestation>(attestation.value()))
	{
		throw std::runtime_error("Attestation is not an AIK TPM Attestation");
	}

	auto tpmAttest = std::get<SPOK_AIKTpmAttestation>(attestation.value());
	auto aikName = tpmAttest.GetPublicName();
	auto ekPub = SPOK_Blob::New(pEkPub, cbEkPub);
	auto secret = SPOK_Blob::New(pSecret, cbSecret);
	auto server = SPOKServer();
	auto challenge = server.AIKGetTpmAttestationChallenge(ekNameAlgId, ekPub, aikName, secret);
	SPOK_Blob::Copy2CStylePtr(challenge, pChallenge, cbChallenge, sizeOut);
}

bool SPS_AIKAttest_Verify(SPOK_Handle hAttest, const uint8_t* nonce, const size_t cbNonce)
{
	auto attestation = AttestationManager::Get(hAttest);
	if(!attestation.has_value())
	{
		return false;
	}
	auto server = SPOKServer();
	auto blob = SPOK_Nonce::Make(nonce, cbNonce);
	return server.AttestationVerify(attestation.value(), blob);
}
bool SPS_AIKAttest_VerifyNonce(SPOK_Handle hAttest, const uint8_t* nonce, const size_t cbNonce)
{
	auto attestation = AttestationManager::Get(hAttest);
	if (!attestation.has_value())
	{
		return false;
	}
	auto server = SPOKServer();
	auto blob = SPOK_Nonce::Make(nonce, cbNonce);
	return server.AttestationVerifyNonce(attestation.value(), blob);
}
bool SPS_AIKAttest_VerifySignature(SPOK_Handle hAttest)
{
	auto attestation = AttestationManager::Get(hAttest);
	if (!attestation.has_value())
	{
		return false;
	}
	auto server = SPOKServer();
	return server.AttestationVerifySignature(attestation.value());
}

//Basic Crypto Operations
void SPS_Decrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto data = SPOK_Blob::New(pBytes, cbBytes);
	auto server = SPOKServer();
	auto decrypted = server.Decrypt(blob, data);
	SPOK_Blob::Copy2CStylePtr(decrypted, pData, cbData, sizeOut);
}
void SPS_Encrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pData, const size_t cbData, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto data = SPOK_Blob::New(pData, cbData);
	auto server = SPOKServer();
	auto encrypted = server.Encrypt(blob, data);
	SPOK_Blob::Copy2CStylePtr(encrypted, pBytes, cbBytes, sizeOut);
}
void SPS_Sign(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto hash = SPOK_Blob::New(pHash, cbHash);
	auto server = SPOKServer();
	auto signature = server.Sign(blob, hash);
	SPOK_Blob::Copy2CStylePtr(signature, pSignature, cbSignature, sizeOut);
}
bool SPS_VerifySignature(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature)
{
	auto blob = SPOK_Blob::New(pKey, cbKey);
	auto hash = SPOK_Blob::New(pHash, cbHash);
	auto signature = SPOK_Blob::New(pSignature, cbSignature);
	auto server = SPOKServer();
	return server.VerifySignature(blob, hash, signature);
}

//Key Helpers
void SPS_GenerateRSAKeyPair(const uint16_t keySizeBits, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	auto server = SPOKServer();
	auto keySize = static_cast<KeySize>(keySizeBits);
	auto keyPair = server.GenerateRSAKeyPair(keySize);
	SPOK_Blob::Copy2CStylePtr(keyPair, pData, cbData, sizeOut);
}
