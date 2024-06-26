#include "SPOKServerApi.h"
#include "SPOKServer.h"
#include "SPOKCore.h"
#include "AttestationManager.h"
#include "SPOKError.h"

SPOKSTATUS SPS_AttestationDestroy(SPOK_Handle hAttestationHandle)
{
	try
	{
		AttestationManager::Destroy(hAttestationHandle);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

SPOK_Handle SPS_AIKPlatformAttest_Decode(const uint8_t* pBlob, const size_t cbBlob)
{
	try
	{
		auto blob = SPOK_Blob::New(pBlob, cbBlob);
		auto server = SPOKServer();
		auto attestation = server.AIKAttestationDecode(blob);
		return AttestationManager::Add(attestation);
	}
	catch (...)
	{
		return NULL;
	}
}

SPOKSTATUS SPS_AIKPlatformAttest_GetPCR(SPOK_Handle hAttest, uint8_t* pPcrTable, const size_t cbPcrTable, size_t& sizeOut, uint8_t& hashSizeOut)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}

		auto server = SPOKServer();
		auto pcrs = server.AIKAttestationGetPCR(attestation.value());
		auto blob = pcrs.GetBlob();
		SPOK_Blob::Copy2CStylePtr(blob, pPcrTable, cbPcrTable, sizeOut);
		hashSizeOut = pcrs.GetDigestSize();
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

SPOKSTATUS SPS_AIKPlatformAttest_GetTcgLog(SPOK_Handle hAttest, uint8_t* pLog, const size_t cbLog, size_t& sizeOut)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}

		auto server = SPOKServer();
		auto log = server.AIKAttestationGetTcgLog(attestation.value());
		SPOK_Blob::Copy2CStylePtr(log, pLog, cbLog, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

bool SPS_AIKPlatformAttest_Verify(SPOK_Handle hAttest, const uint8_t* pNonce, const size_t cbNonce, const uint8_t* pAikPub, const size_t cbAikPub)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}

		auto nonce = SPOK_Nonce::Make(pNonce, cbNonce);
		auto aikPub = SPOK_Blob::New(pAikPub, cbAikPub);
		auto server = SPOKServer();
		auto verify = SPOK_AIKPlatformVerify{ nonce, aikPub };
		auto result = server.AttestationVerify(attestation.value(), verify);
		return std::get<SPOK_AIKPlatformVerifyResult>(result).Result();
	}
	catch (...)
	{
		return false;
	}
}

SPOK_Handle SPS_AIKTpmAttest_Decode(const uint8_t* pBlob, const size_t cbBlob)
{
	try
	{
		auto blob = SPOK_Blob::New(pBlob, cbBlob);
		auto server = SPOKServer();
		auto attestation = server.AIKTpmAttestationDecode(blob);
		return AttestationManager::Add(attestation);
	}
	catch (...)
	{
		return NULL;
	}
}

SPOKSTATUS SPS_AIKTpmAttest_GetChallenge(SPOK_Handle hAttest, const uint16_t ekNameAlgId, const uint8_t* pEkPub, const size_t cbEkPub, const uint8_t* pSecret, const size_t cbSecret, uint8_t* pChallenge, const size_t cbChallenge, size_t& sizeOut)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}
		if (!std::holds_alternative<SPOK_AIKTpmAttestation>(attestation.value()))
		{
			SPOK_THROW_ERROR(SPOK_INVALID_DATA, "Attestation is not an AIK TPM Attestation");
		}

		auto tpmAttest = std::get<SPOK_AIKTpmAttestation>(attestation.value());
		auto aikName = tpmAttest.GetPublicName();
		auto ekPub = SPOK_Blob::New(pEkPub, cbEkPub);
		auto secret = SPOK_Blob::New(pSecret, cbSecret);
		auto server = SPOKServer();
		auto challenge = server.AIKGetTpmAttestationChallenge(ekNameAlgId, ekPub, aikName, secret);
		SPOK_Blob::Copy2CStylePtr(challenge, pChallenge, cbChallenge, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

SPOK_Handle SPS_AIKKeyAttest_Decode(const uint8_t* pBlob, const size_t cbBlob)
{
	try
	{
		auto blob = SPOK_Blob::New(pBlob, cbBlob);
		auto server = SPOKServer();
		auto attestation = server.AIKKeyAttestationDecode(blob);
		return AttestationManager::Add(attestation);
	}
	catch (...)
	{
		return NULL;
	}
}

bool SPS_AIKKeyAttest_Verify(SPOK_Handle hAttest, const uint8_t* pNonce, const size_t cbNonce, const uint8_t* pAikPub, const size_t cbAikPub, const uint8_t* pPubName, const size_t cbPubName)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}
		if (!std::holds_alternative<SPOK_AIKKeyAttestation>(attestation.value()))
		{
			SPOK_THROW_ERROR(SPOK_INVALID_DATA, "Attestation is not an AIK Key Attestation");
		}

		auto nonce = SPOK_Nonce::Make(pNonce, cbNonce);
		auto aikPub = SPOK_Blob::New(pAikPub, cbAikPub);
		auto pubName = SPOK_Blob::New(pPubName, cbPubName);
		auto server = SPOKServer();
		auto verify = SPOK_AIKKeyVerify{ nonce, aikPub, pubName };
		auto result = server.AttestationVerify(attestation.value(), verify);
		return std::get<SPOK_AIKKeyVerifyResult>(result).Result();
	}
	catch (...)
	{
		return false;
	}
}

bool SPS_AIKAttest_Verify(SPOK_Handle hAttest, const uint8_t* nonce, const size_t cbNonce)
{
	try
	{
		auto attestation = AttestationManager::Get(hAttest);
		if (!attestation.has_value())
		{
			SPOK_THROW_ERROR(SPOK_NOT_FOUND, "Attestation not found for handle");
		}

		auto server = SPOKServer();
		auto blob = SPOK_Nonce::Make(nonce, cbNonce);
		auto verify = SPOK_AIKTpmVerify{ blob };
		auto result = server.AttestationVerify(attestation.value(), verify);
		return std::get<SPOK_TpmVerifyResult>(result).Result();
	}
	catch (...)
	{
		return false;
	}
}

//Basic Crypto Operations
SPOKSTATUS SPS_Decrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	try
	{
		auto blob = SPOK_Blob::New(pKey, cbKey);
		auto data = SPOK_Blob::New(pBytes, cbBytes);
		auto server = SPOKServer();
		auto decrypted = server.Decrypt(blob, data);
		SPOK_Blob::Copy2CStylePtr(decrypted, pData, cbData, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}
SPOKSTATUS SPS_Encrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pData, const size_t cbData, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut)
{
	try
	{
		auto blob = SPOK_Blob::New(pKey, cbKey);
		auto data = SPOK_Blob::New(pData, cbData);
		auto server = SPOKServer();
		auto encrypted = server.Encrypt(blob, data);
		SPOK_Blob::Copy2CStylePtr(encrypted, pBytes, cbBytes, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}
SPOKSTATUS SPS_Sign(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut)
{
	try
	{
		auto blob = SPOK_Blob::New(pKey, cbKey);
		auto hash = SPOK_Blob::New(pHash, cbHash);
		auto server = SPOKServer();
		auto signature = server.Sign(blob, hash);
		SPOK_Blob::Copy2CStylePtr(signature, pSignature, cbSignature, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}
bool SPS_VerifySignature(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature)
{
	try
	{
		auto blob = SPOK_Blob::New(pKey, cbKey);
		auto hash = SPOK_Blob::New(pHash, cbHash);
		auto signature = SPOK_Blob::New(pSignature, cbSignature);
		auto server = SPOKServer();
		return server.VerifySignature(blob, hash, signature);
	}
	catch (...)
	{
		return false;
	}
}

//Key Helpers
SPOKSTATUS SPS_GenerateRSAKeyPair(const uint16_t keySizeBits, uint8_t* pData, const size_t cbData, size_t& sizeOut)
{
	try
	{
		auto server = SPOKServer();
		auto keySize = static_cast<KeySize>(keySizeBits);
		auto keyPair = server.GenerateRSAKeyPair(keySize);
		SPOK_Blob::Copy2CStylePtr(keyPair, pData, cbData, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

SPOKSTATUS SPS_WrapKeyForPlatformImport(const uint8_t* pKeyToWrap, const size_t cbKeyToWrap, const uint8_t* pSrk, const size_t cbSrk, uint8_t* pBoundPcrTable, const size_t cbBoundPcrTable, uint8_t* pKeyWrap, const size_t cbKeyWrap, size_t& sizeOut)
{
	try
	{
		auto keyToWrap = SPOK_Blob::New(pKeyToWrap, cbKeyToWrap);
		auto srk = SPOK_Blob::New(pSrk, cbSrk);
		auto boundPcrTable = SPOK_Pcrs(SPOK_Blob::New(pBoundPcrTable, cbBoundPcrTable));
		auto server = SPOKServer();
		auto wrappedKey = server.WrapKeyForPlatformImport(keyToWrap, srk, boundPcrTable);
		SPOK_Blob::Copy2CStylePtr(wrappedKey, pKeyWrap, cbKeyWrap, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}

SPOKSTATUS SPS_WrappedKeyName(const uint8_t* pKeyWrap, const size_t cbKeyWrap, uint8_t* pName, const size_t cbName, size_t& sizeOut)
{
	try
	{
		auto keyWrap = SPOK_Blob::New(pKeyWrap, cbKeyWrap);
		auto server = SPOKServer();
		auto name = server.GetWrappedKeyName(keyWrap);
		SPOK_Blob::Copy2CStylePtr(name, pName, cbName, sizeOut);
		return SPOK_OKAY;
	}
	catch (...)
	{
		return SPOK_Error::SPOK_LippincottHandler();
	}
}