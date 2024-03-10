#include "SPOKServer.h"
#include "TPM_20.h"

SPOKServer::SPOKServer()
{
}

SPOKServer::~SPOKServer()
{
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

bool SPOKServer::AttestationVerify(IAttestation& attestation, const SPOK_Nonce::Nonce& nonce)
{
	struct VerifyVisitor 
	{
		SPOK_Nonce::Nonce nonce;

		VerifyVisitor(const SPOK_Nonce::Nonce& nonce) : nonce(nonce) {}

		bool operator()(SPOK_AIKPlatformAttestation& attestation) const
		{			
			return false;
		}

		bool operator()(SPOK_AIKTpmAttestation& attestation) const 
		{
			return attestation.Verify(nonce);
		}

		bool operator()(SPOK_AIKKeyAttestation& attestation) const
		{
			return false;
		}
	};

	// Use the visitor on a variant
	return std::visit(VerifyVisitor(nonce), attestation);
}

bool SPOKServer::AttestationVerifyNonce(IAttestation& attestation, const SPOK_Nonce::Nonce& nonce)
{
	struct VerifyVisitor
	{
		SPOK_Nonce::Nonce nonce;

		VerifyVisitor(const SPOK_Nonce::Nonce& nonce) : nonce(nonce) {}

		bool operator()(SPOK_AIKPlatformAttestation& attestation) const
		{
			return false;
		}

		bool operator()(SPOK_AIKTpmAttestation& attestation) const
		{
			return attestation.VerifyNonce(nonce);
		}

		bool operator()(SPOK_AIKKeyAttestation& attestation) const
		{
			return false;
		}
	};

	// Use the visitor on a variant
	return std::visit(VerifyVisitor(nonce), attestation);
}

bool SPOKServer::AttestationVerifySignature(IAttestation& attestation)
{
	struct VerifyVisitor
	{
		bool operator()(SPOK_AIKPlatformAttestation& attestation) const
		{
			return false;
		}

		bool operator()(SPOK_AIKTpmAttestation& attestation) const
		{
			return attestation.VerifySignature();
		}

		bool operator()(SPOK_AIKKeyAttestation& attestation) const
		{
			return false;
		}
	};

	// Use the visitor on a variant
	return std::visit(VerifyVisitor(), attestation);
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
