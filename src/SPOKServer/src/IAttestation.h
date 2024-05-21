#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"
#include "SPOKError.h"

#include "SPOK_AIKPlatformAttestation.h"
#include "SPOK_AIKTpmAttestation.h"
#include "SPOK_AIKKeyAttestation.h"

enum class AttestationType : uint32_t
{
	AIKPlatformAttestation,
	AIKTpmAttestation,
	AIKKeyAttestation
};

using IAttestation = std::variant<SPOK_AIKPlatformAttestation, SPOK_AIKTpmAttestation, SPOK_AIKKeyAttestation>;

class Attestation
{
public:
	static IAttestation Create(AttestationType type, SPOK_Blob::Blob blob)
	{
		switch (type)
		{
			case AttestationType::AIKPlatformAttestation:
				return SPOK_AIKPlatformAttestation(blob);
			case AttestationType::AIKTpmAttestation:
				return SPOK_AIKTpmAttestation(blob);
			case AttestationType::AIKKeyAttestation:
				return SPOK_AIKKeyAttestation(blob);
			default:
			{
				auto fmtError = std::format("Invalid AttestationType: {}", (uint32_t)type);
				SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
			}
		}
	};
};

struct IAttestationVerifyVisitor
{
public:
	IAttestationVerifyVisitor(const SPOK_AttestationVerify& verify) : _verifyData(verify) {}

	SPOK_VerifyResult operator()(SPOK_AIKPlatformAttestation& attestation) const
	{
		auto verify = std::get<SPOK_AIKPlatformVerify>(_verifyData);
		return attestation.Verify(verify);
	}

	SPOK_VerifyResult operator()(SPOK_AIKTpmAttestation& attestation) const
	{
		auto verify = std::get<SPOK_AIKTpmVerify>(_verifyData);
		return attestation.Verify(verify);
	}

	SPOK_VerifyResult operator()(SPOK_AIKKeyAttestation& attestation) const
	{
		auto verify = std::get<SPOK_AIKKeyVerify>(_verifyData);
		return attestation.Verify(verify);
	}

private:
	SPOK_AttestationVerify _verifyData;
};