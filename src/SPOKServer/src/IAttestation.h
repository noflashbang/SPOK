#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

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
			return SPOK_AIKKeyAttestation();
		default:
			throw std::invalid_argument("Invalid AttestationType");
		}
	};
};