#pragma once

#include "SPOKCore.h"
#include "StandardLib.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"



struct SPOK_AIKTpmVerify
{
	SPOK_Nonce::Nonce Nonce;
};

struct SPOK_AIKKeyVerify
{
	SPOK_Nonce::Nonce Nonce;
	SPOK_Blob::Blob AikBlob;
	SPOK_Blob::Blob Name;
};

struct SPOK_AIKPlatformVerify
{
	SPOK_Nonce::Nonce Nonce;
	SPOK_Blob::Blob AIKBlob;
};

struct SPOK_TpmVerifyResult
{
	inline bool Result() const { return NonceVerified && NameVerified && CreationVerified && SignatureVerified;	};

	bool NonceVerified;
	bool NameVerified;
	bool CreationVerified;
	bool SignatureVerified;
};

struct SPOK_AIKPlatformVerifyResult
{
	inline bool Result() const { return NonceVerified && SignatureVerified && PcrsVerified; };

	bool NonceVerified;
	bool SignatureVerified;
	bool PcrsVerified;
};

struct SPOK_AIKKeyVerifyResult
{
	inline bool Result() const { return NonceVerified && NameVerified && SignatureVerified; };

	bool NonceVerified;
	bool NameVerified;
	bool SignatureVerified;
};

using SPOK_VerifyResult = std::variant<SPOK_AIKPlatformVerifyResult, SPOK_TpmVerifyResult, SPOK_AIKKeyVerifyResult>;
using SPOK_AttestationVerify = std::variant<SPOK_AIKTpmVerify, SPOK_AIKKeyVerify, SPOK_AIKPlatformVerify>;
