
#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((uint16_t)0x0004)
#endif
#ifndef TPM_API_ALG_ID_SHA256
#define TPM_API_ALG_ID_SHA256       ((uint16_t)0x000B)
#endif
#ifndef TPM_API_ALG_ID_SHA384
#define TPM_API_ALG_ID_SHA384       ((uint16_t)0x000C)
#endif
#ifndef TPM_API_ALG_ID_SHA512
#define TPM_API_ALG_ID_SHA512       ((uint16_t)0x000D)
#endif
#ifndef TPM_API_ALG_ID_NULL
#define TPM_API_ALG_ID_NULL         ((uint16_t)0x0010)
#endif

struct TPM2B_PCR_SELECTION
{
	uint16_t AlgId;
	SPOK_Blob::Blob Bitmap;
};

struct TPMS_CLOCK_INFO
{
	uint64_t Clock;
	uint32_t ResetCount;
	uint32_t RestartCount;
	uint8_t Safe;
};

struct TPM2B_PUBLIC
{
	uint16_t Type;
	uint16_t NameAlg;
	uint32_t ObjectAttributes;
	SPOK_Blob::Blob AuthPolicy;
	uint16_t Symmetric;
	uint16_t Scheme;
	uint16_t SignHash;
	uint16_t KeyBits;
	SPOK_Blob::Blob Exponent;
	SPOK_Blob::Blob Modulus;

	SPOK_Blob::Blob Raw;
	static TPM2B_PUBLIC Decode(const SPOK_Blob::Blob& publicBlob);
};

struct TPM2B_CREATION_DATA
{
	std::vector<TPM2B_PCR_SELECTION> PcrSelection;
	SPOK_Blob::Blob Digest;
	uint8_t Locality;
	uint16_t ParentNameAlg;
	SPOK_Blob::Blob ParentName;
	SPOK_Blob::Blob ParentQualifiedName;
	SPOK_Nonce::Nonce CreationNonce;

	SPOK_Blob::Blob Raw;
	static TPM2B_CREATION_DATA Decode(const SPOK_Blob::Blob& creationData);
};

struct TPM2B_ATTEST
{
	uint32_t Generated;
	uint16_t Type;
	SPOK_Blob::Blob QualifiedSigner;
	SPOK_Nonce::Nonce CreationNonce;
	TPMS_CLOCK_INFO ClockInfo;
	uint64_t FirmwareVersion;
	SPOK_Blob::Blob ObjectName;
	SPOK_Blob::Blob CreationHash;
	
	SPOK_Blob::Blob Raw;
	static TPM2B_ATTEST Decode(const SPOK_Blob::Blob& attest);
};

struct TPMT_SIGNATURE
{
	uint16_t SigAlg;
	uint16_t HashAlg;
	SPOK_Blob::Blob Signature;

	SPOK_Blob::Blob Raw;
	static TPMT_SIGNATURE Decode(const SPOK_Blob::Blob& signature);
};

struct TPM2B_IDBINDING
{
	TPM2B_PUBLIC Public;
	TPM2B_CREATION_DATA CreationData;
	TPM2B_ATTEST Attest;
	TPMT_SIGNATURE Signature;
};

class TPM_20
{
public:
	static SPOK_Blob::Blob CertifyKey(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest);
	static SPOK_Blob::Blob AttestPlatform(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude);

	static TPM2B_IDBINDING DecodeIDBinding(const SPOK_Blob::Blob& idBinding);
	static SPOK_Blob::Blob GenerateChallengeCredential(const uint16_t ekNameAlgId, const SPOK_Blob::Blob& ekPub, const SPOK_Blob::Blob& secret);
	static SPOK_Blob::Blob KDFa(const uint16_t nameAlgId, const SPOK_Blob::Blob& key, const std::string& label, const SPOK_Blob::Blob& contextU, const SPOK_Blob::Blob& contextV, uint16_t bits);
	static SPOK_Blob::Blob CFB(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& iv, const SPOK_Blob::Blob& data);

private:

};

