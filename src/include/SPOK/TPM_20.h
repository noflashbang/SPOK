//MIT License
//
//Copyright(c) 2024 noflashbang
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((uint16_t)0x0004)
#endif
#include <SPOKPcrs.h>
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
	SPOK_Blob Bitmap;

	uint32_t GetMask() const;
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
	SPOK_Blob AuthPolicy;
	uint16_t Symmetric;
	uint16_t Scheme;
	uint16_t SignHash;
	uint16_t KeyBits;
	SPOK_Blob Exponent;
	SPOK_Blob Modulus;

	SPOK_Blob Raw;
	static TPM2B_PUBLIC Decode(const SPOK_Blob& publicBlob);
};

struct TPM2B_CREATION_DATA
{
	std::vector<TPM2B_PCR_SELECTION> PcrSelection;
	SPOK_Blob Digest;
	uint8_t Locality;
	uint16_t ParentNameAlg;
	SPOK_Blob ParentName;
	SPOK_Blob ParentQualifiedName;
	SPOK_Nonce::Nonce CreationNonce;

	SPOK_Blob Raw;
	static TPM2B_CREATION_DATA Decode(const SPOK_Blob& creationData);
};

struct TPM2B_ATTEST_QUOTE
{
	uint32_t Generated;
	uint16_t Type;
	SPOK_Blob QualifiedSigner;
	SPOK_Nonce::Nonce CreationNonce;
	TPMS_CLOCK_INFO ClockInfo;
	uint64_t FirmwareVersion;

	std::vector<TPM2B_PCR_SELECTION> PcrSelection;
	SPOK_Blob PcrDigest;

	SPOK_Blob Raw;
	static TPM2B_ATTEST_QUOTE Decode(const SPOK_Blob& attest);
};

struct TPM2B_ATTEST_CERTIFY
{
	uint32_t Generated;
	uint16_t Type;
	SPOK_Blob QualifiedSigner;
	SPOK_Nonce::Nonce CreationNonce;
	TPMS_CLOCK_INFO ClockInfo;
	uint64_t FirmwareVersion;

	SPOK_Blob Name;
	SPOK_Blob QualifiedName;

	SPOK_Blob Raw;
	static TPM2B_ATTEST_CERTIFY Decode(const SPOK_Blob& attest);
};

struct TPM2B_ATTEST_CREATION
{
	uint32_t Generated;
	uint16_t Type;
	SPOK_Blob QualifiedSigner;
	SPOK_Nonce::Nonce CreationNonce;
	TPMS_CLOCK_INFO ClockInfo;
	uint64_t FirmwareVersion;

	SPOK_Blob ObjectName;
	SPOK_Blob CreationHash;

	SPOK_Blob Raw;
	static TPM2B_ATTEST_CREATION Decode(const SPOK_Blob& attest);
};

struct TPMT_SIGNATURE
{
	uint16_t SigAlg;
	uint16_t HashAlg;
	SPOK_Blob Signature;

	SPOK_Blob Raw;
	static TPMT_SIGNATURE Decode(const SPOK_Blob& signature);
};

struct TPM2B_IDBINDING
{
	TPM2B_PUBLIC Public;
	TPM2B_CREATION_DATA CreationData;
	TPM2B_ATTEST_CREATION Attest;
	TPMT_SIGNATURE Signature;
};

// Storage structure for 2.0 keys - I can't find a source for this structure - other than PCPTool.
// Not sure if this structure is defined somewhere else. Seems to be specific to PCP from MSFT.
struct PCP_20_KEY_BLOB
{
#define PCP_20_KEY_BLOB_MAGIC 'MPCP'
#define PCPTYPE_TPM20 (0x00000002)

	uint32_t   Magic;
	uint32_t   HeaderSize;
	uint32_t   PcpType;
	uint32_t   Flags;
	uint32_t   PublicSize;
	uint32_t   PrivateSize;
	uint32_t   MigrationPublicSize;
	uint32_t   MigrationPrivateSize;
	uint32_t   PolicyDigestListSize;
	uint32_t   PcrBindingSize;
	uint32_t   PcrDigestSize;
	uint32_t   EncryptedSecretSize;
	uint32_t   Tpm12HostageBlobSize;
	uint16_t   PcrAlgId;
};

class TPM_20
{
public:
	static SPOK_Blob CertifyKey(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest);
	static SPOK_Blob AttestPlatform(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude);
	static SPOK_Blob WrapKey(const SPOK_Blob& key, const SPOK_Blob& srk, const SPOK_Pcrs& boundPcrs);
	static SPOK_Blob GetWrappedKeyName(const SPOK_Blob& wrappedKey);

	static TPM2B_IDBINDING DecodeIDBinding(const SPOK_Blob& idBinding);
	static SPOK_Blob GenerateChallengeCredential(const uint16_t ekNameAlgId, const SPOK_Blob& ekPub, const SPOK_Blob& aikName, const SPOK_Blob& secret);
	static SPOK_Blob KDFa(const uint16_t nameAlgId, const SPOK_Blob& key, const std::string& label, const SPOK_Blob& contextU, const SPOK_Blob& contextV, uint16_t bits);
	static SPOK_Blob CFB(const SPOK_Blob& key, const SPOK_Blob& iv, const SPOK_Blob& data);

private:

	static SPOK_Blob GetNameForPublic(const SPOK_Blob& publicBlob);
};
