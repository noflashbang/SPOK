
#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"


#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>


enum class AlgId : uint16_t
{
	RNG,
	RSA,
	SHA1   = 0x0004, //MATCH TPM_ALG_SHA1
	SHA256 = 0x000B, //MATCH TPM_ALG_SHA256
	SHA384 = 0x000C, //MATCH TPM_ALG_SHA384
	SHA512 = 0x000D, //MATCH TPM_ALG_SHA512
};

class BCryptAlgHandle
{
public:
	BCryptAlgHandle(AlgId alg);
	~BCryptAlgHandle();
	operator BCRYPT_ALG_HANDLE() const;

	std::string Name() const;

private:
	BCRYPT_ALG_HANDLE m_hAlg;
	AlgId m_algId;
};

class BCryptKey
{
public:
	BCryptKey(SPOK_Blob::Blob keyBlob);
	BCryptKey(const BCRYPT_KEY_HANDLE& hKey);
	~BCryptKey();
	operator BCRYPT_KEY_HANDLE() const;

	SPOK_Blob::Blob GetPublicKey();

	bool IsValid() const
	{
		return m_hKey != NULL;
	}

	uint16_t KeySize() const;
	uint16_t MaxMessage() const;

	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& data);
	bool Verify(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

private:
	BCryptAlgHandle m_hAlg;
	BCRYPT_KEY_HANDLE m_hKey;
};

enum class KeySize : uint32_t
{
	RSA_1024 = 1024,
	RSA_2048 = 2048,
	RSA_4096 = 4096
};

class BCryptUtil
{
public:
	static std::wstring RsaKeyType(const SPOK_Blob::Blob& keyBlob);

	static BCryptKey Open(SPOK_Blob::Blob& keyBlob);
	static SPOK_Blob::Blob GenerateRsaKeyPair(KeySize keySize);
	static SPOK_Blob::Blob GetRandomBytes(uint32_t size);
};