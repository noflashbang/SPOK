
#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"

#include "standardlib.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>

class BCryptAlgHandle
{
public:
	BCryptAlgHandle();
	~BCryptAlgHandle();
	operator BCRYPT_ALG_HANDLE() const;

private:
	BCRYPT_ALG_HANDLE m_hAlg;
};

class BCryptKey
{
public:
	BCryptKey(SPOK_Blob::Blob keyBlob);
	BCryptKey(const BCRYPT_KEY_HANDLE& hKey);
	~BCryptKey();
	operator BCRYPT_KEY_HANDLE() const;

	bool IsValid() const
	{
		return m_hKey != NULL;
	}

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
	static std::wstring RsaKeyType(const SPOK_Blob::Blob keyBlob);
	static BCryptKey Open(SPOK_Blob::Blob keyBlob);
	static SPOK_Blob::Blob GenerateRsaKeyPair(KeySize keySize);
};