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

#include "TPMAlgId.h"
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"


#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>




class BCryptAlgHandle
{
public:
	BCryptAlgHandle(TPM_ALG_ID alg);
	BCryptAlgHandle(TPM_ALG_ID alg, bool hmacFlag);
	~BCryptAlgHandle();
	operator BCRYPT_ALG_HANDLE() const;

	std::string Name() const;

private:
	BCRYPT_ALG_HANDLE m_hAlg;
	TPM_ALG_ID m_algId;
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
	uint16_t BlockLength() const;
	uint16_t MaxMessage() const;

	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& data, bool useIdentity); //TODO: remove useIdentity
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& data);

	void SetSignHashAlg(uint16_t algId);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& data);
	bool Verify(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

private:
	uint16_t m_signHashAlg = 0x000B; //TPM_ALG_SHA256
	BCryptAlgHandle m_hAlg;
	BCRYPT_KEY_HANDLE m_hKey;
};

enum class KeySize : uint32_t
{
	RSA_1024 = 1024,
	RSA_2048 = 2048,
	RSA_4096 = 4096
};

class SymmetricCipher
{
public:
	SymmetricCipher(const SPOK_Blob::Blob& key, const std::wstring& alg, const std::wstring& mode, const SPOK_Blob::Blob& iv);
	~SymmetricCipher();
	operator BCRYPT_KEY_HANDLE() const;

	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& data);

private:
	BCryptAlgHandle m_hAlg;
	BCRYPT_KEY_HANDLE m_hKey;
	SPOK_Blob::Blob m_iv;
};

class BCryptUtil
{
public:
	static std::wstring RsaKeyType(const SPOK_Blob::Blob& keyBlob);

	static BCryptKey Open(const SPOK_Blob::Blob& keyBlob);
	static SPOK_Blob::Blob GenerateRsaKeyPair(const KeySize keySize);
	static SPOK_Blob::Blob GetRandomBytes(const uint32_t size);
	static SPOK_Nonce::Nonce GetRandomNonce();

	static SymmetricCipher CreateSymmetricCipher(const SPOK_Blob::Blob& key, const std::wstring& alg, const std::wstring& mode, const SPOK_Blob::Blob& iv);
};