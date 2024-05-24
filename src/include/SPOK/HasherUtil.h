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
#include "TPMAlgId.h"
#include "SPOKBlob.h"
#include "BCryptUtil.h"

enum class HasherType
{
	SHA1 = TPM_ALG_ID::TPM_ALG_SHA1,
	SHA256 = TPM_ALG_ID::TPM_ALG_SHA256,
	SHA384 = TPM_ALG_ID::TPM_ALG_SHA384,
	SHA512 = TPM_ALG_ID::TPM_ALG_SHA512,
};

class BCryptHashHandle
{
public:
	BCryptHashHandle(const BCryptAlgHandle& hAlg);
	BCryptHashHandle(const BCryptAlgHandle& hAlg, SPOK_Blob::Blob secret);
	~BCryptHashHandle();
	operator BCRYPT_HASH_HANDLE() const;

	uint32_t GetHashSize() const;

private:
	BCRYPT_HASH_HANDLE m_hHash;
	SPOK_Blob::Blob m_Secret; //HMAC secret
	uint32_t m_HashSize;
};

class HasherUtil
{
public:
	HasherUtil(HasherType type);
	HasherUtil(HasherType type, SPOK_Blob::Blob secret);
	~HasherUtil();

	SPOK_Blob::Blob OneShotHash(const SPOK_Blob::Blob& data);

	void HashData(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob FinishHash();

private:
	BCryptAlgHandle m_hAlg;
	BCryptHashHandle m_hHash;
};

class Hasher
{
public:
	static SPOK_Blob::Blob PublicKeyHash(const SPOK_Blob::Blob& keyBlob);
	static SPOK_Nonce::Nonce Blob2Nonce(const SPOK_Blob::Blob& blob);

	static HasherUtil Create(uint16_t algId);
	static HasherUtil Create_HMAC(uint16_t algId, SPOK_Blob::Blob secret);
};