
#pragma once

#include "SPOKCore.h"
#include "SPOKBlob.h"
#include "BCryptUtil.h"


enum class HasherType
{
	SHA1 = AlgId::SHA1,
	SHA256 = AlgId::SHA256,
	SHA384 = AlgId::SHA384,
	SHA512 = AlgId::SHA512,
};

class BCryptHashHandle
{
public:
	BCryptHashHandle(BCryptAlgHandle hAlg);
	BCryptHashHandle(BCryptAlgHandle hAlg, SPOK_Blob::Blob secret);
	~BCryptHashHandle();
	operator BCRYPT_HASH_HANDLE() const;

private:
	BCRYPT_HASH_HANDLE m_hHash;
	SPOK_Blob::Blob m_Secret; //HMAC secret
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