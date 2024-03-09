
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
	~BCryptHashHandle();
	operator BCRYPT_HASH_HANDLE() const;

private:
	BCRYPT_HASH_HANDLE m_hHash;
};

class HasherUtil
{
public:
	HasherUtil(HasherType type);
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

	static HasherUtil Create(uint16_t algId);
};