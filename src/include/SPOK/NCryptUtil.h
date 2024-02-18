
#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"

#include "standardlib.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>


#define AIK_CHALLENGE_SECRET_SIZE (32)

class NCryptProvHandle
{
public:
	NCryptProvHandle();
	~NCryptProvHandle();
	operator NCRYPT_PROV_HANDLE() const;

private:
	NCRYPT_PROV_HANDLE m_hProv;
};

class NCryptKeyHandle
{
public:
	NCryptKeyHandle(std::wstring name, long flags);
	NCryptKeyHandle(const NCRYPT_KEY_HANDLE& hKey);
	~NCryptKeyHandle();
	operator NCRYPT_KEY_HANDLE() const;

	bool IsValid() const
	{
		return m_hKey != NULL;
	}

private:
	NCryptProvHandle m_hProv;
	NCRYPT_KEY_HANDLE m_hKey;
};

class PlatformAik
{
	public:
		PlatformAik(const SPOK_PlatformKey& aik);
		~PlatformAik();

		SPOK_Blob::Blob GetIdBinding();
		SPOK_Blob::Blob GetPublicKey();

		SPOK_Blob::Blob ActiveChallenge(const SPOK_Blob::Blob& challenge);

private:
	std::wstring m_keyName;
	NCRYPT_MACHINE_KEY m_flag;
};

class PlatformKey
{
public:
	PlatformKey(const SPOK_PlatformKey& aik);
	~PlatformKey();

	SPOK_Blob::Blob GetPublicKey();
	uint16_t KeySize() const;
	uint16_t MaxMessage() const;

	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& data);
	bool Verify(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

private:
	std::wstring m_keyName;
	NCRYPT_MACHINE_KEY m_flag;
};

enum class KeyBlobType : uint32_t
{
	WRAPPED = 0,
	PLAIN = 1
};

class NCryptUtil
{
public:
	static bool DoesAikExists(const SPOK_PlatformKey& aik);
	static PlatformAik CreateAik(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce);
	static void DeleteKey(const SPOK_PlatformKey& aik);

	static SPOK_Blob::Blob GetTpmPublicEndorsementKey();
	static SPOK_Blob::Blob GetTpmSrk();
	static SPOK_Blob::Blob GetPcrTable();
	static SPOK_Blob::Blob GetBootLog();

	//import an opaque key into the TPM
	static void ImportPlatformKey(const SPOK_PlatformKey& aik, const SPOK_Blob::Blob& key, KeyBlobType type);

	//Platform key operations
	static SPOK_Blob::Blob Encrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static SPOK_Blob::Blob Decrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static SPOK_Blob::Blob Sign(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static bool Verify(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);
};