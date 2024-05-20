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
#include "SPOKPcrs.h"

#include "standardlib.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tbs.h>
#include <bcrypt.h>
#include <ncrypt.h>

#define AVAILABLE_PLATFORM_PCRS (24)

#define AIK_CHALLENGE_SECRET_SIZE (32)

#ifndef TCG_EVENT_LOG_FORMAT_1_2
#define TCG_EVENT_LOG_FORMAT_1_2    (1)
#endif

#ifndef TCG_EVENT_LOG_FORMAT_2
#define TCG_EVENT_LOG_FORMAT_2      (2)
#endif


class NCryptProvHandle
{
public:
	NCryptProvHandle();
	NCryptProvHandle(const NCRYPT_PROV_HANDLE& hProv);
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
	NCryptKeyHandle(std::wstring name, long flags, const NCRYPT_PROV_HANDLE& hProv);
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

		NCRYPT_PROV_HANDLE GetProviderHandle();
		TBS_HCONTEXT GetTsbHandle();
		uint32_t GetPlatformHandle();
		uint32_t GetSignatureSize();

		SPOK_Blob::Blob ActiveChallenge(const SPOK_Blob::Blob& challenge);

private:
	NCryptKeyHandle m_key;
};

class PlatformKey
{
public:
	PlatformKey(const SPOK_PlatformKey& aik);
	PlatformKey(const SPOK_PlatformKey& aik, const NCRYPT_PROV_HANDLE& hProv);
	~PlatformKey();

	SPOK_Blob::Blob GetPublicKey();
	uint16_t KeySize() const;
	uint16_t MaxMessage() const;

	NCRYPT_PROV_HANDLE GetProviderHandle();
	TBS_HCONTEXT GetTsbHandle();
	uint32_t GetPlatformHandle();
	uint32_t GetSignatureSize();

	SPOK_Blob::Blob Encrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Decrypt(const SPOK_Blob::Blob& data);
	SPOK_Blob::Blob Sign(const SPOK_Blob::Blob& data);
	bool Verify(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);

private:
	NCryptKeyHandle m_key;
};

enum class KeyBlobType : uint32_t
{
	WRAPPED = 0,
	PLAIN = 1
};

class NCryptUtil
{
public:
	static bool DoesPlatformKeyExists(const SPOK_PlatformKey& platformKey);
	static PlatformAik CreateAik(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce);
	static void DeleteKey(const SPOK_PlatformKey& aik);

	static SPOK_Blob::Blob GetTpmPublicEndorsementKey();
	static SPOK_Blob::Blob GetTpmSrk();
	static SPOK_Blob::Blob GetPcrTable();
	static SPOK_Blob::Blob GetTbsLog();
	static SPOK_Blob::Blob GetFilteredTbsLog(uint32_t pcrsToInclude);

	//import an opaque key into the TPM
	static void ImportPlatformKey(const SPOK_PlatformKey& platformKey, const SPOK_Blob::Blob& key, KeyBlobType type);
	static void CreatePlatformKey(const SPOK_PlatformKey& platformKey);

	//Platform key operations
	static SPOK_Blob::Blob Encrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static SPOK_Blob::Blob Decrypt(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static SPOK_Blob::Blob Sign(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data);
	static bool Verify(const SPOK_PlatformKey& key, const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature);
};