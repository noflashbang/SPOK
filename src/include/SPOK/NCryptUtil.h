
#pragma once
#include "SPOKCore.h"
#include "standardlib.h"
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

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
		PlatformAik(std::wstring keyName, NCRYPT_MACHINE_KEY flag);
		~PlatformAik();

		SPOK_BindingBlob GetIdBinding();
		SPOK_RSAKeyBlob GetPublicKey();

private:
	std::wstring m_keyName;
	NCRYPT_MACHINE_KEY m_flag;
};

class NCryptUtil
{
public:
	static bool DoesAikExists(std::wstring keyName, NCRYPT_MACHINE_KEY flag);
	static PlatformAik CreateAik(std::wstring keyName, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce);
	static void DeleteKey(std::wstring keyName, NCRYPT_MACHINE_KEY flag);
};