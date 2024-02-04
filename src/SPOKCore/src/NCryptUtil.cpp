#include "NCryptUtil.h"

NCryptProvHandle::NCryptProvHandle()
{
	NTSTATUS status = NCryptOpenStorageProvider(&m_hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptOpenStorageProvider failed");
	}
}

NCryptProvHandle::~NCryptProvHandle()
{
	if (m_hProv != NULL)
	{
		NCryptFreeObject(m_hProv);
		m_hProv = NULL;
	}
}

NCryptProvHandle::operator NCRYPT_PROV_HANDLE() const
{
	return m_hProv;
}

NCryptKeyHandle::NCryptKeyHandle(std::wstring name, long flags)
{
	NCRYPT_KEY_HANDLE hKey;
	// Open the key
	HRESULT status = NCryptOpenKey(m_hProv, &hKey, name.c_str(), 0, flags);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptOpenKey failed");
	}
	m_hKey = hKey;
}

NCryptKeyHandle::~NCryptKeyHandle()
{
	if (m_hKey != NULL)
	{
		NCryptFreeObject(m_hKey);
		m_hKey = NULL;
	}
}

NCryptKeyHandle::operator NCRYPT_KEY_HANDLE() const
{
	return m_hKey;
}

PlatformAik::PlatformAik(std::wstring keyName, NCRYPT_MACHINE_KEY flag) : m_keyName(keyName), m_flag(flag)
{
}

PlatformAik::~PlatformAik()
{
}

SPOK_BindingBlob PlatformAik::GetIdBinding()
{
	NCryptKeyHandle hKey(m_keyName, m_flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);
	DWORD bindingSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(hKey, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, NULL, 0, &bindingSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptGetProperty \"NCRYPT_PCP_TPM12_IDBINDING_PROPERTY\" failed");
	}

	SPOK_BindingBlob binding(bindingSize);
	status = NCryptGetProperty(hKey, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, binding.data(), binding.size(), &bindingSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptGetProperty \"NCRYPT_PCP_TPM12_IDBINDING_PROPERTY\" failed");
	}

	return binding;
}

SPOK_RSAKeyBlob PlatformAik::GetPublicKey()
{
	NCryptKeyHandle hKey(m_keyName, m_flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);
	DWORD keySize = 0;
	// Get the public key
	HRESULT status = NCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptExportKey failed");
	}

	SPOK_RSAKeyBlob key(keySize);
	status = NCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, key.data(), key.size(), &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptExportKey failed");
	}

	return key;
}