#include "NCryptUtil.h"
#include "BCryptUtil.h"
#include "TcgLog.h"

#include <TBS.h>
#include <wbcl.h>
#include "Util.h"
#include <iostream>
#include <format>
#include "SPOKError.h"

NCryptProvHandle::NCryptProvHandle()
{
	NTSTATUS status = NCryptOpenStorageProvider(&m_hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptOpenStorageProvider failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
}

NCryptProvHandle::NCryptProvHandle(const NCRYPT_PROV_HANDLE& hProv) : m_hProv(hProv)
{
};

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
		m_hKey = NULL;
	}
	else
	{
		m_hKey = hKey;
	}
}

NCryptKeyHandle::NCryptKeyHandle(const NCRYPT_KEY_HANDLE& hKey) : m_hKey(hKey)
{
}

NCryptKeyHandle::NCryptKeyHandle(std::wstring name, long flags, const NCRYPT_PROV_HANDLE& hProv) : m_hProv(hProv)
{
	NCRYPT_KEY_HANDLE hKey;
	// Open the key
	HRESULT status = NCryptOpenKey(m_hProv, &hKey, name.c_str(), 0, flags);
	if (status != ERROR_SUCCESS)
	{
		m_hKey = NULL;
	}
	else
	{
		m_hKey = hKey;
	}
};

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

PlatformAik::PlatformAik(const SPOK_PlatformKey& aik) : m_key(aik.Name, aik.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0)
{
}

PlatformAik::~PlatformAik()
{
}

SPOK_Blob PlatformAik::GetIdBinding()
{
	DWORD bindingSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, NULL, 0, &bindingSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_TPM12_IDBINDING_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto binding = SPOK_Blob::New(bindingSize);
	status = NCryptGetProperty(m_key, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, binding.data(), SAFE_CAST_TO_INT32(binding.size()), &bindingSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_TPM12_IDBINDING_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return binding;
}

SPOK_Blob PlatformAik::GetPublicKey()
{
	DWORD keySize = 0;
	// Get the public key
	HRESULT status = NCryptExportKey(m_key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptExportKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto key = SPOK_Blob::New(keySize);
	status = NCryptExportKey(m_key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, key.data(), SAFE_CAST_TO_INT32(key.size()), &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptExportKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return key;
}

NCRYPT_PROV_HANDLE PlatformAik::GetProviderHandle()
{
	NCRYPT_PROV_HANDLE hProv;
	DWORD handleSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_PROVIDER_HANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hProv), sizeof(hProv), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PROVIDER_HANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return hProv;
}
TBS_HCONTEXT PlatformAik::GetTsbHandle()
{
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	auto hProv = GetProviderHandle();
	DWORD handleSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hPlatformTbsHandle), sizeof(hPlatformTbsHandle), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PLATFORMHANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return hPlatformTbsHandle;
}
uint32_t PlatformAik::GetPlatformHandle()
{
	uint32_t hPlatformHandle = 0;
	DWORD handleSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hPlatformHandle), sizeof(hPlatformHandle), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PLATFORMHANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return hPlatformHandle;
}
uint32_t PlatformAik::GetSignatureSize()
{
	uint32_t signatureSize = 0;
	DWORD cbSignatureSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(m_key, BCRYPT_SIGNATURE_LENGTH, reinterpret_cast<PBYTE>(&signatureSize), sizeof(signatureSize), &cbSignatureSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"BCRYPT_SIGNATURE_LENGTH\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	return signatureSize;
}

SPOK_Blob PlatformAik::ActiveChallenge(const SPOK_Blob& challenge)
{
	DWORD responseSize = 0;

	//Set the AIK challenge
	HRESULT status = NCryptSetProperty(m_key, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, const_cast<uint8_t*>(challenge.data()), SAFE_CAST_TO_INT32(challenge.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSetProperty \"NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	// Get the secret
	auto response = SPOK_Blob::New(256);
	status = NCryptGetProperty(m_key, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, response.data(), SAFE_CAST_TO_INT32(response.size()), &responseSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	response.resize(responseSize);
	return response;
}

PlatformKey::PlatformKey(const SPOK_PlatformKey& aik) : m_key(aik.Name, aik.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0)
{
};

PlatformKey::PlatformKey(const SPOK_PlatformKey& aik, const NCRYPT_PROV_HANDLE& hProv) : m_key(aik.Name, aik.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0, hProv)
{
};

PlatformKey::~PlatformKey()
{
}

SPOK_Blob PlatformKey::GetPublicKey()
{
	DWORD keySize = 0;
	// Get the public key
	HRESULT status = NCryptExportKey(m_key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptExportKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto key = SPOK_Blob::New(keySize);
	status = NCryptExportKey(m_key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, key.data(), SAFE_CAST_TO_INT32(key.size()), &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptExportKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return key;
}

uint16_t PlatformKey::KeySize() const
{
	DWORD keySize = 0;
	DWORD cbKeySize = 0;
	// Get the key size
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keySize, sizeof(keySize), &cbKeySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_LENGTH_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return SAFE_CAST_TO_UINT16(keySize);
}

uint16_t PlatformKey::MaxMessage() const
{
	uint16_t keySize = KeySize();
	uint16_t maxMessage = (keySize / 8) - 62; // OAEP padding
	return maxMessage;
}

NCRYPT_PROV_HANDLE PlatformKey::GetProviderHandle()
{
	NCRYPT_PROV_HANDLE hProv;
	DWORD handleSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_PROVIDER_HANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hProv), sizeof(hProv), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PROVIDER_HANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return hProv;
}
TBS_HCONTEXT PlatformKey::GetTsbHandle()
{
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	auto hProv = GetProviderHandle();
	DWORD handleSize = 0;
	// Get the ID binding
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hPlatformTbsHandle), sizeof(hPlatformTbsHandle), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PLATFORMHANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	return hPlatformTbsHandle;
}
uint32_t PlatformKey::GetPlatformHandle()
{
	uint32_t hPlatformHandle = 0;
	DWORD handleSize = 0;
	HRESULT status = NCryptGetProperty(m_key, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hPlatformHandle), sizeof(hPlatformHandle), &handleSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PLATFORMHANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return hPlatformHandle;
}
uint32_t PlatformKey::GetSignatureSize()
{
	uint32_t signatureSize = 0;
	DWORD cbSignatureSize = 0;
	HRESULT status = NCryptGetProperty(m_key, BCRYPT_SIGNATURE_LENGTH, reinterpret_cast<PBYTE>(&signatureSize), sizeof(signatureSize), &cbSignatureSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"BCRYPT_SIGNATURE_LENGTH\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	return signatureSize;
}

SPOK_Blob PlatformKey::Encrypt(const SPOK_Blob& data)
{
	if (data.size() > MaxMessage())
	{
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, std::format("Data too large to encrypt -> Max {} bytes, got {} bytes", MaxMessage(), data.size()));
	}

	DWORD dataSize = 0;

	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;

	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	// Encrypt the data
	HRESULT status = NCryptEncrypt(m_key, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), &paddingInfo, NULL, 0, &dataSize, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptEncrypt failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto encryptedData = SPOK_Blob::New(dataSize);
	status = NCryptEncrypt(m_key, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), &paddingInfo, encryptedData.data(), SAFE_CAST_TO_INT32(encryptedData.size()), &dataSize, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptEncrypt failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return encryptedData;
}

SPOK_Blob PlatformKey::Decrypt(const SPOK_Blob& data)
{
	DWORD dataSize = 0;
	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;
	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	auto decryptedData = SPOK_Blob::New(1);
	// Decrypt the data
	HRESULT status = NCryptDecrypt(m_key, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), &paddingInfo, decryptedData.data(), SAFE_CAST_TO_INT32(decryptedData.size()), &dataSize, NCRYPT_PAD_OAEP_FLAG);
	if (status == TPM_E_PCP_BUFFER_TOO_SMALL)
	{
		decryptedData.resize(dataSize);
	}
	else if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptDecrypt failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	status = NCryptDecrypt(m_key, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), &paddingInfo, decryptedData.data(), SAFE_CAST_TO_INT32(decryptedData.size()), &dataSize, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptDecrypt failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return decryptedData;
}

SPOK_Blob PlatformKey::Sign(const SPOK_Blob& data)
{
	if (data.size() > MaxMessage())
	{
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, std::format("Data too large to sign -> Max {} bytes, got {} bytes", MaxMessage(), data.size()));
	}

	DWORD signatureSize = 0;

	//SHA256 padding
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;

	HRESULT status = NCryptSignHash(m_key, &padInfo, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), NULL, 0, &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSignHash failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto signature = SPOK_Blob::New(signatureSize);
	status = NCryptSignHash(m_key, &padInfo, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), signature.data(), SAFE_CAST_TO_INT32(signature.size()), &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSignHash failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return signature;
}

bool PlatformKey::Verify(const SPOK_Blob& data, const SPOK_Blob& signature)
{
	DWORD signatureSize = 0;

	//SHA256 padding
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;

	HRESULT status = NCryptVerifySignature(m_key, &padInfo, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_INT32(data.size()), const_cast<uint8_t*>(signature.data()), SAFE_CAST_TO_INT32(signature.size()), BCRYPT_PAD_PKCS1);
	if (status != NTE_BAD_SIGNATURE && SUCCEEDED(status))
	{
		return true;
	}

	return false;
}

bool NCryptUtil::DoesPlatformKeyExists(const SPOK_PlatformKey& platformKey)
{
	NCryptProvHandle hProv;

	NCryptKeyHandle hKey(platformKey.Name, platformKey.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);

	return hKey.IsValid();
}

PlatformAik NCryptUtil::CreateAik(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce)
{
	DWORD ncryptKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
	NCryptProvHandle hProv;
	NCRYPT_KEY_HANDLE hKey;
	// Create the key
	long flags = NCRYPT_OVERWRITE_KEY_FLAG | (aik.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);
	HRESULT status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, aik.Name.c_str(), 0, flags);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptCreatePersistedKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	// RAII
	NCryptKeyHandle keyHandle(hKey);

	//set the key usage policy
	status = NCryptSetProperty(keyHandle, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, (PBYTE)&ncryptKeyUsage, sizeof(ncryptKeyUsage), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSetProperty \"NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	// Set the nonce
	status = NCryptSetProperty(keyHandle, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, const_cast<uint8_t*>(nonce.data()), SAFE_CAST_TO_INT32(nonce.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSetProperty \"NCRYPT_PCP_TPM12_IDBINDING_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	// Finalize the key
	status = NCryptFinalizeKey(keyHandle, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptFinalizeKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return PlatformAik(aik);
}

void NCryptUtil::DeleteKey(const SPOK_PlatformKey& aik)
{
	NCryptProvHandle hProv;
	NCryptKeyHandle hKey(aik.Name, aik.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);

	if (!hKey.IsValid())
	{
		return;
	}
	// Delete the key
	HRESULT status = NCryptDeleteKey(hKey, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptDeleteKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
}

SPOK_Blob NCryptUtil::GetTpmPublicEndorsementKey()
{
	NCryptProvHandle hProv;
	DWORD keySize = 0;
	// Get the public endorsement key
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, NULL, 0, &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_EKPUB_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto key = SPOK_Blob::New(keySize);
	status = NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, key.data(), SAFE_CAST_TO_INT32(key.size()), &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_EKPUB_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return key;
}

SPOK_Blob NCryptUtil::GetTpmSrk()
{
	NCryptProvHandle hProv;
	DWORD keySize = 0;
	// Get the public endorsement key
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_SRKPUB_PROPERTY, NULL, 0, &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_SRKPUB_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto key = SPOK_Blob::New(keySize);
	status = NCryptGetProperty(hProv, NCRYPT_PCP_SRKPUB_PROPERTY, key.data(), SAFE_CAST_TO_INT32(key.size()), &keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_SRKPUB_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	return key;
}

SPOK_Blob NCryptUtil::GetPcrTable()
{
	NCryptProvHandle hProv;
	DWORD pcrTableSize = 0;
	// Get the PCR table
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_PCRTABLE_PROPERTY, NULL, 0, &pcrTableSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PCRTABLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	auto pcrTable = SPOK_Blob::New(pcrTableSize);
	status = NCryptGetProperty(hProv, NCRYPT_PCP_PCRTABLE_PROPERTY, pcrTable.data(), SAFE_CAST_TO_INT32(pcrTable.size()), &pcrTableSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PCRTABLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	return pcrTable;
}

SPOK_Blob NCryptUtil::GetTbsLog()
{
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	NCryptProvHandle hProv;
	DWORD holder = 0;
	UINT32 neededSize = 0;

	//Get the TSB handle from ncrypt
	HRESULT status = NCryptGetProperty(hProv, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, (PBYTE)&hPlatformTbsHandle, sizeof(hPlatformTbsHandle), &holder, 0);

	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptGetProperty \"NCRYPT_PCP_PLATFORMHANDLE_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	//Get the boot log size
	status = Tbsi_Get_TCG_Log(hPlatformTbsHandle, NULL, &neededSize);

	neededSize++; //appears to be a bug in the TBS API, it returns the size of the buffer needed, but it actually needs the size of the buffer + 1
	auto bootLog = SPOK_Blob::New(neededSize);
	status = Tbsi_Get_TCG_Log(hPlatformTbsHandle, bootLog.data(), &neededSize);

	return bootLog;
}
SPOK_Blob NCryptUtil::GetFilteredTbsLog(uint32_t pcrsToInclude)
{
	auto tsbLog = GetTbsLog();
	auto tcgLog = TcgLog::Parse(tsbLog);
	auto filteredLog = TcgLog::Filter(tcgLog, pcrsToInclude);
	return TcgLog::Serialize(filteredLog);
}

void NCryptUtil::ImportPlatformKey(const SPOK_PlatformKey& platformKey, const SPOK_Blob& key, KeyBlobType type)
{
	NCryptProvHandle hProv;
	NCRYPT_KEY_HANDLE hKey = NULL;

	int flags = NCRYPT_OVERWRITE_KEY_FLAG | (platformKey.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);

	NCryptBuffer keyProperties[] = { {0, NCRYPTBUFFER_PKCS_KEY_NAME, NULL}, {sizeof(BCRYPT_RSA_ALGORITHM), NCRYPTBUFFER_PKCS_ALG_ID, (PBYTE)BCRYPT_RSA_ALGORITHM} };
	NCryptBufferDesc keyParameters = { NCRYPTBUFFER_VERSION, 2, keyProperties };

	auto keyName = platformKey.Name.c_str();
	keyProperties[0].cbBuffer = SAFE_CAST_TO_UINT32((wcslen(keyName) + 1) * sizeof(wchar_t));
	keyProperties[0].pvBuffer = (void*)keyName;

	if (type == KeyBlobType::WRAPPED)
	{
		HRESULT status = NCryptImportKey(hProv, NULL, BCRYPT_OPAQUE_KEY_BLOB, &keyParameters, &hKey, const_cast<uint8_t*>(key.data()), SAFE_CAST_TO_INT32(key.size()), flags);
		if (status != ERROR_SUCCESS)
		{
			auto fmtError = std::format("NCryptImportKey failed with error {}", status);
			SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
		}
		if (hKey != NULL)
		{
			NCryptKeyHandle keyHandle(hKey);
		}
	}
	else
	{
		//TODO: Need to wrap the key in the SRK first...

		auto rsaType = BCryptUtil::RsaKeyType(key);
		keyProperties[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
		keyProperties[1].cbBuffer = SAFE_CAST_TO_UINT32(rsaType.size());
		keyProperties[1].pvBuffer = (void*)rsaType.c_str();

		HRESULT status = NCryptImportKey(hProv, NULL, rsaType.c_str(), &keyParameters, &hKey, const_cast<uint8_t*>(key.data()), SAFE_CAST_TO_INT32(key.size()), flags);
		if (hKey != NULL)
		{
			NCryptKeyHandle keyHandle(hKey);
		}
	}
}

void NCryptUtil::CreatePlatformKey(const SPOK_PlatformKey& platformKey)
{
	NCryptProvHandle hProv;
	NCRYPT_KEY_HANDLE hKey = NULL;
	// Create the key
	long flags = NCRYPT_OVERWRITE_KEY_FLAG | (platformKey.Flag == NCRYPT_MACHINE_KEY::YES ? NCRYPT_MACHINE_KEY_FLAG : 0);
	HRESULT status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, platformKey.Name.c_str(), 0, flags);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptCreatePersistedKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
	// RAII
	NCryptKeyHandle keyHandle(hKey);

	//set the length
	uint32_t keySize = 2048;
	status = NCryptSetProperty(keyHandle, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keySize, sizeof(keySize), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptSetProperty \"NCRYPT_LENGTH_PROPERTY\" failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}

	// Finalize the key
	status = NCryptFinalizeKey(keyHandle, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("NCryptFinalizeKey failed with error {}", status);
		SPOK_THROW_ERROR(SPOK_NCRYPT_FAILURE, fmtError);
	}
}

SPOK_Blob NCryptUtil::Encrypt(const SPOK_PlatformKey& key, const SPOK_Blob& data)
{
	PlatformKey platformKey(key);
	return platformKey.Encrypt(data);
}

SPOK_Blob NCryptUtil::Decrypt(const SPOK_PlatformKey& key, const SPOK_Blob& data)
{
	PlatformKey platformKey(key);
	return platformKey.Decrypt(data);
}

SPOK_Blob NCryptUtil::Sign(const SPOK_PlatformKey& key, const SPOK_Blob& data)
{
	PlatformKey platformKey(key);
	return platformKey.Sign(data);
}

bool NCryptUtil::Verify(const SPOK_PlatformKey& key, const SPOK_Blob& data, const SPOK_Blob& signature)
{
	PlatformKey platformKey(key);
	return platformKey.Verify(data, signature);
}