#include "BCryptUtil.h"
#include <ncrypt.h>
#include "Util.h"

BCryptAlgHandle::BCryptAlgHandle()
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptOpenStorageProvider failed");
	}
}

BCryptAlgHandle::~BCryptAlgHandle()
{
	if (m_hAlg != NULL)
	{
		BCryptCloseAlgorithmProvider(m_hAlg, 0);
		m_hAlg = NULL;
	}
}

BCryptAlgHandle::operator BCRYPT_ALG_HANDLE() const
{
	return m_hAlg;
}

BCryptKey::BCryptKey(SPOK_Blob::Blob keyBlob)
{
	BCRYPT_KEY_HANDLE hKey;
	// Open the key
	auto type = BCryptUtil::RsaKeyType(keyBlob);
	HRESULT status = BCryptImportKeyPair(m_hAlg, NULL, type.c_str(), &hKey, keyBlob.data(), SAFE_CAST_TO_ULONG(keyBlob.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		m_hKey = NULL;
	}
	else
	{
		m_hKey = hKey;
	}
}

BCryptKey::BCryptKey(const BCRYPT_KEY_HANDLE& hKey) : m_hKey(hKey)
{
}

BCryptKey::~BCryptKey()
{
	if (m_hKey != NULL)
	{
		BCryptDestroyKey(m_hKey);
		m_hKey = NULL;
	}
}

BCryptKey::operator BCRYPT_KEY_HANDLE() const
{
	return m_hKey;
}


SPOK_Blob::Blob BCryptKey::Encrypt(const SPOK_Blob::Blob& data)
{
	DWORD dataSize = 0;

	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;

	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	// Encrypt the data
	HRESULT status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), &paddingInfo, NULL, 0, NULL, NULL, &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptEncrypt failed");
	}

	auto encryptedData = SPOK_Blob::New(dataSize);
	status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), &paddingInfo, NULL, 0, encryptedData.data(), SAFE_CAST_TO_ULONG(encryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("NCryptEncrypt failed");
	}

	return encryptedData;

}
SPOK_Blob::Blob BCryptKey::Decrypt(const SPOK_Blob::Blob& data)
{
	DWORD dataSize = 0;

	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;

	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	// Decrypt the data
	HRESULT status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), &paddingInfo, NULL, 0, NULL, 0, &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptDecrypt failed");
	}

	auto decryptedData = SPOK_Blob::New(dataSize);
	status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), &paddingInfo, NULL, 0, decryptedData.data(), SAFE_CAST_TO_ULONG(decryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptDecrypt failed");
	}

	return decryptedData;

}
SPOK_Blob::Blob BCryptKey::Sign(const SPOK_Blob::Blob& data)
{
	auto signature = SPOK_Blob::New(SHA256_DIGEST_SIZE);

	BCRYPT_PKCS1_PADDING_INFO padInfo;
	padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
	DWORD signatureSize = 0;

	HRESULT status = BCryptSignHash(m_hKey, &padInfo, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), signature.data(), SAFE_CAST_TO_ULONG(signature.size()), &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptSignHash failed");
	}

	return signature;

}
bool BCryptKey::Verify(const SPOK_Blob::Blob& data, const SPOK_Blob::Blob& signature)
{
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;

	HRESULT status = BCryptVerifySignature(m_hKey, &padInfo, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_ULONG(data.size()), const_cast<uint8_t*>(signature.data()), SAFE_CAST_TO_ULONG(signature.size()), BCRYPT_PAD_PKCS1);
	if (status != NTE_BAD_SIGNATURE && SUCCEEDED(status))
	{
		return true;
	}

	return false;
}



std::wstring BCryptUtil::RsaKeyType(const SPOK_Blob::Blob keyBlob)
{
	const BCRYPT_RSAKEY_BLOB* pBlob = (const BCRYPT_RSAKEY_BLOB*)keyBlob.data();
	if (pBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC)
	{
		return BCRYPT_RSAPUBLIC_BLOB;
	}
	else if (pBlob->Magic == BCRYPT_RSAPRIVATE_MAGIC)
	{
		return BCRYPT_RSAPRIVATE_BLOB;
	}
	else
	{
		throw std::runtime_error("Invalid RSA key blob");
	}
}

BCryptKey BCryptUtil::Open(SPOK_Blob::Blob keyBlob)
{
	return BCryptKey(keyBlob);
}

SPOK_Blob::Blob BCryptUtil::GenerateRsaKeyPair(KeySize keySize)
{
	BCryptAlgHandle hAlg;
	BCRYPT_KEY_HANDLE hKey;

	NTSTATUS status = BCryptGenerateKeyPair(hAlg, &hKey, (uint32_t)keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptGenerateKeyPair failed");
	}

	BCryptKey key(hKey); // RAII

	status = BCryptFinalizeKeyPair(key, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptFinalizeKeyPair failed");
	}

	DWORD keyBlobSize = 0;
	status = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptExportKey failed");
	}

	auto keyBlob = SPOK_Blob::New(keyBlobSize);
	status = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, keyBlob.data(), SAFE_CAST_TO_ULONG(keyBlob.size()), &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptExportKey failed");
	}
	return keyBlob;
}