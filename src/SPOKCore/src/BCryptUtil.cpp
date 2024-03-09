#include "BCryptUtil.h"
#include <ncrypt.h>
#include "Util.h"

BCryptAlgHandle::BCryptAlgHandle(AlgId alg) : m_hAlg(NULL), m_algId(alg)
{
	NTSTATUS status;
	switch (alg)
	{
		case AlgId::RNG:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
			break;
		}
		case AlgId::RSA:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
			break;
		}
		case AlgId::SHA1:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
			break;
		}
		case AlgId::SHA256:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
			break;
		}
		case AlgId::SHA384:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA384_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
			break;

		}
		case AlgId::SHA512:
		{
			status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA512_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
			break;
		}
		default:
		{
			throw std::runtime_error("Invalid algorithm");
		}
	}

	if (status != ERROR_SUCCESS)
	{
		auto name = Name();
		auto fmtError = std::format("BCryptOpenAlgorithmProvider failed for algorithm {} with error {}", name, status);
		throw std::runtime_error(fmtError);
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

std::string BCryptAlgHandle::Name() const
{
	switch (m_algId)
	{
		case AlgId::RSA:
		{
			return "RSA";
		}
		case AlgId::SHA1:
		{
			return "SHA1";
		}
		case AlgId::SHA256:
		{
			return "SHA256";
		}
		case AlgId::SHA384:
		{
			return "SHA384";
		}
		case AlgId::SHA512:
		{
			return "SHA512";
		}
		default:
		{
			throw std::runtime_error("Invalid algorithm");
		}
	}
}


BCryptKey::BCryptKey(SPOK_Blob::Blob keyBlob) : m_hAlg(AlgId::RSA)
{
	BCRYPT_KEY_HANDLE hKey;
	// Open the key
	auto type = BCryptUtil::RsaKeyType(keyBlob);
	HRESULT status = BCryptImportKeyPair(m_hAlg, NULL, type.c_str(), &hKey, keyBlob.data(), SAFE_CAST_TO_UINT32(keyBlob.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		m_hKey = NULL;
	}
	else
	{
		m_hKey = hKey;
	}
}

BCryptKey::BCryptKey(const BCRYPT_KEY_HANDLE& hKey) : m_hAlg(AlgId::RSA), m_hKey(hKey)
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

SPOK_Blob::Blob BCryptKey::GetPublicKey()
{
	DWORD keyBlobSize = 0;
	HRESULT status = BCryptExportKey(m_hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptExportKey failed");
	}

	auto keyBlob = SPOK_Blob::New(keyBlobSize);
	status = BCryptExportKey(m_hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, keyBlob.data(), SAFE_CAST_TO_UINT32(keyBlob.size()), &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptExportKey failed");
	}
	return keyBlob;
}

uint16_t BCryptKey::KeySize() const
{
	DWORD keySize = 0;
	DWORD cbData = 0;
	HRESULT status = BCryptGetProperty(m_hKey, BCRYPT_KEY_LENGTH, (PUCHAR)&keySize, sizeof(keySize), &cbData, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptGetProperty failed");
	}
	return keySize;
}

uint16_t BCryptKey::MaxMessage() const
{
	uint16_t keySize = KeySize();
	uint16_t maxMessage = (keySize / 8) - 62; // OAEP padding
	return maxMessage;
}

SPOK_Blob::Blob BCryptKey::Encrypt(const SPOK_Blob::Blob& data)
{
	if (data.size() > MaxMessage())
	{
		throw std::runtime_error(std::format("Data too large to encrypt -> Max {} bytes, got {} bytes", MaxMessage(), data.size()));
	}

	DWORD dataSize = 0;

	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;

	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	// Encrypt the data
	HRESULT status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, NULL, NULL, &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptEncrypt failed");
	}

	auto encryptedData = SPOK_Blob::New(dataSize);
	status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, encryptedData.data(), SAFE_CAST_TO_UINT32(encryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
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
	HRESULT status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, NULL, 0, &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptDecrypt failed");
	}

	auto decryptedData = SPOK_Blob::New(dataSize);
	status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, decryptedData.data(), SAFE_CAST_TO_UINT32(decryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptDecrypt failed");
	}

	return decryptedData;

}

void  BCryptKey::SetSignHashAlg(uint16_t algId)
{
	m_signHashAlg = algId;
}

SPOK_Blob::Blob BCryptKey::Sign(const SPOK_Blob::Blob& hash)
{
	if (hash.size() > MaxMessage())
	{
		throw std::runtime_error(std::format("Data too large to sign -> Max {} bytes, got {} bytes", MaxMessage(), hash.size()));
	}
	
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	if (m_signHashAlg == 0x0004)
	{
		padInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000B)
	{
		padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000C)
	{
		padInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000D)
	{
		padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
	}
	else
	{
		throw std::runtime_error("Invalid hash algorithm");
	}

	DWORD signatureSize = 0;
	HRESULT status = BCryptSignHash(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), NULL, 0, &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptSignHash failed");
	}

	auto signature = SPOK_Blob::New(signatureSize);

	status = BCryptSignHash(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), signature.data(), SAFE_CAST_TO_UINT32(signature.size()), &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptSignHash failed");
	}

	return signature;

}
bool BCryptKey::Verify(const SPOK_Blob::Blob& hash, const SPOK_Blob::Blob& signature)
{
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	if (m_signHashAlg == 0x0004)
	{
		padInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000B)
	{
		padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000C)
	{
		padInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM;
	}
	else if (m_signHashAlg == 0x000D)
	{
		padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
	}
	else
	{
		throw std::runtime_error("Invalid hash algorithm");
	}

	HRESULT status = BCryptVerifySignature(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), const_cast<uint8_t*>(signature.data()), SAFE_CAST_TO_UINT32(signature.size()), BCRYPT_PAD_PKCS1);
	if (status != NTE_BAD_SIGNATURE && SUCCEEDED(status))
	{
		return true;
	}

	return false;
}

std::wstring BCryptUtil::RsaKeyType(const SPOK_Blob::Blob& keyBlob)
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

BCryptKey BCryptUtil::Open(SPOK_Blob::Blob& keyBlob)
{
	return BCryptKey(keyBlob);
}

SPOK_Blob::Blob BCryptUtil::GenerateRsaKeyPair(KeySize keySize)
{
	BCryptAlgHandle hAlg(AlgId::RSA);
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
	status = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, keyBlob.data(), SAFE_CAST_TO_UINT32(keyBlob.size()), &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptExportKey failed");
	}
	return keyBlob;
}

SPOK_Blob::Blob BCryptUtil::GetRandomBytes(uint32_t size)
{
	BCryptAlgHandle hAlg(AlgId::RNG);
	auto randomBytes = SPOK_Blob::New(size);
	NTSTATUS status = BCryptGenRandom(hAlg, randomBytes.data(), SAFE_CAST_TO_UINT32(randomBytes.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("BCryptGenRandom failed");
	}
	return randomBytes;
}

SPOK_Nonce::Nonce BCryptUtil::GetRandomNonce()
{
	return SPOK_Nonce::Make(GetRandomBytes(20));
}