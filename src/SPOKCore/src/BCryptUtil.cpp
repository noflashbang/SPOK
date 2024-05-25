#include "BCryptUtil.h"
#include <ncrypt.h>
#include "Util.h"
#include "SPOKError.h"

BCryptAlgHandle::BCryptAlgHandle(TPM_ALG_ID alg) : m_hAlg(NULL), m_algId(alg)
{
	NTSTATUS status;
	switch (alg)
	{
	case TPM_ALG_ID::TPM_ALG_RNG:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_RSA:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA1:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA256:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA384:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA384_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA512:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA512_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_AES:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
		break;
	}
	default:
	{
		auto fmtError = std::format("BCryptAlgHandle: Unknown algorithm id {}", (uint16_t)alg);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}
	}

	if (status != ERROR_SUCCESS)
	{
		auto name = Name();
		auto fmtError = std::format("BCryptOpenAlgorithmProvider failed for algorithm {} with error {}", name, status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
}

BCryptAlgHandle::BCryptAlgHandle(TPM_ALG_ID alg, bool hmacFlag) : m_hAlg(NULL), m_algId(alg)
{
	NTSTATUS status;
	switch (alg)
	{
	case TPM_ALG_ID::TPM_ALG_SHA1:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, hmacFlag ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA256:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, hmacFlag ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA384:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA384_ALGORITHM, MS_PRIMITIVE_PROVIDER, hmacFlag ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
		break;
	}
	case TPM_ALG_ID::TPM_ALG_SHA512:
	{
		status = BCryptOpenAlgorithmProvider(&m_hAlg, BCRYPT_SHA512_ALGORITHM, MS_PRIMITIVE_PROVIDER, hmacFlag ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
		break;
	}
	default:
	{
		auto fmtError = std::format("BCryptAlgHandle: Unknown algorithm id {}", (uint16_t)alg);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}
	}

	if (status != ERROR_SUCCESS)
	{
		auto name = Name();
		auto fmtError = std::format("BCryptOpenAlgorithmProvider failed for algorithm {} with error {}", name, status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
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
	case TPM_ALG_ID::TPM_ALG_RSA:
	{
		return "RSA";
	}
	case TPM_ALG_ID::TPM_ALG_SHA1:
	{
		return "SHA1";
	}
	case TPM_ALG_ID::TPM_ALG_SHA256:
	{
		return "SHA256";
	}
	case TPM_ALG_ID::TPM_ALG_SHA384:
	{
		return "SHA384";
	}
	case TPM_ALG_ID::TPM_ALG_SHA512:
	{
		return "SHA512";
	}
	default:
	{
		auto fmtError = std::format("BCryptAlgHandle: Unknown algorithm id {}", (uint16_t)m_algId);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}
	}
}

BCryptKey::BCryptKey(SPOK_Blob keyBlob) : m_hAlg(TPM_ALG_ID::TPM_ALG_RSA)
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

BCryptKey::BCryptKey(const BCRYPT_KEY_HANDLE& hKey) : m_hAlg(TPM_ALG_ID::TPM_ALG_RSA), m_hKey(hKey)
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

SPOK_Blob BCryptKey::GetPublicKey()
{
	DWORD keyBlobSize = 0;
	HRESULT status = BCryptExportKey(m_hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GetPublicKey: BCryptExportKey failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto keyBlob = SPOK_Blob::New(keyBlobSize);
	status = BCryptExportKey(m_hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, keyBlob.data(), SAFE_CAST_TO_UINT32(keyBlob.size()), &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GetPublicKey: BCryptExportKey failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
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
		auto fmtError = std::format("KeySize: BCryptGetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
	return SAFE_CAST_TO_UINT16(keySize);
}

uint16_t BCryptKey::BlockLength() const
{
	DWORD blockLength = 0;
	DWORD cbData = 0;
	HRESULT status = BCryptGetProperty(m_hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockLength, sizeof(blockLength), &cbData, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("BlockLength: BCryptGetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
	return SAFE_CAST_TO_UINT16(blockLength);
}

uint16_t BCryptKey::MaxMessage() const
{
	uint16_t keySize = KeySize();
	uint16_t maxMessage = (keySize / 8) - 62; // OAEP padding
	return maxMessage;
}

SPOK_Blob BCryptKey::Encrypt(const SPOK_Blob& data, bool useIdentity)
{
	if (data.size() > MaxMessage())
	{
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, std::format("Data too large to encrypt -> Max {} bytes, got {} bytes", MaxMessage(), data.size()));
	}

	DWORD dataSize = 0;

	//OAEP padding
	uint8_t* szLabel = (uint8_t*)"DUPLICATE";
	DWORD cbLabel = 10;

	if (useIdentity)
	{
		szLabel = (uint8_t*)"IDENTITY";
		cbLabel = 9;
	}

	auto paddingInfo = BCRYPT_OAEP_PADDING_INFO{ BCRYPT_SHA256_ALGORITHM, szLabel, cbLabel };

	// Encrypt the data
	HRESULT status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, NULL, NULL, &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Encrypt: BCryptEncrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto encryptedData = SPOK_Blob::New(dataSize);
	status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, encryptedData.data(), SAFE_CAST_TO_UINT32(encryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Encrypt: BCryptEncrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	return encryptedData;
}
SPOK_Blob BCryptKey::Decrypt(const SPOK_Blob& data)
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
		auto fmtError = std::format("Decrypt: BCryptDecrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto decryptedData = SPOK_Blob::New(dataSize);
	status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), &paddingInfo, NULL, 0, decryptedData.data(), SAFE_CAST_TO_UINT32(decryptedData.size()), &dataSize, BCRYPT_PAD_OAEP);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Decrypt: BCryptDecrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	return decryptedData;
}

void  BCryptKey::SetSignHashAlg(uint16_t algId)
{
	m_signHashAlg = algId;
}

SPOK_Blob BCryptKey::Sign(const SPOK_Blob& hash)
{
	if (hash.size() > MaxMessage())
	{
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, std::format("Data too large to sign -> Max {} bytes, got {} bytes", MaxMessage(), hash.size()));
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
		auto fmtError = std::format("Sign: Unknown algorithm id {}", (uint16_t)m_signHashAlg);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}

	DWORD signatureSize = 0;
	HRESULT status = BCryptSignHash(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), NULL, 0, &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Sign: BCryptSignHash failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto signature = SPOK_Blob::New(signatureSize);

	status = BCryptSignHash(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), signature.data(), SAFE_CAST_TO_UINT32(signature.size()), &signatureSize, BCRYPT_PAD_PKCS1);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Sign: BCryptSignHash failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	return signature;
}
bool BCryptKey::Verify(const SPOK_Blob& hash, const SPOK_Blob& signature)
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
		auto fmtError = std::format("Verify: Unknown algorithm id {}", (uint16_t)m_signHashAlg);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}

	HRESULT status = BCryptVerifySignature(m_hKey, &padInfo, const_cast<uint8_t*>(hash.data()), SAFE_CAST_TO_UINT32(hash.size()), const_cast<uint8_t*>(signature.data()), SAFE_CAST_TO_UINT32(signature.size()), BCRYPT_PAD_PKCS1);
	if (status != NTE_BAD_SIGNATURE && SUCCEEDED(status))
	{
		return true;
	}

	return false;
}

SymmetricCipher::SymmetricCipher(const SPOK_Blob& key, const std::wstring& alg, const std::wstring& mode, const SPOK_Blob& iv) : m_hAlg(TPM_ALG_ID::TPM_ALG_AES), m_hKey(NULL), m_iv(iv)
{
	if (alg != BCRYPT_AES_ALGORITHM)
	{
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, "SymmetricCipher: Invalid algorithm - must be AES");
	}
	if (mode != BCRYPT_CHAIN_MODE_CFB) //only supporting CFB mode for now
	{
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, "SymmetricCipher: Invalid mode - must be CFB");
	}

	NTSTATUS status = BCryptGenerateSymmetricKey(m_hAlg, &m_hKey, NULL, 0, const_cast<uint8_t*>(key.data()), SAFE_CAST_TO_UINT32(key.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("SymmetricCipher: BCryptGenerateSymmetricKey failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	//set chaining mode
	status = BCryptSetProperty(m_hKey, BCRYPT_CHAINING_MODE, (PUCHAR)mode.c_str(), SAFE_CAST_TO_UINT32(mode.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("SymmetricCipher: BCryptSetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	//set block length
	DWORD blockLength = 16;
	status = BCryptSetProperty(m_hKey, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&blockLength, sizeof(blockLength), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("SymmetricCipher: BCryptSetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
}
SymmetricCipher::~SymmetricCipher()
{
}
SymmetricCipher::operator BCRYPT_KEY_HANDLE() const
{
	return m_hKey;
}

SPOK_Blob SymmetricCipher::Encrypt(const SPOK_Blob& data)
{
	DWORD dataSize = 0;
	NTSTATUS status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), NULL, const_cast<uint8_t*>(m_iv.data()), SAFE_CAST_TO_UINT32(m_iv.size()), NULL, 0, &dataSize, BCRYPT_BLOCK_PADDING);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Encrypt: BCryptEncrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto encryptedData = SPOK_Blob::New(dataSize);
	status = BCryptEncrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), NULL, const_cast<uint8_t*>(m_iv.data()), SAFE_CAST_TO_UINT32(m_iv.size()), encryptedData.data(), SAFE_CAST_TO_UINT32(encryptedData.size()), &dataSize, BCRYPT_BLOCK_PADDING);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Encrypt: BCryptEncrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	return encryptedData;
}
SPOK_Blob SymmetricCipher::Decrypt(const SPOK_Blob& data)
{
	DWORD dataSize = 0;
	NTSTATUS status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), NULL, const_cast<uint8_t*>(m_iv.data()), SAFE_CAST_TO_UINT32(m_iv.size()), NULL, 0, &dataSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Decrypt: BCryptDecrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto decryptedData = SPOK_Blob::New(dataSize);
	status = BCryptDecrypt(m_hKey, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), NULL, const_cast<uint8_t*>(m_iv.data()), SAFE_CAST_TO_UINT32(m_iv.size()), decryptedData.data(), SAFE_CAST_TO_UINT32(decryptedData.size()), &dataSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("Decrypt: BCryptDecrypt failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);;
	}

	return decryptedData;
}

std::wstring BCryptUtil::RsaKeyType(const SPOK_Blob& keyBlob)
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
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, "Invalid RSA key blob");
	}
}

BCryptKey BCryptUtil::Open(const SPOK_Blob& keyBlob)
{
	return BCryptKey(keyBlob);
}

SPOK_Blob BCryptUtil::GenerateRsaKeyPair(const KeySize keySize)
{
	BCryptAlgHandle hAlg(TPM_ALG_ID::TPM_ALG_RSA);
	BCRYPT_KEY_HANDLE hKey;

	NTSTATUS status = BCryptGenerateKeyPair(hAlg, &hKey, (uint32_t)keySize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GenerateRsaKeyPair: BCryptGenerateKeyPair failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	BCryptKey key(hKey); // RAII

	status = BCryptFinalizeKeyPair(key, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GenerateRsaKeyPair: BCryptFinalizeKeyPair failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	DWORD keyBlobSize = 0;
	status = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GenerateRsaKeyPair: BCryptExportKey failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	auto keyBlob = SPOK_Blob::New(keyBlobSize);
	status = BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, keyBlob.data(), SAFE_CAST_TO_UINT32(keyBlob.size()), &keyBlobSize, 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GenerateRsaKeyPair: BCryptExportKey failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
	return keyBlob;
}

SPOK_Blob BCryptUtil::GetRandomBytes(const uint32_t size)
{
	BCryptAlgHandle hAlg(TPM_ALG_ID::TPM_ALG_RNG);
	auto randomBytes = SPOK_Blob::New(size);
	NTSTATUS status = BCryptGenRandom(hAlg, randomBytes.data(), SAFE_CAST_TO_UINT32(randomBytes.size()), 0);
	if (status != ERROR_SUCCESS)
	{
		auto fmtError = std::format("GetRandomBytes: BCryptGenRandom failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
	return randomBytes;
}

SPOK_Nonce::Nonce BCryptUtil::GetRandomNonce()
{
	return SPOK_Nonce::Make(GetRandomBytes(20));
}

SymmetricCipher BCryptUtil::CreateSymmetricCipher(const SPOK_Blob& key, const std::wstring& alg, const std::wstring& mode, const SPOK_Blob& iv)
{
	return SymmetricCipher(key, alg, mode, iv);
}