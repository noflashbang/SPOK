#include "HasherUtil.h"
#include "Util.h"
#include "SPOKError.h"

BCryptHashHandle::BCryptHashHandle(const BCryptAlgHandle& hAlg)
{
	NTSTATUS status = BCryptCreateHash(hAlg, &m_hHash, nullptr, 0, nullptr, 0, 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptHashHandle: BCryptCreateHash failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	ULONG cbOut = 0;
	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&m_HashSize, sizeof(uint32_t), &cbOut, 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptHashHandle: BCryptGetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
}

BCryptHashHandle::BCryptHashHandle(const BCryptAlgHandle& hAlg, SPOK_Blob secret)
{
	m_Secret = secret;
	NTSTATUS status = BCryptCreateHash(hAlg, &m_hHash, nullptr, 0, secret.data(), SAFE_CAST_TO_UINT32(secret.size()), 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptHashHandle: BCryptCreateHash failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	ULONG cbOut = 0;
	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&m_HashSize, sizeof(uint32_t), &cbOut, 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptHashHandle: BCryptGetProperty failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
}

BCryptHashHandle::~BCryptHashHandle()
{
	if (m_hHash)
	{
		BCryptDestroyHash(m_hHash);
	}
}

BCryptHashHandle::operator BCRYPT_HASH_HANDLE() const
{
	return m_hHash;
}

uint32_t BCryptHashHandle::GetHashSize() const
{
	return m_HashSize;
}

HasherUtil::HasherUtil(HasherType type) : m_hAlg((TPM_ALG_ID)type), m_hHash(m_hAlg)
{
}

HasherUtil::HasherUtil(HasherType type, SPOK_Blob secret) : m_hAlg((TPM_ALG_ID)type, true), m_hHash(m_hAlg, secret)
{
}

HasherUtil::~HasherUtil()
{
}

SPOK_Blob HasherUtil::OneShotHash(const SPOK_Blob& data)
{
	HashData(data);
	return FinishHash();
}

void HasherUtil::HashData(const SPOK_Blob& data)
{
	NTSTATUS status = BCryptHashData(m_hHash, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptHashData failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}
}
SPOK_Blob HasherUtil::FinishHash()
{
	uint32_t hashSize = m_hHash.GetHashSize();
	auto hash = SPOK_Blob::New(hashSize);
	NTSTATUS status = BCryptFinishHash(m_hHash, hash.data(), SAFE_CAST_TO_UINT32(hash.size()), 0);
	if (!SUCCEEDED(status))
	{
		auto fmtError = std::format("BCryptFinishHash failed with {}", status);
		SPOK_THROW_ERROR(SPOK_BCRYPT_FAILURE, fmtError);
	}

	return hash;
}

SPOK_Blob Hasher::PublicKeyHash(const SPOK_Blob& keyBlob)
{
	const BCRYPT_RSAKEY_BLOB* pBlob = (const BCRYPT_RSAKEY_BLOB*)keyBlob.data();

	// Extract the modulus and exponent from the BLOB
	std::vector<uint8_t> modulusV(pBlob->cbModulus);
	std::vector<uint8_t> exponentV(pBlob->cbPublicExp);
	memcpy(exponentV.data(), keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB), pBlob->cbPublicExp);
	memcpy(modulusV.data(), keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB) + pBlob->cbPublicExp, pBlob->cbModulus);

	SPOK_Blob encodedKey;
	auto bw = encodedKey.GetWriter();

	std::vector<uint8_t> modulusTL;
	std::vector<uint8_t> exponentTL;
	std::vector<uint8_t> sequenceTL;

	auto modSize = modulusV.size();
	auto expSize = exponentV.size();

	bool modLeading = false;
	auto modulusFirstByte = *modulusV.data();
	if (modSize >= 128 && modulusFirstByte | 0x80)
	{
		modSize++;
		modLeading = true;
	};
	modulusTL.push_back(0x02);
	if (modSize < 128)
	{
		modulusTL.push_back(static_cast<uint8_t>(modSize));
	}
	else if (modSize < 256)
	{
		modulusTL.push_back(0x81);
		modulusTL.push_back(static_cast<uint8_t>(modSize));
	}
	else
	{
		modulusTL.push_back(0x82);
		modulusTL.push_back(static_cast<uint8_t>((modSize >> 8) & 0xFF));
		modulusTL.push_back(static_cast<uint8_t>(modSize & 0xFF));
	}

	bool expLeading = false;
	auto expFirstByte = *exponentV.data();
	if (expSize >= 128 && expFirstByte | 0x80)
	{
		expSize++;
		expLeading = true;
	};
	exponentTL.push_back(0x02);
	if (expSize < 128)
	{
		exponentTL.push_back(static_cast<uint8_t>(expSize));
	}
	else if (expSize < 256)
	{
		exponentTL.push_back(0x81);
		exponentTL.push_back(static_cast<uint8_t>(expSize));
	}
	else
	{
		exponentTL.push_back(0x82);
		exponentTL.push_back(static_cast<uint8_t>((expSize >> 8) & 0xFF));
		exponentTL.push_back(static_cast<uint8_t>(expSize & 0xFF));
	}

	uint16_t length = SAFE_CAST_TO_UINT16((modSize + expSize + exponentTL.size() + modulusTL.size()));

	sequenceTL.push_back(0x30);
	if (length < 128)
	{
		sequenceTL.push_back(static_cast<uint8_t>(length));
	}
	else if (length < 256)
	{
		sequenceTL.push_back(0x81);
		sequenceTL.push_back(static_cast<uint8_t>(length));
	}
	else
	{
		sequenceTL.push_back(0x82);
		sequenceTL.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
		sequenceTL.push_back(static_cast<uint8_t>(length & 0xFF));
	}

	bw.Resize(length + sequenceTL.size());

	// Add the ASN.1 header (sequence tag and length)
	bw.Write(sequenceTL.data(), sequenceTL.size());

	bw.Write(modulusTL.data(), modulusTL.size());
	if (modLeading)
	{
		bw.Write(0x00);
	}
	bw.Write(modulusV.data(), modulusV.size());

	bw.Write(exponentTL.data(), exponentTL.size());
	if (expLeading)
	{
		bw.Write(0x00);
	}
	bw.Write(exponentV.data(), exponentV.size());

	// Hash the encoded key
	HasherUtil hasher(HasherType::SHA256);
	return hasher.OneShotHash(encodedKey);
}

SPOK_Nonce::Nonce Hasher::Blob2Nonce(const SPOK_Blob& blob)
{
	HasherUtil hasher(HasherType::SHA1);
	auto hash = hasher.OneShotHash(blob);
	return SPOK_Nonce::Make(hash.data(), hash.size());
}

HasherUtil Hasher::Create(uint16_t algId)
{
	if (algId == 0x0004)
	{
		return HasherUtil(HasherType::SHA1);
	}
	else if (algId == 0x000B)
	{
		return HasherUtil(HasherType::SHA256);
	}
	else if (algId == 0x000C)
	{
		return HasherUtil(HasherType::SHA384);
	}
	else if (algId == 0x000D)
	{
		return HasherUtil(HasherType::SHA512);
	}
	else
	{
		auto fmtError = std::format("Hasher::Create: Unsupported hash algorithm {}", algId);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}
}

HasherUtil Hasher::Create_HMAC(uint16_t algId, SPOK_Blob secret)
{
	if (algId == 0x0004)
	{
		return HasherUtil(HasherType::SHA1, secret);
	}
	else if (algId == 0x000B)
	{
		return HasherUtil(HasherType::SHA256, secret);
	}
	else if (algId == 0x000C)
	{
		return HasherUtil(HasherType::SHA384, secret);
	}
	else if (algId == 0x000D)
	{
		return HasherUtil(HasherType::SHA512, secret);
	}
	else
	{
		auto fmtError = std::format("Hasher::Create_HMAC: Unsupported hash algorithm {}", algId);
		SPOK_THROW_ERROR(SPOK_INVALID_ALGORITHM, fmtError);
	}
}