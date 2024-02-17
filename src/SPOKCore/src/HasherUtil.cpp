#include "HasherUtil.h"
#include "Util.h"


BCryptHashHandle::BCryptHashHandle(BCryptAlgHandle hAlg)
{
	NTSTATUS status = BCryptCreateHash(hAlg, &m_hHash, nullptr, 0, nullptr, 0, 0);
	if (!SUCCEEDED(status))
	{
		throw std::runtime_error("BCryptCreateHash failed");
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


HasherUtil::HasherUtil(HasherType type) : m_hAlg((AlgId)type), m_hHash(m_hAlg)
{
}

HasherUtil::~HasherUtil()
{
}

SPOK_Blob::Blob HasherUtil::OneShotHash(const SPOK_Blob::Blob& data)
{
	HashData(data);
	return FinishHash();
}

void HasherUtil::HashData(const SPOK_Blob::Blob& data)
{
	NTSTATUS status = BCryptHashData(m_hHash, const_cast<uint8_t*>(data.data()), SAFE_CAST_TO_UINT32(data.size()), 0);
	if (!SUCCEEDED(status))
	{
		throw std::runtime_error("BCryptHashData failed");
	}
}
SPOK_Blob::Blob HasherUtil::FinishHash()
{
	ULONG cbOut = 0;
	ULONG hashSize = 0;
	NTSTATUS status = BCryptGetProperty(m_hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize, sizeof(hashSize), &cbOut, 0);
	if (!SUCCEEDED(status))
	{
		throw std::runtime_error("BCryptGetProperty failed");
	}

	auto hash = SPOK_Blob::New(hashSize);
	status = BCryptFinishHash(m_hHash, hash.data(), SAFE_CAST_TO_UINT32(hash.size()), 0);
	if (!SUCCEEDED(status))
	{
		throw std::runtime_error("BCryptFinishHash failed");
	}

	return hash;
}

SPOK_Blob::Blob Hasher::PublicKeyHash(const SPOK_Blob::Blob& keyBlob)
{
	const BCRYPT_RSAKEY_BLOB* pBlob = (const BCRYPT_RSAKEY_BLOB*)keyBlob.data();

	// Extract the modulus and exponent from the BLOB
	std::vector<uint8_t> modulus(pBlob->cbModulus);
	std::vector<uint8_t> exponent(pBlob->cbPublicExp);
	memcpy(modulus.data(), keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB), pBlob->cbModulus);
	memcpy(exponent.data(), keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB) + pBlob->cbModulus, pBlob->cbPublicExp);

	SPOK_Blob::Blob encodedKey;

	// Add the ASN.1 header (sequence tag and length)
	encodedKey.push_back(0x30); // Sequence tag
	int length = modulus.size() + exponent.size() + 2;
	//encodedKey.push_back(static_cast<uint8_t>(modulus.size() + exponent.size() + 2)); // Length

	// Add the modulus (integer tag and length)
	encodedKey.push_back(0x02); // Integer tag
	int modLength = modulus.size();
	//encodedKey.push_back(static_cast<uint8_t>(modulus.size()));
	encodedKey.insert(encodedKey.end(), modulus.begin(), modulus.end());

	// Add the exponent (integer tag and length)
	encodedKey.push_back(0x02); // Integer tag
	int expLength = exponent.size();
	//encodedKey.push_back(static_cast<uint8_t>(exponent.size()));
	encodedKey.insert(encodedKey.end(), exponent.begin(), exponent.end());

	// Hash the encoded key
	HasherUtil hasher(HasherType::SHA256);
	return hasher.OneShotHash(encodedKey);
}