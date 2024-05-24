#include "SPOKPcrs.h"
#include "Util.h"
#include <TPM_20.h>
#include <format>
#include "SPOKError.h"

SPOK_Pcrs::SPOK_Pcrs(uint8_t digestSize) : _digestSize(digestSize)
{
	std::fill(_pcrTable.begin(), _pcrTable.end(), 0); //zero out the table
	FillDefaultPcrs();
}

SPOK_Pcrs::SPOK_Pcrs(SPOK_Blob::Blob blob)
{
	std::fill(_pcrTable.begin(), _pcrTable.end(), 0); //zero out the table

	auto size = blob.size();
	auto hashSize = size / TPM_PCRS_CNT;
	_digestSize = SAFE_CAST_TO_UINT8(hashSize);
	for (int i = 0; i < TPM_PCRS_CNT; i++)
	{
		std::copy(blob.begin() + (i * hashSize), blob.begin() + ((i + 1) * hashSize), _pcrTable.begin() + (i * hashSize));
	}
}

SPOK_Pcrs::SPOK_Pcrs(const SPOK_Pcrs& other)
{
	_digestSize = other._digestSize;
	std::copy(other._pcrTable.begin(), other._pcrTable.end(), _pcrTable.begin());
}

SPOK_Pcrs& SPOK_Pcrs::operator=(const SPOK_Pcrs& other)
{
	if (this != &other)
	{
		_digestSize = other._digestSize;
		std::copy(other._pcrTable.begin(), other._pcrTable.end(), _pcrTable.begin());
	}
	return *this;
}

void SPOK_Pcrs::FillDefaultPcrs()
{
	for (uint32_t pcrIndex = 0; pcrIndex < TPM_PCRS_CNT; pcrIndex++)
	{
		std::vector<uint8_t> pcrValue(_digestSize);
		if (pcrIndex <= 15 || pcrIndex >= TPM_PCRS_CNT)
		{
			std::copy(_ZERO_PCR.begin(), _ZERO_PCR.begin() + _digestSize, _pcrTable.begin() + (pcrIndex * _digestSize));
		}
		else
		{
			std::copy(_ONE_PCR.begin(), _ONE_PCR.begin() + _digestSize, _pcrTable.begin() + (pcrIndex * _digestSize));
		}
	}
}

SPOK_Blob::Blob SPOK_Pcrs::GetBlob() const
{
	SPOK_Blob::Blob blob;
	std::copy(_pcrTable.begin(), _pcrTable.end(), std::back_inserter(blob));
	return blob;
}

std::array<uint8_t, TPM_PCRS_MAXSIZE> SPOK_Pcrs::GetPcr(const uint8_t pcrRegister) const
{
	if (pcrRegister >= TPM_PCRS_CNT)
	{
		auto fmtError = std::format("Invalid PCR Register: {}", pcrRegister);
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	std::array<uint8_t, TPM_PCRS_MAXSIZE> pcrValue;
	std::copy(_pcrTable.begin() + (pcrRegister * _digestSize), _pcrTable.begin() + ((pcrRegister + 1) * _digestSize), pcrValue.begin());
	return pcrValue;
}

void SPOK_Pcrs::SetPcr(const uint8_t pcrRegister, const std::array<uint8_t, TPM_PCRS_MAXSIZE>& pcrValue)
{
	if (pcrRegister >= TPM_PCRS_CNT)
	{
		auto fmtError = std::format("Invalid PCR Register: {}", pcrRegister);
		SPOK_THROW_ERROR(SPOK_INVALID_DATA, fmtError);
	}

	std::copy(pcrValue.begin(), pcrValue.end(), _pcrTable.begin() + (pcrRegister * _digestSize));
}
std::array<uint8_t, TPM_PCR_TABLE_MAXSIZE> SPOK_Pcrs::GetPcrTable() const
{
	return _pcrTable;
}
void SPOK_Pcrs::SetPcrTable(const std::array<uint8_t, TPM_PCR_TABLE_MAXSIZE>& pcrTable)
{
	std::copy(pcrTable.begin(), pcrTable.end(), _pcrTable.begin());
}
uint8_t SPOK_Pcrs::GetDigestSize() const
{
	return _digestSize;
}

uint16_t SPOK_Pcrs::GetAlgId() const
{
	if (_digestSize == SHA256_DIGEST_SIZE)
	{
		return TPM_API_ALG_ID_SHA256;
	}
	return TPM_API_ALG_ID_SHA1;
}

uint32_t SPOK_Pcrs::GetMask() const
{
	uint32_t mask = 0;
	for (uint32_t pcrIndex = 0; pcrIndex < TPM_PCRS_CNT; pcrIndex++)
	{
		auto pcrValue = GetPcr(pcrIndex);
		if ((pcrIndex <= 15 || pcrIndex >= TPM_PCRS_CNT))
		{
			if (!std::all_of(pcrValue.begin(), pcrValue.end(), [](uint8_t i) { return i == 0x00; }))
			{
				mask |= (1 << pcrIndex);
			}
		}
		else
		{
			if (!std::all_of(pcrValue.begin(), pcrValue.end(), [](uint8_t i) { return i == 0xFF; }))
			{
				mask |= (1 << pcrIndex);
			}
		}
	}
	return mask;
}

SPOK_Pcrs SPOK_Pcrs::GetFiltered(uint32_t mask) const
{
	SPOK_Pcrs filteredPcrs(_digestSize);
	for (uint32_t pcrIndex = 0; pcrIndex < TPM_PCRS_CNT; pcrIndex++)
	{
		if (mask & (1 << pcrIndex))
		{
			auto pcrValue = GetPcr(pcrIndex);
			filteredPcrs.SetPcr(pcrIndex, pcrValue);
		}
	}
	return filteredPcrs;
}