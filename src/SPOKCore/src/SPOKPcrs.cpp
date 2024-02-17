#include "SPOKPcrs.h"
#include "Util.h"


SPOK_Pcrs::SPOK_Pcrs(uint8_t digestSize) : _digestSize(digestSize)
{
	std::fill(_pcrTable.begin(), _pcrTable.end(), 0);
}

SPOK_Pcrs::SPOK_Pcrs(SPOK_Blob::Blob blob)
{
	auto size = blob.size();
	auto hashSize = size / TPM_PCRS_CNT;
	_digestSize = SAFE_CAST_TO_UINT8(hashSize);
	for (int i = 0; i < TPM_PCRS_CNT; i++)
	{
		std::copy(blob.begin() + (i * hashSize), blob.begin() + ((i + 1) * hashSize), _pcrTable.begin() + (i * hashSize));
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
	std::array<uint8_t, TPM_PCRS_MAXSIZE> pcrValue;
	std::copy(_pcrTable.begin() + (pcrRegister * _digestSize), _pcrTable.begin() + ((pcrRegister + 1) * _digestSize), pcrValue.begin());
	return pcrValue;
}
void SPOK_Pcrs::SetPcr(const uint8_t pcrRegister, const std::array<uint8_t, TPM_PCRS_MAXSIZE>& pcrValue)
{
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