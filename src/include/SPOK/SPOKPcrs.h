//MIT License
//
//Copyright(c) 2024 noflashbang
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

#pragma once 
#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <iterator>

#include "SPOKCore.h"
#include "SPOKApiTypes.h"
#include "SPOKBlob.h"

#define TPM_PCRS_CNT (24) 
#define TPM_PCRS_MAXSIZE (SHA256_DIGEST_SIZE) // PCRS are SHA1 or SHA256
#define TPM_PCR_TABLE_MAXSIZE (TPM_PCRS_CNT * TPM_PCRS_MAXSIZE)


class SPOK_Pcrs
{
public:
	SPOK_Pcrs(uint8_t digestSize);
	SPOK_Pcrs(SPOK_Blob::Blob blob);

	SPOK_Pcrs(const SPOK_Pcrs& other);
	SPOK_Pcrs& operator=(const SPOK_Pcrs& other);

	~SPOK_Pcrs() = default;

	void FillDefaultPcrs();

	SPOK_Blob::Blob GetBlob() const;

	std::array<uint8_t, TPM_PCRS_MAXSIZE> GetPcr(const uint8_t pcrRegister) const;
	void SetPcr(const uint8_t pcrRegister, const std::array<uint8_t, TPM_PCRS_MAXSIZE>& pcrValue);
	
	std::array<uint8_t, TPM_PCR_TABLE_MAXSIZE> GetPcrTable() const;
	void SetPcrTable(const std::array<uint8_t, TPM_PCR_TABLE_MAXSIZE>& pcrTable);

	uint8_t GetDigestSize() const;
	uint16_t GetAlgId() const;
	uint32_t GetMask() const;

	SPOK_Pcrs GetFiltered(uint32_t mask) const;

private:
	std::array<uint8_t, TPM_PCR_TABLE_MAXSIZE> _pcrTable;
	uint8_t _digestSize;

	const std::array<uint8_t, TPM_PCRS_MAXSIZE> _ZERO_PCR = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	const std::array<uint8_t, TPM_PCRS_MAXSIZE> _ONE_PCR =  { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
};