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
#include <string>

#include "SPOKApiTypes.h"


#define SHA1_DIGEST_SIZE (20)
#define SHA256_DIGEST_SIZE (32)

#ifndef TPM_VERSION_12
#define TPM_VERSION_12 0x00010000
#endif

#ifndef TPM_VERSION_20
#define TPM_VERSION_20 0x00020000
#endif

#ifndef PCR_0
#define PCR_0  (0x00000001)
#define PCR_1  (0x00000002)
#define PCR_2  (0x00000004)
#define PCR_3  (0x00000008)
#define PCR_4  (0x00000010)
#define PCR_5  (0x00000020)
#define PCR_6  (0x00000040)
#define PCR_7  (0x00000080)
#define PCR_8  (0x00000100)
#define PCR_9  (0x00000200)
#define PCR_10 (0x00000400)
#define PCR_11 (0x00000800)
#define PCR_12 (0x00001000)
#define PCR_13 (0x00002000)
#define PCR_14 (0x00004000)
#define PCR_15 (0x00008000)
#define PCR_16 (0x00010000)
#define PCR_17 (0x00020000)
#define PCR_18 (0x00040000)
#define PCR_19 (0x00080000)
#define PCR_20 (0x00100000)
#define PCR_21 (0x00200000)
#define PCR_22 (0x00400000)
#define PCR_23 (0x00800000)
#define PCR_24 (0x01000000)
#endif


struct SPOK_PlatformKey
{
	std::wstring Name;
	NCRYPT_MACHINE_KEY Flag;
};

#define SPOK_KEY_ATT_MAGIC 'SPKA' // Key Attestation Data Structure
struct SPOK_KEY_ATT_BLOB
{
    uint32_t Magic;
    uint32_t TpmVersion;
    uint32_t HeaderSize;
    uint32_t KeyAttestSize;
    uint32_t SignatureSize;
};

#define SPOK_PLATFORM_ATT_MAGIC 'SPPA' // Platform Attestation Data Structure
struct SPOK_PLATFORM_ATT_BLOB 
{
    uint32_t Magic;
    uint32_t TpmVersion;
    uint32_t HeaderSize;
    uint32_t PcrValuesSize;
    uint32_t QuoteSize;
    uint32_t SignatureSize;
    uint32_t TsbSize;
};

