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


#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32

#ifndef TPM_VERSION_12
#define TPM_VERSION_12 0x00010000
#endif

#ifndef TPM_VERSION_20
#define TPM_VERSION_20 0x00020000
#endif

struct SPOK_PlatformKey
{
	std::wstring Name;
	NCRYPT_MACHINE_KEY Flag;
};

#define SPOK_KEY_ATT_MAGIC 'SPKA' // Key Attestation Data Structure
typedef struct _SPOK_KEY_ATT_BLOB {
    uint32_t Magic;
    uint32_t TpmVersion;
    uint32_t HeaderSize;
    uint32_t KeyAttestSize;
    uint32_t SignatureSize;
} SPOK_KEY_ATT_BLOB;

#define SPOK_PLATFORM_ATT_MAGIC 'SPPA' // Platform Attestation Data Structure
typedef struct _SPOK_PLATFORM_ATT_BLOB {
    uint32_t Magic;
    uint32_t TpmVersion;
    uint32_t HeaderSize;
    uint32_t PcrMask;
    uint32_t QuoteSize;
    uint32_t SignatureSize;
    uint32_t TsbSize;
} SPOK_PLATFORM_ATT_BLOB;

