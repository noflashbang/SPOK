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
#include <stdint.h>

enum class TPM_ALG_ID : uint16_t
{
	TPM_ALG_ERROR     = 0x0000,
	TPM_ALG_RSA       = 0x0001,
	TPM_ALG_SHA1      = 0x0004,
	TPM_ALG_HMAC      = 0x0005,
	TPM_ALG_AES       = 0x0006,
	TPM_ALG_MGF1      = 0x0007,
	TPM_ALG_KEYEDHASH = 0x0008,
	TPM_ALG_XOR       = 0x000A,
	TPM_ALG_SHA256    = 0x000B,
	TPM_ALG_SHA384    = 0x000C,
	TPM_ALG_SHA512    = 0x000D,
	TPM_ALG_NULL      = 0x0010,
	TPM_ALG_SM3_256   = 0x0012,
								//Using this value to match TPM_ALG_KDF1_SP800_108, as it is the closest match to a random number generator
	TPM_ALG_RNG       = 0x0022, //TPM_ALG_KDF1_SP800_108 = NIST Recommendation for Key Derivation Using Pseudorandom Functions
	TPM_ALG_SHA3_256  = 0x0027, //Defined in wbcl.h
	TPM_ALG_SHA3_384  = 0x0028, //Defined in wbcl.h
	TPM_ALG_SHA3_512  = 0x0029  //Defined in wbcl.h
};
