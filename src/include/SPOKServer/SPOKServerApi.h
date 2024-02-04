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
#include <vector>
#include <memory>

#include "SPOKCore.h"


#ifdef SPOKSERVER_EXPORTS
#define SPOKSERVER_API __declspec(dllexport)
#else
#define SPOKSERVER_API __declspec(dllimport) 
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	SPOKSERVER_API SPOK_Handle SPS_Create();
	
	//AIK Platform Attestation
	SPOKSERVER_API void SPS_AIKAttestationDecode();
	SPOKSERVER_API void	SPS_AIKAttestationGetPCR();
	SPOKSERVER_API void SPS_AIKAttestationGetTcgLog();
	SPOKSERVER_API void SPS_AIKAttestationVerify();

	//AIK Attestation
	SPOKSERVER_API void SPS_AIKDecodeBinding();
	SPOKSERVER_API void SPS_AIKFreeBinding();
	SPOKSERVER_API void SPS_AIKGetChallenge();
	
	//AIK Key Attestation
	SPOKSERVER_API void SPS_AIKKeyAttestationDecode();
	SPOKSERVER_API void SPS_AIKKeyAttestationVerify();

	SPOKSERVER_API void SPS_AIKRawVerifyNonce();
	SPOKSERVER_API void SPS_AIKRawVerifySignature();

	//Basic Crypto Operations
	SPOKSERVER_API void SPS_Decrypt();
	SPOKSERVER_API void SPS_Encrypt();
	SPOKSERVER_API void SPS_Sign();
	SPOKSERVER_API void SPS_VerifySignature();

	//Key Helpers
	SPOKSERVER_API void SPS_GenerateRSA256KeyPair();
	SPOKSERVER_API void SPS_WrapKeyForPlatformImport();

#ifdef __cplusplus
}
#endif