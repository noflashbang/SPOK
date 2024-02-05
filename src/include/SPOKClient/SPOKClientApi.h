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


#ifdef SPOKCLIENT_EXPORTS
#define SPOKCLIENT_API __declspec(dllexport)
#else
#define SPOKCLIENT_API __declspec(dllimport) 
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	SPOKCLIENT_API SPOK_Handle SPC_Create();
		
	//AIK Management
	SPOKCLIENT_API void SPC_AIKCreate(std::wstring name, NCRYPT_MACHINE_KEY flag, SPOK_Nonce nonce);
	SPOKCLIENT_API void SPC_AIKDelete(std::wstring name, NCRYPT_MACHINE_KEY flag);
	SPOKCLIENT_API bool SPC_AIKExists(std::wstring name, NCRYPT_MACHINE_KEY flag);

	//AIK Attestation
	SPOKCLIENT_API void SPC_AIKGetKeyAttestation();
	SPOKCLIENT_API void SPC_AIKGetPlatformAttestation();

	//AIK Public Key
	SPOKCLIENT_API void SPC_AIKGetPublicKey();

	//Endorsement Key Access
	SPOKCLIENT_API void SPC_GetEndorsementPublicKey();

	//AIK Challenge
	SPOKCLIENT_API void SPC_AIKGetChallengeBinding();
	SPOKCLIENT_API void SPC_AIKActivateChallenge();

	//AIK Quote and Verify
	SPOKCLIENT_API void SPC_GetBootLog();	
	SPOKCLIENT_API void SPC_GetPCRTable();

	//SRK Access
	SPOKCLIENT_API void SPC_GetStorageRootKey();

	//User Key Addition
	SPOKCLIENT_API void SPC_PlatformImportKey();

	//Cryptographic Operations
	SPOKCLIENT_API void SPC_PlatformDecrypt();
	SPOKCLIENT_API void SPC_PlatformEncrypt();
	SPOKCLIENT_API void SPC_PlatformSign();
	SPOKCLIENT_API void SPC_PlatformVerifySignature();

#ifdef __cplusplus
}
#endif