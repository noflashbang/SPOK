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

#include "SPOKApiTypes.h"


#ifdef SPOKCLIENT_EXPORTS
#define SPOKCLIENT_API __declspec(dllexport)
#else
#define SPOKCLIENT_API __declspec(dllimport) 
#endif

#ifdef __cplusplus
extern "C"
{
#endif
		
	//AIK Management
	SPOKCLIENT_API void SPC_AIKCreate(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* nonce, const size_t cbNonce);
	SPOKCLIENT_API void SPC_AIKDelete(const wchar_t* name, const NCRYPT_MACHINE_KEY flag);
	SPOKCLIENT_API bool SPC_AIKExists(const wchar_t* name, const NCRYPT_MACHINE_KEY flag);

	//AIK Attestation
	SPOKCLIENT_API void SPC_AIKGetKeyAttestation(const wchar_t* aikName, const NCRYPT_MACHINE_KEY aikFlag, const uint8_t* nonce, const size_t cbNonce, const wchar_t* keyName, const NCRYPT_MACHINE_KEY keyFlag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);
	SPOKCLIENT_API void SPC_AIKGetPlatformAttestation();

	//AIK Public Key
	SPOKCLIENT_API void SPC_AIKGetPublicKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);

	//Endorsement Key Access
	SPOKCLIENT_API void SPC_GetEndorsementPublicKey(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);

	//AIK Challenge
	SPOKCLIENT_API void SPC_AIKGetChallengeBinding(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);
	SPOKCLIENT_API void SPC_AIKActivateChallenge(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pChallenge, const size_t cbChallenge, uint8_t pSecretOut[32]);

	//AIK Quote and Verify
	SPOKCLIENT_API void SPC_GetBootLog(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);
	SPOKCLIENT_API void SPC_GetPCRTable(uint8_t* pPcrTable, const size_t cbPcrTable, size_t& sizeOut);

	//SRK Access
	SPOKCLIENT_API void SPC_GetStorageRootKey(uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);

	//User Key Addition
	SPOKCLIENT_API void SPC_PlatformImportWrappedKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pKeyBlob, const size_t cbKeyBlob);
	SPOKCLIENT_API void SPC_CreatePlatformKey(const wchar_t* name, const NCRYPT_MACHINE_KEY flag);

	//Cryptographic Operations
	SPOKCLIENT_API void SPC_PlatformDecrypt(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut);
	SPOKCLIENT_API void SPC_PlatformEncrypt(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut);
	SPOKCLIENT_API void SPC_PlatformSign(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pHash, const size_t cbhash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut);
	SPOKCLIENT_API bool SPC_PlatformVerifySignature(const wchar_t* name, const NCRYPT_MACHINE_KEY flag, const uint8_t* pHash, const size_t cbhash, const uint8_t* pSignature, const size_t cbSignature);

#ifdef __cplusplus
}
#endif