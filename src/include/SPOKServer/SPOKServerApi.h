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

	//Cleanup attestation
	SPOKSERVER_API void SPS_AttestationDestroy(SPOK_Handle hAttestationHandle);

	//AIK Platform Attestation
	SPOKSERVER_API SPOK_Handle SPS_AIKPlatformAttest_Decode(const uint8_t* pBlob, const size_t cbBlob);
	SPOKSERVER_API void	SPS_AIKPlatformAttest_GetPCR(SPOK_Handle hAttest, uint8_t* pPcrTable, const size_t cbPcrTable, size_t& sizeOut, uint8_t& hashSizeOut);
	SPOKSERVER_API void SPS_AIKPlatformAttest_GetTcgLog(SPOK_Handle hAttest, uint8_t* pLog, const size_t cbLog, size_t& sizeOut);
	SPOKSERVER_API bool SPS_AIKPlatformAttest_Verify(SPOK_Handle hAttest, const uint8_t* pNonce, const size_t cbNonce, const uint8_t* pAikPub, const size_t cbAikPub);

	//AIK Tpm Attestation
	SPOKSERVER_API SPOK_Handle SPS_AIKTpmAttest_Decode(const uint8_t* pBlob, const size_t cbBlob);
	SPOKSERVER_API void SPS_AIKTpmAttest_GetChallenge(SPOK_Handle hAttest, const uint16_t ekNameAlgId, const uint8_t* pEkPub, const size_t cbEkPub, const uint8_t* pSecret, const size_t cbSecret, uint8_t* pChallenge, const size_t cbChallenge, size_t& sizeOut);
	SPOKSERVER_API bool SPS_AIKAttest_Verify(SPOK_Handle hAttest, const uint8_t* nonce, const size_t cbNonce);

	//AIK Key Attestation
	SPOKSERVER_API SPOK_Handle SPS_AIKKeyAttest_Decode(const uint8_t* pBlob, const size_t cbBlob);
	SPOKSERVER_API bool SPS_AIKKeyAttest_Verify(SPOK_Handle hAttest, const uint8_t* nonce, const size_t cbNonce, const uint8_t* pAikPub, const size_t cbAikPub, const uint8_t* pPubName, const size_t cbPubName);

	//Basic Crypto Operations
	SPOKSERVER_API void SPS_Decrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pBytes, const size_t cbBytes, uint8_t* pData, const size_t cbData, size_t& sizeOut);
	SPOKSERVER_API void SPS_Encrypt(const uint8_t* pKey, const size_t cbKey, const uint8_t* pData, const size_t cbData, uint8_t* pBytes, const size_t cbBytes, size_t& sizeOut);
	SPOKSERVER_API void SPS_Sign(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature, size_t& sizeOut);
	SPOKSERVER_API bool SPS_VerifySignature(const uint8_t* pKey, const size_t cbKey, const uint8_t* pHash, const size_t cbHash, uint8_t* pSignature, const size_t cbSignature);

	//Key Helpers
	SPOKSERVER_API void SPS_GenerateRSAKeyPair(const uint16_t keySizeBits, uint8_t* pData, const size_t cbData, size_t& sizeOut);
	SPOKSERVER_API void SPS_WrapKeyForPlatformImport(const uint8_t* pKeyToWrap, const size_t cbKeyToWrap, const uint8_t* pSrk, const size_t cbSrk, uint8_t* pBoundPcrTable, const size_t cbBoundPcrTable, uint8_t* pKeyWrap, const size_t cbKeyWrap, size_t& sizeOut);
	SPOKSERVER_API void SPS_WrappedKeyName(const uint8_t* pKeyWrap, const size_t cbKeyWrap, uint8_t* pName, const size_t cbName, size_t& sizeOut);

#ifdef __cplusplus
}
#endif