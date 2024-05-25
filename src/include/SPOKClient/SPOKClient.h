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

#include "SPOKCore.h"
#include "NCryptUtil.h"

#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

class SPOKClient
{
public:
	SPOKClient();
	~SPOKClient();

	void AIKCreate(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce);
	void AIKDelete(const SPOK_PlatformKey& aik);
	bool AIKExists(const SPOK_PlatformKey& aik);

	SPOK_Blob AIKGetKeyAttestation(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest);
	SPOK_Blob AIKGetPlatformAttestation(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude);

	SPOK_Blob AIKGetPublicKey(const SPOK_PlatformKey& aik);
	SPOK_Blob GetEndorsementPublicKey();
	SPOK_Blob AIKGetChallengeBinding(const SPOK_PlatformKey& aik);
	SPOK_Blob AIKActivateChallenge(const SPOK_PlatformKey& aik, const SPOK_Blob& challenge);
	SPOK_Blob GetBootLog();
	SPOK_Blob GetBootLog(const uint32_t pcrsToInclude);
	SPOK_Blob GetPCRTable();
	SPOK_Blob GetStorageRootKey();
	void PlatformImportKey(const SPOK_PlatformKey& platformKey, const SPOK_Blob& key, KeyBlobType type);
	void PlatformCreateKey(const SPOK_PlatformKey& platformKey);
	bool PlatformKeyExists(const SPOK_PlatformKey& platformKey);

	SPOK_Blob PlatformDecrypt(const SPOK_PlatformKey& key, const SPOK_Blob& data);
	SPOK_Blob PlatformEncrypt(const SPOK_PlatformKey& key, const SPOK_Blob& data);
	SPOK_Blob PlatformSign(const SPOK_PlatformKey& key, const SPOK_Blob& data);
	bool PlatformVerifySignature(const SPOK_PlatformKey& key, const SPOK_Blob& data, const SPOK_Blob& signature);
};