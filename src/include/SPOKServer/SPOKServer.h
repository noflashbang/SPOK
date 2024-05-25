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
#include "BCryptUtil.h"
#include "NCryptUtil.h"

#include "SPOKNonce.h"
#include "SPOKBlob.h"
#include "SPOKPcrs.h"

#include "IAttestation.h"

class SPOKServer
{
public:
	SPOKServer();
	~SPOKServer();

	//AIK Platform Attestation
	SPOK_AIKPlatformAttestation AIKAttestationDecode(const SPOK_Blob& attQuote);
	SPOK_Pcrs AIKAttestationGetPCR(IAttestation& attestation);
	SPOK_Blob AIKAttestationGetTcgLog(IAttestation& attestation);

	//AIK TPM Attestation
	SPOK_AIKTpmAttestation AIKTpmAttestationDecode(const SPOK_Blob& idBinding);
	SPOK_Blob AIKGetTpmAttestationChallenge(const uint16_t ekNameAlgId, const SPOK_Blob& ekPub, const SPOK_Blob& aikName, const SPOK_Blob& secret);

	//AIK Key Attestation
	SPOK_AIKKeyAttestation AIKKeyAttestationDecode(const SPOK_Blob& attKey);

	//All Types of Attestation
	SPOK_VerifyResult AttestationVerify(IAttestation& attestation, const SPOK_AttestationVerify& verify);

	//Basic Crypto Operations
	SPOK_Blob Decrypt(const SPOK_Blob& key, const SPOK_Blob& data);
	SPOK_Blob Encrypt(const SPOK_Blob& key, const SPOK_Blob& data);
	SPOK_Blob Sign(const SPOK_Blob& key, const SPOK_Blob& data);
	bool VerifySignature(const SPOK_Blob& key, const SPOK_Blob& data, const SPOK_Blob& signature);

	//Key Helpers
	SPOK_Blob GenerateRSAKeyPair(KeySize keySize);
	SPOK_Blob WrapKeyForPlatformImport(const SPOK_Blob& keyToWrap, const SPOK_Blob& srk, const SPOK_Pcrs& boundPcrs);
	SPOK_Blob GetWrappedKeyName(const SPOK_Blob& keyWrap);
};