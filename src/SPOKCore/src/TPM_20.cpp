#include "TPM_20.h"
#include "SPOKCore.h"
#include "SPOKBlob.h"
#include "Util.h"
#include "NCryptUtil.h"
#include "BCryptUtil.h"
#include "TcgLog.h"
#include "HasherUtil.h"
#include <iostream>



// Hard-coded policies - from PCPTool.
const uint8_t defaultUserPolicy[] = { 0x8f, 0xcd, 0x21, 0x69, 0xab, 0x92, 0x69, 0x4e,
								  0x0c, 0x63, 0x3f, 0x1a, 0xb7, 0x72, 0x84, 0x2b,
								  0x82, 0x41, 0xbb, 0xc2, 0x02, 0x88, 0x98, 0x1f,
								  0xc7, 0xac, 0x1e, 0xdd, 0xc1, 0xfd, 0xdb, 0x0e };
const uint8_t adminObjectChangeAuthPolicy[] = { 0xe5, 0x29, 0xf5, 0xd6, 0x11, 0x28, 0x72, 0x95,
											0x4e, 0x8e, 0xd6, 0x60, 0x51, 0x17, 0xb7, 0x57,
											0xe2, 0x37, 0xc6, 0xe1, 0x95, 0x13, 0xa9, 0x49,
											0xfe, 0xe1, 0xf2, 0x04, 0xc4, 0x58, 0x02, 0x3a };
const uint8_t adminCertifyPolicy[] = { 0xaf, 0x2c, 0xa5, 0x69, 0x69, 0x9c, 0x43, 0x6a,
								   0x21, 0x00, 0x6f, 0x1c, 0xb8, 0xa2, 0x75, 0x6c,
								   0x98, 0xbc, 0x1c, 0x76, 0x5a, 0x35, 0x59, 0xc5,
								   0xfe, 0x1c, 0x3f, 0x5e, 0x72, 0x28, 0xa7, 0xe7 };
const uint8_t adminCertifyPolicyNoPin[] = { 0x04, 0x8e, 0x9a, 0x3a, 0xce, 0x08, 0x58, 0x3f,
										0x79, 0xf3, 0x44, 0xff, 0x78, 0x5b, 0xbe, 0xa9,
										0xf0, 0x7a, 0xc7, 0xfa, 0x33, 0x25, 0xb3, 0xd4,
										0x9a, 0x21, 0xdd, 0x51, 0x94, 0xc6, 0x58, 0x50 };
const uint8_t adminActivateCredentialPolicy[] = { 0xc4, 0x13, 0xa8, 0x47, 0xb1, 0x11, 0x12, 0xb1,
											  0xcb, 0xdd, 0xd4, 0xec, 0xa4, 0xda, 0xaa, 0x15,
											  0xa1, 0x85, 0x2c, 0x1c, 0x3b, 0xba, 0x57, 0x46,
											  0x1d, 0x25, 0x76, 0x05, 0xf3, 0xd5, 0xaf, 0x53 };

uint32_t TPM2B_PCR_SELECTION::GetMask() const
{
	if (Bitmap.size() != 3)
	{
		throw std::invalid_argument("Invalid PcrSelection");
	}

	//read the selected PCRs
	uint32_t pcrsToInclude = 0;
	pcrsToInclude = (Bitmap[0]);
	pcrsToInclude += (Bitmap[1] << 8);
	pcrsToInclude += (Bitmap[2] << 16);

	return pcrsToInclude;
}

SPOK_Blob::Blob TPM_20::CertifyKey(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest)
{
	PlatformAik aikKey(aik);
	auto aikProvider = aikKey.GetProviderHandle();

	PlatformKey key(keyToAttest, aikProvider);

	auto keyProvider = key.GetProviderHandle();

	if (aikProvider != keyProvider)
	{
		throw std::runtime_error("The AIK and the key to attest are not from the same provider");
	}
	auto tsbHandle = aikKey.GetTsbHandle();
	auto aikHandle = aikKey.GetPlatformHandle();
	auto keyHandle = key.GetPlatformHandle();
	auto aikSignatureSize = aikKey.GetSignatureSize();

	SPOK_Blob::Blob cmd;
	cmd.resize(512);
	SPOK_Blob::Blob rsp;
	rsp.resize(512);

	uint32_t rspSize = rsp.size();
	
	auto bw = SPOK_BinaryWriter(cmd);
	uint32_t usageAuthSize = 2 * sizeof(UINT32) + // authHandle
					2 * sizeof(UINT16) + // nonceNULL
					2 * sizeof(BYTE) +   // sessionAttributes
					2 * sizeof(UINT16); // password size

	// TPM2.0 certify command
	bw.BE_Write16(0x8002); // TPM_ST_SESSIONS
	bw.BE_Write32(0x00000000); // parameterSize
	bw.BE_Write32(0x00000148); // TPM_CC_Certify
	bw.BE_Write32(keyHandle); // keyhandle
	bw.BE_Write32(aikHandle); // aikHandle
	
	bw.BE_Write32(usageAuthSize); // size of the usage auth area
	
	bw.BE_Write32(0x40000009); // TPM_RS_PW
	bw.BE_Write16(0x0000); // nonce size
	bw.Write(0x00); // session attributes
	bw.BE_Write16(0x0000); // password size

	bw.BE_Write32(0x40000009); // TPM_RS_PW
	bw.BE_Write16(0x0000); // nonce size
	bw.Write(0x00); // session attributes
	bw.BE_Write16(0x0000); // password size

	bw.BE_Write16(SAFE_CAST_TO_UINT16(nonce.size())); // nonce size
	bw.Write(nonce.data(), nonce.size()); // nonce

	bw.BE_Write16(0x0010); // TPM_ALG_NULL

	uint32_t cmdSize = bw.Tell();
	bw.Seek(2); // go back to parameterSize
	bw.BE_Write32(cmdSize); // write the size of the command

	// Send the command to the TPM
	auto status = Tbsip_Submit_Command(tsbHandle, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd.data(), cmdSize, rsp.data(), &rspSize);
	if (status != TBS_SUCCESS)
	{
		throw std::runtime_error("Tbsip_Submit_Command failed");
	}

	// Check the response
	auto br = SPOK_BinaryReader(rsp);
	auto tag = br.BE_Read16();
	auto size = br.BE_Read32();
	auto retCode = br.BE_Read32();
	if (retCode != 0)
	{
		throw std::runtime_error("TPM2.0 Certify failed");
	}
	auto paramSize = br.BE_Read32();
	auto certifyInfoSize = br.BE_Read16();
	auto certifyInfo = br.Read(certifyInfoSize);
	auto sigAlg = br.BE_Read16();
	if (sigAlg != 0x0014)
	{
		throw std::runtime_error("Invalid signature algorithm - Expected TPM_ALG_RSASSA_PKCS1v1_5");
	}
	auto sigHashAlg = br.BE_Read16();
	if (sigHashAlg != TPM_API_ALG_ID_SHA1)
	{
		throw std::runtime_error("Invalid signature hash algorithm - Expected TPM_ALG_SHA1");
	}
	auto sigSize = br.BE_Read16();
	auto sig = br.Read(sigSize);

	// calculate the quote length
	auto required = sizeof(SPOK_KEY_ATT_BLOB) + certifyInfoSize + sigSize;
	auto quote = SPOK_Blob::Blob(required);
	auto bwQuote = SPOK_BinaryWriter(quote);

	SPOK_KEY_ATT_BLOB keyAttBlob;
	keyAttBlob.Magic = SPOK_KEY_ATT_MAGIC;
	keyAttBlob.TpmVersion = SPOK_TPM_VERSION_20;
	keyAttBlob.HeaderSize = sizeof(SPOK_KEY_ATT_BLOB);
	keyAttBlob.KeyAttestSize = certifyInfoSize;
	keyAttBlob.SignatureSize = sigSize;

	bwQuote.Write((uint8_t*)&keyAttBlob, sizeof(SPOK_KEY_ATT_BLOB));
	bwQuote.Write(certifyInfo);
	bwQuote.Write(sig);

	return quote;
}

SPOK_Blob::Blob TPM_20::AttestPlatform(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude)
{
	//Grab the tsb log
	auto tsbLog = NCryptUtil::GetFilteredTbsLog(pcrsToInclude);
	//auto tsbLog = NCryptUtil::GetTbsLog();
	auto log = TcgLog::Parse(tsbLog);
	
	//grab the largest hash algorithm
	uint16_t maxDigest = 0;
	TPM_ALG_ID algIdfromTcg = TPM_ALG_ID::TPM_ALG_SHA1;
	for (auto& data : log.Header.DigestSizes)
	{
		if (data.DigestSize > maxDigest)
		{
			maxDigest = data.DigestSize;
			algIdfromTcg = data.AlgorithmId;
		}
	}
	uint16_t algId = static_cast<uint16_t>(algIdfromTcg);

	SPOK_Blob::Blob pcrProfile;
	//count
	pcrProfile.push_back(0x00);
	pcrProfile.push_back(0x00);
	pcrProfile.push_back(0x00);
	pcrProfile.push_back(0x01);

	// TPM_ALG
	pcrProfile.push_back(SAFE_CAST_TO_UINT8(algId >> 8));
	pcrProfile.push_back(SAFE_CAST_TO_UINT8(algId & 0xFF));

	// sizeOfSelect
	pcrProfile.push_back(0x03);

	// platform PCRs mask
	pcrProfile.push_back(SAFE_CAST_TO_UINT8(pcrsToInclude & 0x000000ff));
	pcrProfile.push_back(SAFE_CAST_TO_UINT8((pcrsToInclude & 0x0000ff00) >> 8));
	pcrProfile.push_back(SAFE_CAST_TO_UINT8((pcrsToInclude & 0x00ff0000) >> 16));

	PlatformAik aikKey(aik);
	auto tsbHandle = aikKey.GetTsbHandle();
	auto aikHandle = aikKey.GetPlatformHandle();
	auto aikSignatureSize = aikKey.GetSignatureSize();

	SPOK_Blob::Blob cmd;
	cmd.resize(512);
	SPOK_Blob::Blob rsp;
	rsp.resize(512);

	auto bw = SPOK_BinaryWriter(cmd);
	uint32_t usageAuthSize = sizeof(UINT32) + // authHandle
		sizeof(UINT16) + // nonceNULL
		sizeof(BYTE) +   // sessionAttributes
		sizeof(UINT16); // password size

	bw.BE_Write16(0x8002); // TPM_ST_SESSIONS
	bw.BE_Write32(0x00000000); // parameterSize
	bw.BE_Write32(0x00000158); // TPM_CC_Quote
	bw.BE_Write32(aikHandle); // keyhandle
	bw.BE_Write32(usageAuthSize); // size of the usage auth area
	bw.BE_Write32(0x40000009); // TPM_RS_PW
	bw.BE_Write16(0x0000); // nonce size
	bw.Write(0x00); // session attributes
	bw.BE_Write16(0x0000); // password size

	bw.BE_Write16(SAFE_CAST_TO_UINT16(nonce.size())); // nonce size
	bw.Write(nonce.data(), nonce.size()); // nonce

	bw.BE_Write16(0x0010);
	bw.Write(pcrProfile); // PCR profile

	uint32_t cmdSize = bw.Tell();
	bw.Seek(2); // go back to parameterSize
	bw.BE_Write32(cmdSize); // write the size of the command

	// Send the command to the TPM
	uint32_t rspSize = rsp.size();
	auto status = Tbsip_Submit_Command(tsbHandle, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd.data(), cmdSize, rsp.data(), &rspSize);
	if (status != TBS_SUCCESS)
	{
		throw std::runtime_error("Tbsip_Submit_Command failed");
	}

	// Check the response
	auto br = SPOK_BinaryReader(rsp);
	auto tag = br.BE_Read16();
	auto size = br.BE_Read32();
	auto retCode = br.BE_Read32();

	if (retCode != 0)
	{
		throw std::runtime_error("TPM2.0 Quote failed");
	}

	auto paramSize = br.BE_Read32();
	auto quoteSize = br.BE_Read16();
	auto quote = br.Read(quoteSize);

	auto sigAlg = br.BE_Read16();
	if (sigAlg != 0x0014)
	{
		throw std::runtime_error("Invalid signature algorithm - Expected TPM_ALG_RSASSA_PKCS1v1_5");
	}
	auto sigHashAlg = br.BE_Read16();
	if (sigHashAlg != TPM_API_ALG_ID_SHA1)
	{
		throw std::runtime_error("Invalid signature hash algorithm - Expected TPM_ALG_SHA1");
	}
	auto sigSize = br.BE_Read16();
	auto sig = br.Read(sigSize);

	//get the pcrTable
	auto devicePcrs = NCryptUtil::GetPcrTable();
	auto pcrTable = SPOK_Pcrs(devicePcrs);
	auto pcrs = pcrTable.GetFiltered(pcrsToInclude).GetBlob();
	auto pcrsSize = pcrs.size();

	// calculate the quote length
	auto required = sizeof(SPOK_PLATFORM_ATT_BLOB) + pcrsSize + quoteSize + sigSize + tsbLog.size();
	auto quoteBlob = SPOK_Blob::Blob(required);
	auto bwQuote = SPOK_BinaryWriter(quoteBlob);

	SPOK_PLATFORM_ATT_BLOB platAttBlob;
	platAttBlob.Magic = SPOK_PLATFORM_ATT_MAGIC;
	platAttBlob.TpmVersion = SPOK_TPM_VERSION_20;
	platAttBlob.HeaderSize = sizeof(SPOK_PLATFORM_ATT_BLOB);
	platAttBlob.PcrValuesSize = pcrsSize;
	platAttBlob.QuoteSize = quoteSize;
	platAttBlob.SignatureSize = sigSize;
	platAttBlob.TsbSize = tsbLog.size();

	bwQuote.Write((uint8_t*)&platAttBlob, sizeof(SPOK_PLATFORM_ATT_BLOB));
	bwQuote.Write(pcrs);
	bwQuote.Write(quote);
	bwQuote.Write(sig);
	bwQuote.Write(tsbLog);

	return quoteBlob;
}

SPOK_Blob::Blob TPM_20::WrapKey(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& srk, const SPOK_Pcrs& boundPcrs)
{
	PCP_20_KEY_BLOB keyBlob;
	memset(&keyBlob, 0, sizeof(PCP_20_KEY_BLOB));

	SPOK_Blob::Blob defaultExponent = { 0x01, 0x00, 0x01 };
	//BCryptKey keyToWrap(key);
	//get key struct
	BCRYPT_RSAKEY_BLOB* pKeyPair = (BCRYPT_RSAKEY_BLOB*)key.data();

	auto pcrMask = boundPcrs.GetMask();
	uint32_t objectAttributes = 0x00060000;
	if(pcrMask == 0)
	{
		objectAttributes = objectAttributes | 0x00000040;
	}

	bool usingDefaultExponent = false;
	if((pKeyPair->cbPublicExp == 3) && (memcmp(&(key.data())[sizeof(BCRYPT_RSAKEY_BLOB)], defaultExponent.data(), sizeof(defaultExponent)) == 0))
	{
		usingDefaultExponent = true;
	}

	BCryptKey srkKey(srk);
	auto blockLength = srkKey.BlockLength();

	SPOK_Blob::Blob orPolicy(sizeof(uint32_t) + (4 * SHA256_DIGEST_SIZE)); // TPM_CC_PolicyOR + 4 * (Policies)
	auto opbw = SPOK_BinaryWriter(orPolicy);
	opbw.BE_Write32(0x00000171); // TPM_CC_PolicyOR

	SPOK_Blob::Blob pcrCompositeDigest;

	uint32_t policyListSize = sizeof(uint32_t) + // count
							  4 * (sizeof(uint16_t) + SHA256_DIGEST_SIZE); // we can only have 4 policies
	SPOK_Blob::Blob policyDigestList(policyListSize);
	auto pdlbw = SPOK_BinaryWriter(policyDigestList);
	pdlbw.BE_Write32(0x00000004); // count

	if (pcrMask == 0)
	{
		//default policy
		pdlbw.BE_Write16(SHA256_DIGEST_SIZE);
		pdlbw.Write(defaultUserPolicy, 32);

		opbw.Write(defaultUserPolicy, 32);
	}
	else
	{
		//policy for pcr binding
		uint32_t pcrPolicySize = SHA256_DIGEST_SIZE + // default policy hash
								 sizeof(uint32_t)   + // TPM_CC_PolicyPCR
								 sizeof(uint32_t)   + // count
								 sizeof(uint16_t)   + // hash
								 sizeof(uint8_t)    + // size
								 3                  + // pcr selection
								 SHA256_DIGEST_SIZE;  // pcr digest

		SPOK_Blob::Blob pcrPolicy(pcrPolicySize);
		auto ppbw = SPOK_BinaryWriter(pcrPolicy);

		SPOK_Blob::Blob pcrComposite;
		
		//add all selected pcrs to the composite
		for(uint32_t ii = 0; ii < AVAILABLE_PLATFORM_PCRS; ++ii)
		{
			if (pcrMask & (1 << ii))
			{
				auto pcr = boundPcrs.GetPcr(ii);
				std::copy(pcr.begin(), pcr.end(), std::back_inserter(pcrComposite));
			}
		}
		//hash the composite
		auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA256);
		pcrCompositeDigest = hasher.OneShotHash(pcrComposite);

		ppbw.Write(defaultUserPolicy, 32);
		ppbw.BE_Write32(0x0000017F); // TPM_CC_PolicyPCR
		ppbw.BE_Write32(0x00000001); // count
		ppbw.BE_Write16(boundPcrs.GetAlgId());
		ppbw.Write(0x03); // size
		ppbw.Write(SAFE_CAST_TO_UINT8(pcrMask & 0x000000ff));
		ppbw.Write(SAFE_CAST_TO_UINT8((pcrMask & 0x0000ff00) >> 8));
		ppbw.Write(SAFE_CAST_TO_UINT8((pcrMask & 0x00ff0000) >> 16));
		ppbw.Write(pcrCompositeDigest);

		//hash the composite
		auto hasherComposite = Hasher::Create(TPM_API_ALG_ID_SHA256);
		auto policyDigest = hasherComposite.OneShotHash(pcrPolicy);

		pdlbw.BE_Write16(SHA256_DIGEST_SIZE);
		pdlbw.Write(policyDigest);
		opbw.Write(policyDigest);
	}

	pdlbw.BE_Write16(SHA256_DIGEST_SIZE);
	pdlbw.Write(adminObjectChangeAuthPolicy, 32);
	opbw.Write(adminObjectChangeAuthPolicy, 32);

	pdlbw.BE_Write16(SHA256_DIGEST_SIZE);
	pdlbw.Write(adminCertifyPolicy, 32);
	opbw.Write(adminCertifyPolicy, 32);

	pdlbw.BE_Write16(SHA256_DIGEST_SIZE);
	pdlbw.Write(adminActivateCredentialPolicy, 32);
	opbw.Write(adminActivateCredentialPolicy, 32);

	uint32_t pcrBindingSize = 0;
	uint32_t pcrDigestSize = 0;
	
	if (pcrMask != 0)
	{
		pcrBindingSize = sizeof(uint8_t) +
						 sizeof(uint8_t) +
						 sizeof(uint8_t);
		pcrDigestSize = SHA256_DIGEST_SIZE;
	}
	SPOK_Blob::Blob pcrBinding(pcrBindingSize);
	SPOK_Blob::Blob pcrDigest(pcrDigestSize);

	if (pcrMask != 0)
	{
		auto pbw = SPOK_BinaryWriter(pcrBinding);
		pbw.Write(SAFE_CAST_TO_UINT8(pcrMask & 0x000000ff));
		pbw.Write(SAFE_CAST_TO_UINT8((pcrMask & 0x0000ff00) >> 8));
		pbw.Write(SAFE_CAST_TO_UINT8((pcrMask & 0x00ff0000) >> 16));

		auto pdbw = SPOK_BinaryWriter(pcrDigest);
		pdbw.Write(pcrCompositeDigest);
	}

	//calculate the digest for the orPolicy
	auto hasher = Hasher::Create(TPM_API_ALG_ID_SHA256);
	auto orPolicyDigest = hasher.OneShotHash(orPolicy);

	uint32_t publicSize = sizeof(uint16_t) + // type
		sizeof(uint16_t) + // nameAlg
		sizeof(uint32_t) + // objectAttributes
		sizeof(uint16_t) + // DIGEST + authPolicy.size
		SHA256_DIGEST_SIZE +
		sizeof(uint16_t) + // algorithm
		sizeof(uint16_t) + // scheme
		sizeof(uint16_t) + // keyBits
		sizeof(uint32_t) + // exponent
		sizeof(uint16_t) + // size
		pKeyPair->cbModulus; // modulus
	SPOK_Blob::Blob publicKey(publicSize);
	auto pkbw = SPOK_BinaryWriter(publicKey);
	pkbw.BE_Write16(0x0001); // TPM_ALG_RSA
	pkbw.BE_Write16(TPM_API_ALG_ID_SHA256); // TPM_ALG_SHA256
	pkbw.BE_Write32(objectAttributes); // objectAttributes
	pkbw.BE_Write16(SHA256_DIGEST_SIZE); // policy digest size
	pkbw.Write(orPolicyDigest); // orPolicy digest
	pkbw.BE_Write16(0x0010); // TPM_ALG_NULL
	pkbw.BE_Write16(0x0010); // TPM_ALG_NULL
	pkbw.BE_Write16((uint16_t)pKeyPair->BitLength);
	if (usingDefaultExponent)
	{
		pkbw.BE_Write32(0x00000000); //default
	}
	else
	{
		//write any leading zeros
		for (uint32_t n = 0; n < (sizeof(uint32_t) - pKeyPair->cbPublicExp); ++n)
		{
			pkbw.Write(0x00);
		}
		pkbw.Write(&(key.data())[sizeof(BCRYPT_RSAKEY_BLOB)], pKeyPair->cbPublicExp);
	}
	pkbw.BE_Write16(SAFE_CAST_TO_UINT16(pKeyPair->cbModulus));
	pkbw.Write(&(key.data())[sizeof(BCRYPT_RSAKEY_BLOB) + pKeyPair->cbPublicExp], pKeyPair->cbModulus);

	//get the public name
	auto publicName = GetNameForPublic(publicKey);

	uint32_t encryptedSecretSize = sizeof(uint16_t) + blockLength;
	SPOK_Blob::Blob encryptedSecret(encryptedSecretSize);
	auto esbw = SPOK_BinaryWriter(encryptedSecret);
	esbw.BE_Write16(blockLength);

	//get the random seed
	const uint16_t AES_KEY_SIZE = 16;
	auto seed = BCryptUtil::GetRandomBytes(AES_KEY_SIZE);
	
	auto encryptedSeed = srkKey.Encrypt(seed, false);
	esbw.Write(encryptedSeed);


	uint32_t tpm12HostageBlobSize = sizeof(uint16_t) +     // TPM2B_SENSITIVE.size
									sizeof(uint16_t) +     // TPMT_SENSITIVE.sensitiveType
									sizeof(uint16_t) +     // authValue.Size
									sizeof(uint16_t) +     // symValue.Size
									sizeof(uint16_t) +     // TPMU_SENSITIVE_COMPOSITE.size
									pKeyPair->cbPrime1;

	SPOK_Blob::Blob tpm12HostageBlob(tpm12HostageBlobSize);
	auto thbw = SPOK_BinaryWriter(tpm12HostageBlob);
	thbw.BE_Write16(tpm12HostageBlobSize - sizeof(uint16_t)); // TPM2B_SENSITIVE.size
	thbw.BE_Write16(0x0001); // TPMT_SENSITIVE.sensitiveType = RSA
	thbw.BE_Write16(0x0000); // authValue.Size
	thbw.BE_Write16(0x0000); // symValue.Size
	thbw.BE_Write16(pKeyPair->cbPrime1); // TPMU_SENSITIVE_COMPOSITE.size
	thbw.Write(&(key.data())[sizeof(BCRYPT_RSAKEY_BLOB) + pKeyPair->cbPublicExp + pKeyPair->cbModulus], pKeyPair->cbPrime1); // private

	//calculate the symettric key
	auto symKey = KDFa(TPM_API_ALG_ID_SHA256, seed, "STORAGE", publicName, SPOK_Blob::New(0), AES_KEY_SIZE * 8);

	//encrypt the tpm12HostageBlob
	auto zeroIv = SPOK_Blob::New(AES_KEY_SIZE);
	auto protectedBlob = CFB(symKey, zeroIv, tpm12HostageBlob);
	protectedBlob.resize(tpm12HostageBlob.size());

	//calculate the hmac key
	auto hmacKey = KDFa(TPM_API_ALG_ID_SHA256, seed, "INTEGRITY", SPOK_Blob::New(0), SPOK_Blob::New(0), SHA256_DIGEST_SIZE * 8);

	//calculate the hmac	
	auto hmacHasher = Hasher::Create_HMAC(TPM_API_ALG_ID_SHA256, hmacKey);
	hmacHasher.HashData(tpm12HostageBlob);
	hmacHasher.HashData(publicName);
	auto outerHmac = hmacHasher.FinishHash();

	//build the opauqe key blob header
	keyBlob.Magic = PCP_20_KEY_BLOB_MAGIC;
	keyBlob.HeaderSize = sizeof(PCP_20_KEY_BLOB);
	keyBlob.PcpType = PCPTYPE_TPM20;
	keyBlob.Flags = 0;
	keyBlob.PublicSize = publicKey.size() + sizeof(uint16_t);
	keyBlob.PrivateSize = 0;
	keyBlob.MigrationPublicSize = 0;
	keyBlob.MigrationPrivateSize = 0;
	keyBlob.PolicyDigestListSize = policyDigestList.size();
	keyBlob.PcrBindingSize = pcrBinding.size();
	keyBlob.PcrDigestSize = pcrDigest.size();
	keyBlob.EncryptedSecretSize = encryptedSecret.size();
	keyBlob.Tpm12HostageBlobSize = sizeof(uint16_t) + sizeof(uint16_t) + outerHmac.size() + tpm12HostageBlob.size();
	keyBlob.PcrAlgId = boundPcrs.GetAlgId();

	//build the key blob
	SPOK_Blob::Blob keyBlobOut;
	keyBlobOut.resize(sizeof(PCP_20_KEY_BLOB) + keyBlob.PublicSize + keyBlob.PolicyDigestListSize + keyBlob.PcrBindingSize + keyBlob.PcrDigestSize + keyBlob.EncryptedSecretSize + keyBlob.Tpm12HostageBlobSize);
	auto bw = SPOK_BinaryWriter(keyBlobOut);
	bw.Write((uint8_t*)&keyBlob, sizeof(PCP_20_KEY_BLOB));
	
	bw.BE_Write16(keyBlob.PublicSize);
	bw.Write(publicKey);

	bw.Write(policyDigestList);
	bw.Write(pcrBinding);
	bw.Write(pcrDigest);
	bw.Write(encryptedSecret);
	
	bw.BE_Write16(sizeof(uint16_t) + outerHmac.size() + protectedBlob.size());
	bw.BE_Write16(outerHmac.size());
	bw.Write(outerHmac);
	bw.Write(protectedBlob);

	std::cout << "KeyBlob size: " << keyBlobOut.size() << std::endl;
	std::cout << SPOK_Blob::BlobToHex(keyBlobOut) << std::endl;

	return keyBlobOut;
}

SPOK_Blob::Blob TPM_20::GetWrappedKeyName(const SPOK_Blob::Blob& wrappedKey)
{
	//seek to the start of the public key
	auto br = SPOK_BinaryReader(wrappedKey);
	br.Seek(sizeof(PCP_20_KEY_BLOB));
	auto publicSize = br.BE_Read16();
	auto publicKey = br.Read(publicSize);

	return GetNameForPublic(publicKey);
}

TPM2B_PUBLIC TPM2B_PUBLIC::Decode(const SPOK_Blob::Blob& publicBlob)
{
	auto br = SPOK_BinaryReader(publicBlob);

	auto type = br.BE_Read16();
	auto nameAlg = br.BE_Read16();
	auto objectAttributes = br.BE_Read32();
	auto authPolicySize = br.BE_Read16();
	auto authPolicy = br.Read(authPolicySize);
	auto symmetric = br.BE_Read16();

	if (symmetric == 0x0006)
	{
		auto keyBits = br.BE_Read16();
		auto mode = br.BE_Read16();
	}
	else if (symmetric != 0x0010)
	{
		throw std::runtime_error("Invalid symmetric algorithm");
	}
	auto scheme = br.BE_Read16();

	uint16_t signHashAlg = 0;
	if (scheme == 0x0014)
	{
		signHashAlg = br.BE_Read16();
	}
	else if (scheme != 0x0010)
	{
		throw std::runtime_error("Invalid scheme");
	}

	auto keybits = br.BE_Read16();
	auto exponent = br.BE_Read32();

	auto exponentBlob = SPOK_Blob::Blob();

	auto exponentArray = std::array<uint8_t, 4> 
	{
		static_cast<uint8_t>((exponent >> 24) & 0xFF),
		static_cast<uint8_t>((exponent >> 16) & 0xFF),
		static_cast<uint8_t>((exponent >> 8) & 0xFF),
		static_cast<uint8_t>(exponent & 0xFF)
	};

	if (exponentArray[0] == 0x00)
	{
		//use default
		exponentArray[0] = 0x01;
		exponentArray[1] = 0x00;
		exponentArray[2] = 0x01;
		exponentArray[3] = 0x00;
	}
	
	exponentBlob.insert(exponentBlob.end(), exponentArray.begin(), exponentArray.end());

	//remove any trailing 0s
	while (exponentBlob.back() == 0x00)
	{
		exponentBlob.pop_back();
	}

	auto modulusSize = br.BE_Read16();
	auto modulus = br.Read(modulusSize);

	return TPM2B_PUBLIC{ type, nameAlg, objectAttributes, authPolicy, symmetric, scheme, signHashAlg, keybits, exponentBlob, modulus, publicBlob };
}

TPM2B_CREATION_DATA TPM2B_CREATION_DATA::Decode(const SPOK_Blob::Blob& creationBlob)
{
	auto br = SPOK_BinaryReader(creationBlob);

	auto prcSelection = std::vector<TPM2B_PCR_SELECTION>();
	auto pcrSelectionSize = br.BE_Read32();
	for (auto i = 0; i < pcrSelectionSize; i++)
	{
		auto algId = br.BE_Read16();
		auto bitmapSize = br.BE_Read16();
		auto bitmap = br.Read(bitmapSize);

		prcSelection.push_back(TPM2B_PCR_SELECTION{ algId, bitmap });
	}

	auto digestSize = br.BE_Read16();
	auto digest = br.Read(digestSize);

	auto locality = br.Read();

	auto parentNameAlg = br.BE_Read16();

	auto parentNameSize = br.BE_Read16();
	auto parentName = br.Read(parentNameSize);

	auto parentQualifiedNameSize = br.BE_Read16();
	auto parentQualifiedName = br.Read(parentQualifiedNameSize);

	auto creationNonceSize = br.BE_Read16();
	auto creationNonceBlob = br.Read(creationNonceSize);
	auto creationNonce = SPOK_Nonce::Make(creationNonceBlob);

	return TPM2B_CREATION_DATA{ prcSelection, digest, locality, parentNameAlg, parentName, parentQualifiedName, creationNonce, creationBlob };
}

TPM2B_ATTEST_QUOTE TPM2B_ATTEST_QUOTE::Decode(const SPOK_Blob::Blob& attestBlob)
{
	auto br = SPOK_BinaryReader(attestBlob);

	auto generated = br.BE_Read32();
	if (generated != 0xff544347) // TPM_GENERATED
	{
		throw std::runtime_error("Invalid attestation generation");
	}

	auto type = br.BE_Read16();
	if (type != 0x8018) //TPM_ST_ATTEST_QUOTE
	{
		throw std::runtime_error("Invalid attestation type");
	}

	auto qualifiedSignerSize = br.BE_Read16();
	auto qualifiedSigner = br.Read(qualifiedSignerSize);

	auto creationNonceSize = br.BE_Read16();
	auto creationNonceBlob = br.Read(creationNonceSize);
	auto creationNonce = SPOK_Nonce::Make(creationNonceBlob);

	auto clock_clock = br.BE_Read64();
	auto clock_resetCount = br.BE_Read32();
	auto clock_restartCount = br.BE_Read32();
	auto clock_safe = br.Read();
	auto clockInfo = TPMS_CLOCK_INFO{ clock_clock, clock_resetCount, clock_restartCount, clock_safe };

	auto firmwareVersion = br.BE_Read64();

	auto prcSelection = std::vector<TPM2B_PCR_SELECTION>();
	auto pcrSelectionSize = br.BE_Read32();
	for (auto i = 0; i < pcrSelectionSize; i++)
	{
		auto algId = br.BE_Read16();
		auto bitmapSize = br.Read();
		auto bitmap = br.Read(bitmapSize);

		prcSelection.push_back(TPM2B_PCR_SELECTION{ algId, bitmap });
	}

	auto digestSize = br.BE_Read16();
	auto pcrDigest = br.Read(digestSize);

	return TPM2B_ATTEST_QUOTE{ generated, type, qualifiedSigner, creationNonce, clockInfo, firmwareVersion, prcSelection, pcrDigest, attestBlob };
}

TPM2B_ATTEST_CERTIFY TPM2B_ATTEST_CERTIFY::Decode(const SPOK_Blob::Blob& certifyBlob)
{
	auto br = SPOK_BinaryReader(certifyBlob);

	auto generated = br.BE_Read32();
	if (generated != 0xff544347) // TPM_GENERATED
	{
		throw std::runtime_error("Invalid attestation generation");
	}

	auto type = br.BE_Read16();
	if (type != 0x8017) //TPM_ST_ATTEST_CERTIFY
	{
		throw std::runtime_error("Invalid attestation type");
	}

	auto qualifiedSignerSize = br.BE_Read16();
	auto qualifiedSigner = br.Read(qualifiedSignerSize);

	auto creationNonceSize = br.BE_Read16();
	auto creationNonceBlob = br.Read(creationNonceSize);
	auto creationNonce = SPOK_Nonce::Make(creationNonceBlob);

	auto clock_clock = br.BE_Read64();
	auto clock_resetCount = br.BE_Read32();
	auto clock_restartCount = br.BE_Read32();
	auto clock_safe = br.Read();
	auto clockInfo = TPMS_CLOCK_INFO{ clock_clock, clock_resetCount, clock_restartCount, clock_safe };

	auto firmwareVersion = br.BE_Read64();

	auto nameSize = br.BE_Read16();
	auto name = br.Read(nameSize);

	auto qualifiedNameSize = br.BE_Read16();
	auto qualifiedName = br.Read(qualifiedNameSize);
	
	return TPM2B_ATTEST_CERTIFY{ generated, type, qualifiedSigner, creationNonce, clockInfo, firmwareVersion, name, qualifiedName, certifyBlob };
}

TPM2B_ATTEST_CREATION TPM2B_ATTEST_CREATION::Decode(const SPOK_Blob::Blob& attestBlob)
{
	auto br = SPOK_BinaryReader(attestBlob);

	auto generated = br.BE_Read32();
	if (generated != 0xff544347) // TPM_GENERATED
	{
		throw std::runtime_error("Invalid attestation generation");
	}

	auto type = br.BE_Read16();
	if (type != 0x801A) //TPM_ST_ATTEST_CREATION
	{
		throw std::runtime_error("Invalid attestation type");
	}

	auto qualifiedSignerSize = br.BE_Read16();
	auto qualifiedSigner = br.Read(qualifiedSignerSize);

	auto creationNonceSize = br.BE_Read16();
	auto creationNonceBlob = br.Read(creationNonceSize);
	auto creationNonce = SPOK_Nonce::Make(creationNonceBlob);

	auto clock_clock = br.BE_Read64();
	auto clock_resetCount = br.BE_Read32();
	auto clock_restartCount = br.BE_Read32();
	auto clock_safe = br.Read();
	auto clockInfo = TPMS_CLOCK_INFO{ clock_clock, clock_resetCount, clock_restartCount, clock_safe };

	auto firmwareVersion = br.BE_Read64();

	auto objectNameSize = br.BE_Read16();
	auto objectName = br.Read(objectNameSize);

	auto creationHashSize = br.BE_Read16();
	auto creationHash = br.Read(creationHashSize);

	return TPM2B_ATTEST_CREATION{ generated, type, qualifiedSigner, creationNonce, clockInfo, firmwareVersion, objectName, creationHash, attestBlob };
}

TPMT_SIGNATURE TPMT_SIGNATURE::Decode(const SPOK_Blob::Blob& signatureBlob)
{
	auto br = SPOK_BinaryReader(signatureBlob);

	auto sigAlg = br.BE_Read16();
	auto sigHashAlg = br.BE_Read16();
	auto signatureSize = br.BE_Read16();
	auto signature = br.Read(signatureSize);

	return TPMT_SIGNATURE{ sigAlg, sigHashAlg, signature, signatureBlob };
}

TPM2B_IDBINDING TPM_20::DecodeIDBinding(const SPOK_Blob::Blob& idBinding)
{
	auto br = SPOK_BinaryReader(idBinding);

	auto pubSize = br.BE_Read16();
	auto pub = br.Read(pubSize);

	auto creationSize = br.BE_Read16();
	auto creation = br.Read(creationSize);

	auto attSize = br.BE_Read16();
	auto att = br.Read(attSize);

	auto signatureSize = (idBinding.size() - br.Tell());
	auto signature = br.Read(signatureSize);

	auto pubStruct = TPM2B_PUBLIC::Decode(pub);
	auto creationStruct = TPM2B_CREATION_DATA::Decode(creation);
	auto attStruct = TPM2B_ATTEST_CREATION::Decode(att);
	auto sigStruct = TPMT_SIGNATURE::Decode(signature);

	return TPM2B_IDBINDING{ pubStruct, creationStruct, attStruct, sigStruct };
}

SPOK_Blob::Blob TPM_20::GenerateChallengeCredential(const uint16_t ekNameAlgId, const SPOK_Blob::Blob& ekPub, const SPOK_Blob::Blob& aikName, const SPOK_Blob::Blob& secret)
{
	//AES key size
	const uint16_t AES_KEY_SIZE = 16;

	//validate the secret
	if (secret.size() > SHA256_DIGEST_SIZE)
	{
		throw std::runtime_error("Secret is too large max is SHA256_DIGEST_SIZE");
	}

	//get the random seed
	auto seed = BCryptUtil::GetRandomBytes(AES_KEY_SIZE);

	//create the AES key from the seed
	auto aesKey = KDFa(ekNameAlgId, seed, "STORAGE", aikName, SPOK_Blob::Blob(), AES_KEY_SIZE * 8);

	//create the IV - zeros
	auto iv = SPOK_Blob::Blob(AES_KEY_SIZE, 0x00);

	//encrypt the secret
	auto secretBlob = SPOK_Blob::New(secret.size() + sizeof(uint16_t));
	auto bw = SPOK_BinaryWriter(secretBlob);
	bw.BE_Write16(SAFE_CAST_TO_UINT16(secret.size()));
	bw.Write(secret);

	auto encryptedSecret = CFB(aesKey, iv, secretBlob);
	//trim to the first 16 bytes
	encryptedSecret.resize(secretBlob.size());

	//generate hmac key
	auto hmacKey = KDFa(ekNameAlgId, seed, "INTEGRITY", SPOK_Blob::Blob(), SPOK_Blob::Blob(), SHA256_DIGEST_SIZE * 8);

	//calculate the outer hmac
	auto outerHmacHaser = Hasher::Create_HMAC(ekNameAlgId, hmacKey);
	auto outerBlob = SPOK_Blob::New(encryptedSecret.size() + aikName.size());
	auto outerBw = SPOK_BinaryWriter(outerBlob);
	outerBw.Write(encryptedSecret);
	outerBw.Write(aikName);
	auto outerHmac = outerHmacHaser.OneShotHash(outerBlob);

	//encrypt the seed
	//get a key for the EK
	auto ekKey = BCryptUtil::Open(ekPub);
	if (ekKey.IsValid() == false)
	{
		throw std::runtime_error("Failed to open the EK key");
	}
	auto encryptedSeed = ekKey.Encrypt(seed, true);
	auto ekBlockLength = ekKey.BlockLength();

	//create the challenge
	uint16_t challengeSize = sizeof(uint16_t) +                      // TPM2B_ID_OBJECT.size
							 sizeof(uint16_t) + SHA256_DIGEST_SIZE + // TPM2B_DIGEST outerHAMC
							 encryptedSecret.size()                + // TPM2B_DIGEST credential value
							 sizeof(uint16_t) + ekBlockLength;       // TPM2B_ENCRYPTED_SECRET protecting credential value
								
	auto challengeObject = SPOK_Blob::Blob(challengeSize);
	auto challengeBw = SPOK_BinaryWriter(challengeObject);

	challengeBw.BE_Write16(SAFE_CAST_TO_UINT16(challengeSize - sizeof(uint16_t) - sizeof(uint16_t) - ekBlockLength));
	challengeBw.BE_Write16(SAFE_CAST_TO_UINT16(outerHmac.size()));
	challengeBw.Write(outerHmac);
	//challengeBw.BE_Write16(SAFE_CAST_TO_UINT16(encryptedSecret.size()));
	challengeBw.Write(encryptedSecret);
	challengeBw.BE_Write16(SAFE_CAST_TO_UINT16(encryptedSeed.size()));
	challengeBw.Write(encryptedSeed);

	return challengeObject;
}

SPOK_Blob::Blob TPM_20::KDFa(const uint16_t nameAlgId, const SPOK_Blob::Blob& key, const std::string& label, const SPOK_Blob::Blob& contextU, const SPOK_Blob::Blob& contextV, uint16_t bits)
{
	uint32_t iteration = 0;
	uint16_t outSize = bits / 8;
	uint16_t counter = 0;
	SPOK_Blob::Blob out;

	//calculate the size of the buffer
	auto bufferSize = sizeof(uint32_t) + label.size() + sizeof(uint8_t) + sizeof(UINT16) + contextU.size() + contextV.size() + sizeof(UINT16);
	auto buffer = SPOK_Blob::Blob(bufferSize);

	auto bw = SPOK_BinaryWriter(buffer);
	bw.BE_Write32(iteration);
	bw.Write((const uint8_t*)label.data(), label.size());
	bw.Write(0x00); //null terminator

	if (contextU.size() != 0)
	{
		bw.Write(contextU);
	}

	if (contextV.size() != 0)
	{
		bw.Write(contextV);
	}

	bw.BE_Write32(bits);

	while (counter < outSize)
	{
		auto remaining = outSize - counter;
		auto hasher = Hasher::Create_HMAC(nameAlgId, key);
		iteration++;
		bw.Seek(0);
		bw.BE_Write32(iteration);

		//std::cout << "KDFa Input: " << SPOK_Blob::BlobToBase64(buffer) << std::endl;

		auto hash = hasher.OneShotHash(buffer);
		if(hash.size() <= remaining)
		{
			out.insert(out.end(), hash.begin(), hash.end());
			counter += hash.size();
		}
		else
		{
			out.insert(out.end(), hash.begin(), hash.begin() + remaining);
			counter += remaining;
		}
	}
	return out;
}

SPOK_Blob::Blob TPM_20::CFB(const SPOK_Blob::Blob& key, const SPOK_Blob::Blob& iv, const SPOK_Blob::Blob& data)
{
	auto cipher = BCryptUtil::CreateSymmetricCipher(key, BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CFB, iv);
	return cipher.Encrypt(data);
}

SPOK_Blob::Blob TPM_20::GetNameForPublic(const SPOK_Blob::Blob& publicBlob)
{
	//get the public name
	auto hasherPublicName = Hasher::Create(TPM_API_ALG_ID_SHA256);
	auto publicNameHash = hasherPublicName.OneShotHash(publicBlob);

	//add the algid and return
	SPOK_Blob::Blob publicName(sizeof(uint16_t) + publicNameHash.size());
	auto pnbw = SPOK_BinaryWriter(publicName);
	pnbw.BE_Write16(TPM_API_ALG_ID_SHA256);
	pnbw.Write(publicNameHash);

	return publicName;
}