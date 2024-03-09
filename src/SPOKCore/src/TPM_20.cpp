#include "TPM_20.h"
#include "SPOKCore.h"
#include "SPOKBlob.h"
#include "Util.h"
#include "NCryptUtil.h"
#include "TcgLog.h"

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
	keyAttBlob.TpmVersion = TPM_VERSION_20;
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

	// calculate the quote length
	auto required = sizeof(SPOK_PLATFORM_ATT_BLOB) + quoteSize + sigSize + tsbLog.size();
	auto quoteBlob = SPOK_Blob::Blob(required);
	auto bwQuote = SPOK_BinaryWriter(quoteBlob);

	SPOK_PLATFORM_ATT_BLOB platAttBlob;
	platAttBlob.Magic = SPOK_PLATFORM_ATT_MAGIC;
	platAttBlob.TpmVersion = TPM_VERSION_20;
	platAttBlob.HeaderSize = sizeof(SPOK_PLATFORM_ATT_BLOB);
	platAttBlob.PcrMask = pcrsToInclude;
	platAttBlob.QuoteSize = quoteSize;
	platAttBlob.SignatureSize = sigSize;
	platAttBlob.TsbSize = tsbLog.size();

	bwQuote.Write((uint8_t*)&platAttBlob, sizeof(SPOK_PLATFORM_ATT_BLOB));
	bwQuote.Write(quote);
	bwQuote.Write(sig);
	bwQuote.Write(tsbLog);

	return quoteBlob;
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

TPM2B_ATTEST TPM2B_ATTEST::Decode(const SPOK_Blob::Blob& attestBlob)
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

	return TPM2B_ATTEST{ generated, type, qualifiedSigner, creationNonce, clockInfo, firmwareVersion, objectName, creationHash, attestBlob };
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
	auto attStruct = TPM2B_ATTEST::Decode(att);
	auto sigStruct = TPMT_SIGNATURE::Decode(signature);

	return TPM2B_IDBINDING{ pubStruct, creationStruct, attStruct, sigStruct };
}