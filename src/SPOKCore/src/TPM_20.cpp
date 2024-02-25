#include "TPM_20.h"
#include "SPOKCore.h"
#include "SPOKBlob.h"
#include "Util.h"
#include "NCryptUtil.h"
#include "TcgLog.h"

SPOK_Blob::Blob TPM_20::CertifyKey(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest)
{
	PlatformAik aikKey(aik);
	PlatformKey key(keyToAttest);

	auto aikProvider = aikKey.GetProviderHandle();
	auto keyProvider = key.GetProviderHandle();

	if (aikProvider != keyProvider)
	{
		throw std::runtime_error("The AIK and the key to attest are not from the same provider");
	}
	auto tsbHandle = aikKey.GetTsbHandle();
	auto aikHandle = aikKey.GetProviderHandle();
	auto keyHandle = key.GetProviderHandle();
	auto aikSignatureSize = aikKey.GetSignatureSize();

	SPOK_Blob::Blob cmd;
	cmd.resize(512);
	SPOK_Blob::Blob rsp;
	rsp.resize(512);

	uint32_t rspSize = 0;
	
	auto bw = SPOK_BinaryStream(cmd);
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
	auto br = SPOK_BinaryStream(rsp);
	auto tag = br.BE_Read16();
	auto size = br.BE_Read32();
	auto retCode = br.BE_Read32();
	auto paramSize = br.BE_Read32();
	auto certifyInfoSize = br.BE_Read32();
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
	auto bwQuote = SPOK_BinaryStream(quote);

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
	//pcrProfile.push_back(SAFE_CAST_TO_UINT8(pcrsToInclude & 0x000000ff));
	//pcrProfile.push_back(SAFE_CAST_TO_UINT8((pcrsToInclude & 0x0000ff00) >> 8));
	//pcrProfile.push_back(SAFE_CAST_TO_UINT8((pcrsToInclude & 0x00ff0000) >> 16));

	pcrProfile.push_back(0x7f);
	pcrProfile.push_back(0xf7);
	pcrProfile.push_back(0x00);

	PlatformAik aikKey(aik);
	auto tsbHandle = aikKey.GetTsbHandle();
	auto aikHandle = aikKey.GetPlatformHandle();
	auto aikSignatureSize = aikKey.GetSignatureSize();

	SPOK_Blob::Blob cmd;
	cmd.resize(512);
	SPOK_Blob::Blob rsp;
	rsp.resize(512);

	auto bw = SPOK_BinaryStream(cmd);
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
	auto br = SPOK_BinaryStream(rsp);
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
	auto bwQuote = SPOK_BinaryStream(quoteBlob);

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
