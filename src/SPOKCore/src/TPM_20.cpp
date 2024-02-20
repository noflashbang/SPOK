#include "TPM_20.h"
#include "SPOKCore.h"
#include "SPOKBlob.h"
#include "Util.h"
#include "NCryptUtil.h"

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
