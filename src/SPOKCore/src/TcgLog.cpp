#include "TcgLog.h"
#include "StandardLib.h"
#include "SPOKBlob.h"
#include "HasherUtil.h"
#include "Util.h"
#include "SPOKError.h"
#include <format>

TcgLogEventType TcgLog::GetEventType(uint32_t eventType)
{
	switch (eventType)
	{
	case 0x00000000:
		return TcgLogEventType::EV_PREBOOT_CERT;
	case 0x00000001:
		return TcgLogEventType::EV_POST_CODE;
	case 0x00000002:
		return TcgLogEventType::EV_UNUSED;
	case 0x00000003:
		return TcgLogEventType::EV_NO_ACTION;
	case 0x00000004:
		return TcgLogEventType::EV_SEPARATOR;
	case 0x00000005:
		return TcgLogEventType::EV_ACTION;
	case 0x00000006:
		return TcgLogEventType::EV_EVENT_TAG;
	case 0x00000007:
		return TcgLogEventType::EV_S_CRTM_CONTENTS;
	case 0x00000008:
		return TcgLogEventType::EV_S_CRTM_VERSION;
	case 0x00000009:
		return TcgLogEventType::EV_CPU_MICROCODE;
	case 0x0000000A:
		return TcgLogEventType::EV_PLATFORM_CONFIG_FLAGS;
	case 0x0000000B:
		return TcgLogEventType::EV_TABLE_OF_DEVICES;
	case 0x0000000C:
		return TcgLogEventType::EV_COMPACT_HASH;
	case 0x0000000D:
		return TcgLogEventType::EV_IPL;
	case 0x0000000E:
		return TcgLogEventType::EV_IPL_PARTITION_DATA;
	case 0x0000000F:
		return TcgLogEventType::EV_NONHOST_CODE;
	case 0x00000010:
		return TcgLogEventType::EV_NONHOST_CONFIG;
	case 0x00000011:
		return TcgLogEventType::EV_NONHOST_INFO;
	case 0x80000001:
		return TcgLogEventType::EV_EFI_VARIABLE_DRIVER_CONFIG;
	case 0x80000002:
		return TcgLogEventType::EV_EFI_VARIABLE_BOOT;
	case 0x80000003:
		return TcgLogEventType::EV_EFI_BOOT_SERVICES_APPLICATION;
	case 0x80000004:
		return TcgLogEventType::EV_EFI_BOOT_SERVICES_DRIVER;
	case 0x80000005:
		return TcgLogEventType::EV_EFI_RUNTIME_SERVICES_DRIVER;
	case 0x80000006:
		return TcgLogEventType::EV_EFI_GPT_EVENT;
	case 0x80000007:
		return TcgLogEventType::EV_EFI_ACTION;
	case 0x80000008:
		return TcgLogEventType::EV_EFI_PLATFORM_FIRMWARE_BLOB;
	case 0x80000009:
		return TcgLogEventType::EV_EFI_HANDOFF_TABLES;
	case 0x8000000A:
		return TcgLogEventType::EV_EFI_HCRTM_EVENT;
	case 0x800000E0:
		return TcgLogEventType::EV_EFI_VARIABLE_AUTHORITY;
	default:
	{
		auto msg = std::format("Invalid TCG log event type: {0}", eventType);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}
	}
}

TPM_ALG_ID TcgLog::GetTpmAlgId(uint16_t algId)
{
	switch (algId)
	{
	case 0x0000:
		return TPM_ALG_ID::TPM_ALG_ERROR;
	case 0x0001:
		return TPM_ALG_ID::TPM_ALG_RSA;
	case 0x0004:
		return TPM_ALG_ID::TPM_ALG_SHA1;
	case 0x0005:
		return TPM_ALG_ID::TPM_ALG_HMAC;
	case 0x0006:
		return TPM_ALG_ID::TPM_ALG_AES;
	case 0x0007:
		return TPM_ALG_ID::TPM_ALG_MGF1;
	case 0x0008:
		return TPM_ALG_ID::TPM_ALG_KEYEDHASH;
	case 0x000A:
		return TPM_ALG_ID::TPM_ALG_XOR;
	case 0x000B:
		return TPM_ALG_ID::TPM_ALG_SHA256;
	case 0x000C:
		return TPM_ALG_ID::TPM_ALG_SHA384;
	case 0x000D:
		return TPM_ALG_ID::TPM_ALG_SHA512;
	case 0x0010:
		return TPM_ALG_ID::TPM_ALG_SM3_256;
	case 0x0023:
		return TPM_ALG_ID::TPM_ALG_SHA3_256;
	case 0x0024:
		return TPM_ALG_ID::TPM_ALG_SHA3_384;
	case 0x0025:
		return TPM_ALG_ID::TPM_ALG_SHA3_512;
	default:
	{
		auto msg = std::format("Invalid TCG log digest algorithm: {0}", algId);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}
	}
}

uint32_t TcgLog::GetDigestSize(TPM_ALG_ID algId)
{
	switch (algId)
	{
	case TPM_ALG_ID::TPM_ALG_SHA1:
		return 20;
	case TPM_ALG_ID::TPM_ALG_SHA256:
		return 32;
	case TPM_ALG_ID::TPM_ALG_SHA384:
		return 48;
	case TPM_ALG_ID::TPM_ALG_SHA512:
		return 64;
	case TPM_ALG_ID::TPM_ALG_SM3_256:
		return 32;
	case TPM_ALG_ID::TPM_ALG_SHA3_256:
		return 32;
	case TPM_ALG_ID::TPM_ALG_SHA3_384:
		return 48;
	case TPM_ALG_ID::TPM_ALG_SHA3_512:
		return 64;
	default:
	{
		auto msg = std::format("Invalid TCG log digest algorithm: {0}", (uint16_t)algId);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}
	}
}

TcgLog TcgLog::Parse(const std::vector<uint8_t>& tcgLogData)
{
	TcgLog tcgLog;
	uint32_t offset = 0;
	SPOK_BinaryReader stream(tcgLogData);

	// Parse the TCG log header
	if (tcgLogData.size() < 65)
	{
		auto msg = std::format("Invalid TCG log size: {0}", tcgLogData.size());
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}

	auto pcrIndex = stream.LE_Read32();
	if (pcrIndex != 0)
	{
		auto msg = std::format("Invalid PCR index: {0}", pcrIndex);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}

	TcgLogEventType eventType = GetEventType(stream.LE_Read32());

	if (eventType != TcgLogEventType::EV_NO_ACTION)
	{
		auto msg = std::format("Invalid TCG log event type: {0}", (uint32_t)eventType);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}

	auto digest = stream.Read(20);
	if (digest != std::vector<uint8_t>(20, 0))
	{
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, "Invalid TCG log digest");
	}

	auto eventSize = stream.LE_Read32();

	auto signature = stream.Read(16);
	if (signature != std::vector<uint8_t> { 'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', '\0' })
	{
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, "Invalid TCG log signature");
	}

	auto platformClass = stream.LE_Read32();
	auto specVersionMinor = stream.Read();
	auto specVersionMajor = stream.Read();
	auto specErrata = stream.Read();
	auto uintnSize = stream.Read();
	auto numberOfAlgorithms = stream.LE_Read32();

	std::vector<TcgLogDigestSize> digestSizes;
	for (uint32_t i = 0; i < numberOfAlgorithms; i++)
	{
		auto algId = stream.LE_Read16();
		auto digestSize = stream.LE_Read16();
		auto digestSizeObj = TcgLogDigestSize(GetTpmAlgId(algId), digestSize);
		digestSizes.push_back(digestSizeObj);
	}

	auto vendorInfoSize = stream.Read();
	auto vendorInfo = stream.Read(vendorInfoSize);

	//fill in the header
	std::copy(signature.begin(), signature.end(), tcgLog.Header.Signature.begin());
	tcgLog.Header.PlatformClass = platformClass;
	tcgLog.Header.NumberOfAlgorithms = numberOfAlgorithms;
	tcgLog.Header.SpecVersionMinor = specVersionMinor;
	tcgLog.Header.SpecVersionMajor = specVersionMajor;
	tcgLog.Header.SpecErrata = specErrata;
	tcgLog.Header.UintnSize = uintnSize;
	tcgLog.Header.DigestSizes = digestSizes;
	tcgLog.Header.VendorInfoSize = vendorInfoSize;
	tcgLog.Header.VendorInfo = vendorInfo;
	tcgLog.Header.DigestSizes = digestSizes;

	// Parse the TCG log entries
	while ((tcgLogData.size() - stream.Tell()) > 16) // 16 is the minimum size of an event
	{
		TcgLogEvent event;
		event.PCRIndex = stream.LE_Read32();
		event.Type = GetEventType(stream.LE_Read32());

		auto digestCount = stream.LE_Read32();
		for (uint32_t i = 0; i < digestCount; i++)
		{
			TcgLogDigest digest;
			digest.AlgorithmId = GetTpmAlgId(stream.LE_Read16());
			digest.Digest = stream.Read(GetDigestSize(digest.AlgorithmId));
			event.Digests.push_back(digest);
		}
		auto size = stream.LE_Read32();
		event.Data = stream.Read(size);
		tcgLog.Events.push_back(event);
	}
	return tcgLog;
}

TcgLog TcgLog::Filter(const TcgLog& tcgLog, uint32_t pcrMask)
{
	TcgLog filteredTcgLog;
	filteredTcgLog.Header = tcgLog.Header;
	for (const auto& event : tcgLog.Events)
	{
		if ((pcrMask & (1 << event.PCRIndex)) != 0)
		{
			filteredTcgLog.Events.push_back(event);
		}
	}
	return filteredTcgLog;
}

std::vector<uint8_t> TcgLog::ComputeSoftPCRTable(const TcgLog& tcgLog, TPM_ALG_ID algId)
{
	uint32_t hashSize = TcgLog::GetDigestSize(algId);
	HasherType hasherType;
	if (algId == TPM_ALG_ID::TPM_ALG_SHA1)
	{
		hasherType = HasherType::SHA1;
	}
	else if (algId == TPM_ALG_ID::TPM_ALG_SHA256)
	{
		hasherType = HasherType::SHA256;
	}
	else if (algId == TPM_ALG_ID::TPM_ALG_SHA384)
	{
		hasherType = HasherType::SHA384;
	}
	else if (algId == TPM_ALG_ID::TPM_ALG_SHA512)
	{
		hasherType = HasherType::SHA512;
	}
	else
	{
		auto msg = std::format("Unsupported TCG log digest algorithm: {0}", (uint16_t)algId);
		SPOK_THROW_ERROR(SPOK_TCGLOG_FAILURE, msg);
	}

	std::vector<uint8_t> softPCRTable;
	//foreach pcr compute the hash of all the events
	for (uint32_t pcrIndex = 0; pcrIndex < 24; pcrIndex++)
	{
		std::vector<uint8_t> pcrValue(hashSize);
		auto fillValue = (pcrIndex <= 15 || pcrIndex >= 24) ? 0x00 : 0xFF;
		std::fill(pcrValue.begin(), pcrValue.end(), fillValue);
		for (const auto& event : tcgLog.Events)
		{
			if (event.Type == TcgLogEventType::EV_NO_ACTION)
			{
				continue;
			}
			HasherUtil hasher(hasherType);

			if (event.PCRIndex == pcrIndex)
			{
				HasherUtil eventhasher(hasherType);
				auto digestevt = eventhasher.OneShotHash(event.Data);

				for (const auto& digest : event.Digests)
				{
					if (digest.AlgorithmId == algId)
					{
						//hash the pcr
						hasher.HashData(pcrValue);
						hasher.HashData(digest.Digest);
						pcrValue = hasher.FinishHash();
					}
				}
			}
		}
		softPCRTable.insert(softPCRTable.end(), pcrValue.begin(), pcrValue.end());
	}
	return softPCRTable;
}

bool TcgLog::VerifyLogIntegrity(const TcgLog& tcgLog)
{
	bool valid = true;

	//check the event digest against the data
	for (const auto& event : tcgLog.Events)
	{
		for (const auto& digest : event.Digests)
		{
			HasherType hasherType = HasherType::SHA256;
			if (digest.AlgorithmId == TPM_ALG_ID::TPM_ALG_SHA1)
			{
				hasherType = HasherType::SHA1;
			}
			HasherUtil hasher(hasherType);
			auto computedDigest = hasher.OneShotHash(event.Data);
			if (digest.Digest != computedDigest)
			{
				valid = false;
				break;
			}
		}
	}

	return valid;
}

std::vector<uint8_t> TcgLog::Serialize(const TcgLog& tcgLog)
{
	//calculate the size needed for the blob
	uint32_t size = 0;
	size += 4; //PCRIndex
	size += 4; //EventType
	size += 20; //Digest
	size += 4; //EventSize
	size += 16; //Signature
	size += 4; //PlatformClass
	size += 1; //SpecVersionMinor
	size += 1; //SpecVersionMajor
	size += 1; //SpecErrata
	size += 1; //UintnSize
	size += 4; //NumberOfAlgorithms
	size += SAFE_CAST_TO_UINT32(tcgLog.Header.DigestSizes.size() * 4); //DigestSizes
	size += 1; //VendorInfoSize
	size += SAFE_CAST_TO_UINT32(tcgLog.Header.VendorInfo.size()); //VendorInfo
	for (const auto& event : tcgLog.Events)
	{
		size += 4; //PCRIndex
		size += 4; //EventType
		size += 4; //DigestCount
		for (const auto& digest : event.Digests)
		{
			size += 2;
			size += SAFE_CAST_TO_UINT32(digest.Digest.size());
		}
		size += 4; //DataSize
		size += SAFE_CAST_TO_UINT32(event.Data.size()); //Data
	}
	SPOK_Blob::Blob tbsLog(size);
	SPOK_BinaryWriter stream(tbsLog);

	stream.LE_Write32(0);
	stream.LE_Write32(static_cast<uint32_t>(TcgLogEventType::EV_NO_ACTION));
	stream.Write(std::vector<uint8_t>(20, 0));
	stream.LE_Write32(0);
	stream.Write(std::vector<uint8_t> { 'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', '\0' });
	stream.LE_Write32(tcgLog.Header.PlatformClass);
	stream.Write(tcgLog.Header.SpecVersionMinor);
	stream.Write(tcgLog.Header.SpecVersionMajor);
	stream.Write(tcgLog.Header.SpecErrata);
	stream.Write(tcgLog.Header.UintnSize);
	stream.LE_Write32(static_cast<uint32_t>(tcgLog.Header.DigestSizes.size()));
	for (const auto& digestSize : tcgLog.Header.DigestSizes)
	{
		stream.LE_Write16(static_cast<uint16_t>(digestSize.AlgorithmId));
		stream.LE_Write16(digestSize.DigestSize);
	}
	stream.Write(tcgLog.Header.VendorInfoSize);
	stream.Write(tcgLog.Header.VendorInfo);

	for (const auto& event : tcgLog.Events)
	{
		stream.LE_Write32(event.PCRIndex);
		stream.LE_Write32(static_cast<uint32_t>(event.Type));
		stream.LE_Write32(static_cast<uint32_t>(event.Digests.size()));
		for (const auto& digest : event.Digests)
		{
			stream.LE_Write16(static_cast<uint16_t>(digest.AlgorithmId));
			stream.Write(digest.Digest);
		}
		stream.LE_Write32(static_cast<uint32_t>(event.Data.size()));
		stream.Write(event.Data);
	}
	return tbsLog;
};