#pragma once

#include <stdint.h>
#include <vector>
#include <array>


enum class TPM_ALG_ID : uint16_t
{
	TPM_ALG_ERROR     = 0x0000,
	TPM_ALG_RSA       = 0x0001,
	TPM_ALG_SHA1      = 0x0004,
	TPM_ALG_HMAC      = 0x0005,
	TPM_ALG_AES       = 0x0006,
	TPM_ALG_MGF1      = 0x0007,
	TPM_ALG_KEYEDHASH = 0x0008,
	TPM_ALG_XOR       = 0x000A,
	TPM_ALG_SHA256    = 0x000B,
	TPM_ALG_SHA384    = 0x000C,
	TPM_ALG_SHA512    = 0x000D,
	TPM_ALG_NULL      = 0x0010,
	TPM_ALG_SM3_256   = 0x0012,
    TPM_ALG_SHA3_256  = 0x0027, //Defined in wbcl.h
    TPM_ALG_SHA3_384  = 0x0028, //Defined in wbcl.h
    TPM_ALG_SHA3_512  = 0x0029  //Defined in wbcl.h

};

enum class TcgLogEventType : uint32_t
{
    EV_PREBOOT_CERT                  = 0x00000000,
    EV_POST_CODE                     = 0x00000001,
    EV_UNUSED                        = 0x00000002,
    EV_NO_ACTION                     = 0x00000003,
    EV_SEPARATOR                     = 0x00000004,
    EV_ACTION                        = 0x00000005,
    EV_EVENT_TAG                     = 0x00000006,
    EV_S_CRTM_CONTENTS               = 0x00000007,
    EV_S_CRTM_VERSION                = 0x00000008,
    EV_CPU_MICROCODE                 = 0x00000009,
    EV_PLATFORM_CONFIG_FLAGS         = 0x0000000A,
    EV_TABLE_OF_DEVICES              = 0x0000000B,
    EV_COMPACT_HASH                  = 0x0000000C,
    EV_IPL                           = 0x0000000D,
    EV_IPL_PARTITION_DATA            = 0x0000000E,
    EV_NONHOST_CODE                  = 0x0000000F,
    EV_NONHOST_CONFIG                = 0x00000010,
    EV_NONHOST_INFO                  = 0x00000011,
    EV_EFI_VARIABLE_DRIVER_CONFIG    = 0x80000001,
    EV_EFI_VARIABLE_BOOT             = 0x80000002,
    EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003,
    EV_EFI_BOOT_SERVICES_DRIVER      = 0x80000004,
    EV_EFI_RUNTIME_SERVICES_DRIVER   = 0x80000005,
    EV_EFI_GPT_EVENT                 = 0x80000006,
    EV_EFI_ACTION                    = 0x80000007,
    EV_EFI_PLATFORM_FIRMWARE_BLOB    = 0x80000008,
    EV_EFI_HANDOFF_TABLES            = 0x80000009,
    EV_EFI_HCRTM_EVENT               = 0x8000000A,
    EV_EFI_VARIABLE_AUTHORITY        = 0x800000E0
};
   

struct TcgLogDigestSize
{
    TPM_ALG_ID AlgorithmId;
    uint16_t   DigestSize;
};

struct TcgLogDigest
{
    TPM_ALG_ID    AlgorithmId;
    std::vector<uint8_t>  Digest;
};

struct TcgLogEvent
{
    uint32_t PCRIndex;
    TcgLogEventType Type;
    std::vector<TcgLogDigest> Digests;
    std::vector<uint8_t> Data;
};

struct TcgLogHeader
{
    uint8_t                       SpecVersionMajor;
    uint8_t                       SpecVersionMinor;
    uint8_t                       SpecErrata;
    uint8_t                       UintnSize;
    uint8_t                       VendorInfoSize;
    uint32_t                      PlatformClass;
    uint32_t                      NumberOfAlgorithms;
    std::vector<uint8_t>          VendorInfo;
    std::array<uint8_t, 16>       Signature;
    std::vector<TcgLogDigestSize> DigestSizes;
};

struct TcgLog
{
	TcgLogHeader Header;
	std::vector<TcgLogEvent> Events;

    static TcgLogEventType GetEventType(uint32_t eventType);
    static TPM_ALG_ID GetTpmAlgId(uint16_t algId);
    static uint32_t GetDigestSize(TPM_ALG_ID algId);
    static TcgLog Parse(const std::vector<uint8_t>& tcgLogData);
    static TcgLog Filter(const TcgLog& tcgLog, uint32_t pcrMask);
    static std::vector<uint8_t> ComputeSoftPCRTable(const TcgLog& tcgLog, TPM_ALG_ID algId);
    static std::vector<uint8_t> Serialize(const TcgLog& tcgLog);
};

