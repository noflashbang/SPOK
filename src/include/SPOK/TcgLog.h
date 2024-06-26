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

#include "TPMAlgId.h"
#include <stdint.h>
#include <vector>
#include <array>


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
    static bool VerifyLogIntegrity(const TcgLog& tcgLog);
    static std::vector<uint8_t> Serialize(const TcgLog& tcgLog);
};

