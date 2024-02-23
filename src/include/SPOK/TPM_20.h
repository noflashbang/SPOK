
#pragma once
#include "SPOKCore.h"
#include "SPOKNonce.h"
#include "SPOKBlob.h"

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((UINT16)0x0004)
#endif
#ifndef TPM_API_ALG_ID_SHA256
#define TPM_API_ALG_ID_SHA256       ((UINT16)0x000B)
#endif
#ifndef TPM_API_ALG_ID_SHA384
#define TPM_API_ALG_ID_SHA384       ((UINT16)0x000C)
#endif
#ifndef TPM_API_ALG_ID_NULL
#define TPM_API_ALG_ID_NULL       ((UINT16)0x0010)
#endif

class TPM_20
{
public:
	static SPOK_Blob::Blob CertifyKey(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, const SPOK_PlatformKey& keyToAttest);
	static SPOK_Blob::Blob AttestPlatform(const SPOK_PlatformKey& aik, const SPOK_Nonce::Nonce& nonce, uint32_t pcrsToInclude);

private:

};

