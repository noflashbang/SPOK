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
#include <string>
#include <map>
#include <stdexcept>

#include "SPOKApiTypes.h"

class SPOK_Error
{
public:
	static SPOKSTATUS SPOK_LippincottHandler();
	static SPOKSTATUS SPOK_ErrorMessageToStatus(const std::string& message);
	static std::string SPOK_StatusToErrorMessage(SPOKSTATUS status);
	static void SPOK_SetLastError(const std::string& message);

private:
	static std::map<SPOKSTATUS, std::string> m_ErrorMessages;
};



#define SPOK_OKAY  ( 0)
#define SPOK_ERROR (0x80000000)

#define SPOK_SUCCESS(x) ((x & SPOK_ERROR) == 0)
#define SPOK_FAILURE(x) ((x & SPOK_ERROR) != 0)

#define SPOK_ERROR_MESSAGE(x)  SPOK_Error::SPOK_StatusToErrorMessage(x)
#define SPOK_SET_LAST_ERROR(x) SPOK_Error::SPOK_SetLastError(x)

#define SPOK_THROW_ERROR(x, msg) {                                              \
									SPOK_SET_LAST_ERROR(msg);                   \
									auto gMsg = SPOK_ERROR_MESSAGE(x);          \
									throw std::runtime_error(gMsg);             \
								 }

#define SPOK_OVERFLOW             (0x80000001)
#define SPOK_INVALID_ALGORITHM    (0x80000002)
#define SPOK_NOT_FOUND            (0x80000003)
#define SPOK_BCRYPT_FAILURE       (0x80000004)
#define SPOK_NCRYPT_FAILURE       (0x80000005)
#define SPOK_INSUFFICIENT_BUFFER  (0x80000006)
#define SPOK_INVALID_HANDLE       (0x80000007)
#define SPOK_INVALID_STATE        (0x80000008)
#define SPOK_INVALID_DATA         (0x80000009)
#define SPOK_INVALID_SIGNATURE    (0x8000000A)
#define SPOK_INVALID_KEY          (0x8000000B)
#define SPOK_TPMCMD_FAILED       (0x8000000B)
#define SPOK_TCGLOG_FAILURE      (0x8000000C)

#define SPOK_UNKNOWN_ERROR		  (0x8000FFFE)
#define SPOK_LAST_ERROR           (0x8000FFFF)

