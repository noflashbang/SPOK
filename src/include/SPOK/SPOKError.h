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
#include <stdexcept>

#include "SPOKApiTypes.h"

class SPOK_Error
{
public:
	static SPOKSTATUS SPOK_LippincottHandler();
	static void SPOK_SetLastError(const std::string& message);

	static std::exception SPOK_This_Error(SPOKSTATUS x, std::string msg);

private:
	static std::string _lastError;
};

class SPOK_Overflow : public std::overflow_error
{
public:
	SPOK_Overflow(const std::string& message) noexcept : std::overflow_error(message) {}
};

class SPOK_InvalidAlgorithm : public std::invalid_argument
{
public:
	SPOK_InvalidAlgorithm(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_NotFound : public std::out_of_range
{
public:
	SPOK_NotFound(const std::string& message) noexcept : std::out_of_range(message) {}
};

class SPOK_BCryptFailure : public std::runtime_error
{
public:
	SPOK_BCryptFailure(const std::string& message) noexcept : std::runtime_error(message) {}
};

class SPOK_NCryptFailure : public std::runtime_error
{
public:
	SPOK_NCryptFailure(const std::string& message) noexcept : std::runtime_error(message) {}
};

class SPOK_InsufficientBuffer : public std::length_error
{
public:
	SPOK_InsufficientBuffer(const std::string& message) noexcept : std::length_error(message) {}
};

class SPOK_InvalidHandle : public std::invalid_argument
{
public:
	SPOK_InvalidHandle(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_InvalidState : public std::invalid_argument
{
public:
	SPOK_InvalidState(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_InvalidData : public std::invalid_argument
{
public:
	SPOK_InvalidData(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_InvalidSignature : public std::invalid_argument
{
public:
	SPOK_InvalidSignature(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_InvalidKey : public std::invalid_argument
{
public:
	SPOK_InvalidKey(const std::string& message) noexcept : std::invalid_argument(message) {}
};

class SPOK_TpmCmdFailed : public std::runtime_error
{
public:
	SPOK_TpmCmdFailed(const std::string& message) noexcept : std::runtime_error(message) {}
};

class SPOK_TcgLogFailure : public std::runtime_error
{
public:
	SPOK_TcgLogFailure(const std::string& message) noexcept : std::runtime_error(message) {}
};

#define SPOK_OKAY  ( 0)
#define SPOK_ERROR (0x80000000)

#define SPOK_SUCCESS(x) ((x & SPOK_ERROR) == 0)
#define SPOK_FAILURE(x) ((x & SPOK_ERROR) != 0)

#define SPOK_THROW_ERROR(x, msg) throw SPOK_Error::SPOK_This_Error(x, msg)

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
#define SPOK_TPMCMD_FAILED        (0x8000000C)
#define SPOK_TCGLOG_FAILURE       (0x8000000D)

#define SPOK_UNKNOWN_ERROR		  (0x8000FFFE)
#define SPOK_LAST_ERROR           (0x8000FFFF)
