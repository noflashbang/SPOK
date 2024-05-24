#include "SPOKError.h"

SPOKSTATUS SPOK_Error::SPOK_LippincottHandler()
{
	try
	{
		throw;
	}
	catch (const SPOK_Overflow& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_OVERFLOW;
	}
	catch (const SPOK_InvalidAlgorithm& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_ALGORITHM;
	}
	catch (const SPOK_NotFound& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_NOT_FOUND;
	}
	catch (const SPOK_BCryptFailure& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_BCRYPT_FAILURE;
	}
	catch (const SPOK_NCryptFailure& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_NCRYPT_FAILURE;
	}
	catch (const SPOK_InsufficientBuffer& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INSUFFICIENT_BUFFER;
	}
	catch (const SPOK_InvalidHandle& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_HANDLE;
	}
	catch (const SPOK_InvalidState& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_STATE;
	}
	catch (const SPOK_InvalidData& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_DATA;
	}
	catch (const SPOK_InvalidSignature& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_SIGNATURE;
	}
	catch (const SPOK_InvalidKey& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_INVALID_KEY;
	}
	catch (const SPOK_TpmCmdFailed& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_TPMCMD_FAILED;
	}
	catch (const SPOK_TcgLogFailure& e)
	{
		SPOK_SetLastError(e.what());
		return SPOK_TCGLOG_FAILURE;
	}
	catch (...)
	{
		SPOK_SetLastError("Unknown error");
		return SPOK_UNKNOWN_ERROR;
	}
}

std::string SPOK_Error::_lastError = "";

void SPOK_Error::SPOK_SetLastError(const std::string& message)
{
	_lastError = message;
}

std::exception SPOK_Error::SPOK_This_Error(SPOKSTATUS kind, std::string msg)
{
	switch (kind)
	{
	case SPOK_OVERFLOW:            return SPOK_Overflow(msg); break;
	case SPOK_INVALID_ALGORITHM:   return SPOK_InvalidAlgorithm(msg); break;
	case SPOK_NOT_FOUND:           return SPOK_NotFound(msg); break;
	case SPOK_BCRYPT_FAILURE:      return SPOK_BCryptFailure(msg); break;
	case SPOK_NCRYPT_FAILURE:      return SPOK_NCryptFailure(msg); break;
	case SPOK_INSUFFICIENT_BUFFER: return SPOK_InsufficientBuffer(msg); break;
	case SPOK_INVALID_HANDLE:      return SPOK_InvalidHandle(msg); break;
	case SPOK_INVALID_STATE:       return SPOK_InvalidState(msg); break;
	case SPOK_INVALID_DATA:        return SPOK_InvalidData(msg); break;
	case SPOK_INVALID_SIGNATURE:   return SPOK_InvalidSignature(msg); break;
	case SPOK_INVALID_KEY:         return SPOK_InvalidKey(msg); break;
	case SPOK_TPMCMD_FAILED:       return SPOK_TpmCmdFailed(msg); break;
	case SPOK_TCGLOG_FAILURE:      return SPOK_TcgLogFailure(msg); break;
	default:                       return std::runtime_error(msg); break;
	}
}