#include "SPOKError.h"

SPOKSTATUS SPOK_Error::SPOK_LippincottHandler()
{
	try
	{
		throw;
	}
	catch (const std::runtime_error& e)
	{
		return SPOK_ErrorMessageToStatus(e.what());
	}
	catch (...)
	{
		return SPOK_UNKNOWN_ERROR;
	}
}

SPOKSTATUS SPOK_Error::SPOK_ErrorMessageToStatus(const std::string& message)
{
	for (const auto& [status, msg] : m_ErrorMessages)
	{
		if (msg == message)
		{
			return status;
		}
	}
	return SPOK_UNKNOWN_ERROR;

}
std::string SPOK_Error::SPOK_StatusToErrorMessage(SPOKSTATUS status)
{
	auto it = m_ErrorMessages.find(status);
	if (it != m_ErrorMessages.end())
	{
		return it->second;
	}
	return "Unknown error";
}

void SPOK_Error::SPOK_SetLastError(const std::string& message)
{
	m_ErrorMessages[SPOK_LAST_ERROR] = message;
}

std::map<SPOKSTATUS, std::string> SPOK_Error::m_ErrorMessages = {
	{SPOK_UNKNOWN_ERROR, "Unknown error"},
	{SPOK_OVERFLOW, "Overflow"},
	{SPOK_INVALID_ALGORITHM, "Invalid algorithm"},
	{SPOK_NOT_FOUND, "Not found"},
	{SPOK_BCRYPT_FAILURE, "BCrypt failure"},
	{SPOK_NCRYPT_FAILURE, "NCrypt failure"},
	{SPOK_INSUFFICIENT_BUFFER, "Insufficient buffer"},
	{SPOK_INVALID_HANDLE, "Invalid handle"},
	{SPOK_INVALID_STATE, "Invalid state"},
	{SPOK_INVALID_DATA, "Invalid data"},
	{SPOK_INVALID_SIGNATURE, "Invalid signature"},
	{SPOK_INVALID_KEY, "Invalid key"},
	{SPOK_TPMCMD_FAILED, "TPM command failed"},
	{SPOK_TCGLOG_FAILURE, "TCG log failure"}
};