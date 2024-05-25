#pragma

#include "CreateAikAction.h"
#include <SPOKClientApi.h>
#include <SPOKBlob.h>
#include <SPOKNonce.h>
#include <HasherUtil.h>


bool CreateAikAction::ValidateArguments(const ArgumentParser& parser) 
{
	return IsCommand(parser, L"CREATEAIK") && HasArgument(parser, L"AIK") && HasArgument(parser, L"NONCE");
}

void CreateAikAction::Execute(const ArgumentParser& parser)
{
	std::wstring name = GetArgument(parser, L"AIK");
	std::wstring nonceStr = GetArgument(parser, L"NONCE");

	auto nonceBlob = SPOK_Blob::FromString(nonceStr);
	auto nonce = Hasher::Blob2Nonce(nonceBlob);
	auto result = SPC_AIKCreate(name.c_str(), NCRYPT_MACHINE_KEY::NO, nonce.data(), nonce.size());

	if (SPOK_FAILURE(result))
	{
		std::wcout << L"Failed to create AIK: " << result << std::endl;
	}
	else
	{
		std::wcout << L"AIK " << name << L" created successfully" << std::endl;
	}
}

std::wstring CreateAikAction::UsageLine() const
{
	return L"CREATEAIK -aik <name> -nonce <nonce>";
}
