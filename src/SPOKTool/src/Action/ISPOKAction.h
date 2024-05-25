#pragma once

#include "..\stdlib.h"
#include "..\ArgumentParser.h"
#include "..\util.h"

class ISPOKAction
{
public:

	ISPOKAction() = default;
	virtual ~ISPOKAction() = default;

	virtual bool ValidateArguments(const ArgumentParser& parser) = 0;
	virtual void Execute(const ArgumentParser& parser) = 0;
	virtual std::wstring UsageLine() const = 0;

protected:

	inline bool IsCommand(const ArgumentParser& parser, const std::wstring& command) const
	{
		return parser.IsCommand(command);
	}

	inline bool HasArgument(const ArgumentParser& parser, const std::wstring& key) const
	{
		return parser.HasArgument(key);
	}

	inline std::wstring GetArgument(const ArgumentParser& parser, const std::wstring& key) const
	{
		return parser.GetArgument(key);
	}
};