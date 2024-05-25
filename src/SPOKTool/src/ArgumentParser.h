#pragma once

#include "stdlib.h"
#include "util.h"

class ArgumentParser
{
public:

	ArgumentParser(int argc, wchar_t* argv[]);

	~ArgumentParser();

	bool IsCommand(const std::wstring& command) const;
	std::wstring GetCommand() const;
	
	bool HasArgument(const std::wstring& key) const;
	std::wstring GetArgument(const std::wstring& key) const;
	
private:

	void Parse(int argc, wchar_t* argv[]);

	std::wstring m_command;
	std::map<std::wstring, std::wstring> m_args;
};