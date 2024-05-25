#include "ArgumentParser.h"


ArgumentParser::ArgumentParser(int argc, wchar_t* argv[])
{
	Parse(argc, argv);
};

ArgumentParser::~ArgumentParser()
{
}

bool ArgumentParser::IsCommand(const std::wstring& command) const
{
	return m_command == Util::StringToUpper(command);
}

std::wstring ArgumentParser::GetCommand() const
{
	return m_command;
}

bool ArgumentParser::HasArgument(const std::wstring& key) const
{
	return m_args.find(Util::StringToUpper(key)) != m_args.end();
}

std::wstring ArgumentParser::GetArgument(const std::wstring& key) const
{
	if (HasArgument(Util::StringToUpper(key)))
	{
		return m_args.at(key);
	}
	return L"";
}

void ArgumentParser::Parse(int argc, wchar_t* argv[])
{
	for (int i = 1; i < argc; i++)
	{
		if (i == 1)
		{
			m_command = Util::StringToUpper(argv[i]);
			continue;
		}

		std::wstring arg = argv[i];
		if (arg[0] == '-')
		{
			std::wstring key = arg.substr(1);
			std::wstring value = L"";
			if (i + 1 < argc)
			{
				std::wstring nextArg = argv[i + 1];
				if (nextArg[0] != '-')
				{
					value = nextArg;
					i++;
				}
			}
			m_args[Util::StringToUpper(key)] = Util::StringToUpper(value);
		}
	}
}
