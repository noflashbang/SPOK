#include <SPOKCore.h>
#include <SPOKClientApi.h>
#include <SPOKServerApi.h>

#include <SPOKNonce.h>
#include <SPOKError.h>
#include <HasherUtil.h>
#include <SPOKBlob.h>
#include <SPOKPcrs.h>
#include <TcgLog.h>

#include "stdlib.h"

#include "Action\ISPOKAction.h"
#include "Action\CreateAikAction.h"

int wmain(int argc, wchar_t* argv[])
{
	auto args = ArgumentParser(argc, argv);

	std::vector<ISPOKAction*> actions;
	actions.push_back(new CreateAikAction());

	bool foundAnAction = false;
	for (auto action : actions)
	{
		if (action->ValidateArguments(args))
		{
			foundAnAction = true;
			action->Execute(args);
			break;
		}
	}

	if (!foundAnAction)
	{
		std::wcout << L"Usage:" << std::endl;
		for (auto action : actions)
		{
			std::wcout << action->UsageLine() << std::endl;
		}
	}
	
	return 0;
}

