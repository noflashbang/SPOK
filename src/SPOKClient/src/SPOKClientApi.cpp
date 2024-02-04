#include "SPOKClientApi.h"


SPOK_Handle SPC_Create()
{
	SPOKCore core;
	return core.GetVersion();
}

