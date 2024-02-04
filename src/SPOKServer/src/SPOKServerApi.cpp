#include "SPOKServerApi.h"


SPOK_Handle SPS_Create()
{
	SPOKCore core;
	return core.GetVersion();
}
