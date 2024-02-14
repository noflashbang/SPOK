#pragma once

#include "StandardLib.h"
#include "SPOKCore.h"

void CopySpokBlob2CStylePtr(const SPOK_Blob& blob, unsigned char* destPtr, const size_t destSize, size_t& sizeOut);

