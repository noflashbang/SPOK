#include "Blob.h"

void CopySpokBlob2CStylePtr(const SPOK_Blob& blob, unsigned char* destPtr, const size_t destSize, size_t& sizeOut)
{
	sizeOut = blob.size();
	if (destPtr == nullptr || destSize <= sizeOut)
	{
		return;
	}
	memcpy_s(destPtr, destSize, blob.data(), blob.size());
}
