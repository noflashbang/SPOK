#include "SPOKBlob.h"


SPOK_Blob::Blob SPOK_Blob::New(const size_t size)
{
	return Blob(size, 0);
}
SPOK_Blob::Blob SPOK_Blob::New(const uint8_t* data, const size_t size)
{
	return Blob(data, data + size);
}

void SPOK_Blob::Copy2CStylePtr(const SPOK_Blob::Blob& source, uint8_t* destPtr, const size_t destSize, size_t& sizeOut)
{
	sizeOut = source.size();
	if (destPtr == nullptr || destSize <= sizeOut)
	{
		return;
	}
	memcpy_s(destPtr, destSize, source.data(), source.size());
}



