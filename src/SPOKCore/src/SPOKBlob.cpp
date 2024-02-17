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

std::string SPOK_Blob::BlobToHex(const Blob& blob)
{
	std::string hex;
	hex.reserve(blob.size() * 2);
	for (const auto& byte : blob)
	{
		hex += "0123456789ABCDEF"[byte >> 4];
		hex += "0123456789ABCDEF"[byte & 0x0F];
	}
	return hex;
}

SPOK_Blob::Blob SPOK_Blob::HexToBlob(const std::string& hex)
{
	Blob blob;
	blob.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		blob.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
	}
	return blob;
}



