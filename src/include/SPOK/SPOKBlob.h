//MIT License
//
//Copyright(c) 2024 noflashbang
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

#pragma once 
#include <array>
#include <vector>
#include <algorithm>
#include <string>

#include "SPOKApiTypes.h"

class SPOK_Blob
{
public:

	typedef std::vector<uint8_t> Blob;

	static Blob New(const size_t size);
	static Blob New(const uint8_t* data, const size_t size);

	static void Copy2CStylePtr(const Blob& source, uint8_t* destPtr, const size_t destSize, size_t& sizeOut);
	static std::string BlobToHex(const Blob& blob);
	static Blob HexToBlob(const std::string& hex);

	static std::string BlobToBase64(const Blob& blob);
	static Blob Base64ToBlob(const std::string& base64);
};

class EndianSwap
{
public:
	static inline uint16_t Swap16(uint16_t value)
	{
		return (value >> 8) | (value << 8);
	}

	static inline uint32_t Swap32(uint32_t value)
	{
		return (value >> 24) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | (value << 24);
	}

	static inline uint64_t Swap64(uint64_t value)
	{
		return (value >> 56) | ((value >> 40) & 0x000000000000FF00) | ((value >> 24) & 0x0000000000FF0000) | ((value >> 8) & 0x00000000FF000000) | ((value << 8) & 0x000000FF00000000) | ((value << 24) & 0x0000FF0000000000) | ((value << 40) & 0x00FF000000000000) | (value << 56);
	}

	//Might need these for 'optimizations' later
	//static inline void Swap16InToByteArray(uint8_t* data, uint16_t value)
	//{
	//	data[0] = value >> 8;
	//	data[1] = value & 0xFF;
	//}
	//
	//static inline void Swap32InToByteArray(uint8_t* data, uint32_t value)
	//{
	//	data[0] = value >> 24;
	//	data[1] = (value >> 16) & 0xFF;
	//	data[2] = (value >> 8) & 0xFF;
	//	data[3] = value & 0xFF;
	//}
	//
	//static inline void Swap64InToByteArray(uint8_t* data, uint64_t value)
	//{
	//	data[0] = value >> 56;
	//	data[1] = (value >> 48) & 0xFF;
	//	data[2] = (value >> 40) & 0xFF;
	//	data[3] = (value >> 32) & 0xFF;
	//	data[4] = (value >> 24) & 0xFF;
	//	data[5] = (value >> 16) & 0xFF;
	//	data[6] = (value >> 8) & 0xFF;
	//	data[7] = value & 0xFF;
	//}
	//
	//static inline uint16_t Swap16FromByteArray(const uint8_t* data)
	//{
	//	return (data[0] << 8) | data[1];
	//}
	//
	//static inline uint32_t Swap32FromByteArray(const uint8_t* data)
	//{
	//	return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	//}
	//
	//static inline uint64_t Swap64FromByteArray(const uint8_t* data)
	//{
	//	return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | (uint64_t)data[7];
	//}
};

class SPOK_BinaryStream
{
public:
	SPOK_BinaryStream(SPOK_Blob::Blob& data) : m_data(data) {}
	~SPOK_BinaryStream() = default;

	uint8_t  Read();

	uint16_t LE_Read16();
	uint32_t LE_Read32();
	uint64_t LE_Read64();

	uint16_t BE_Read16();
	uint32_t BE_Read32();
	uint64_t BE_Read64();

	void Write(const uint8_t value);

	void LE_Write16(const uint16_t value);
	void LE_Write32(const uint32_t value);
	void LE_Write64(const uint64_t value);

	void BE_Write16(const uint16_t value);
	void BE_Write32(const uint32_t value);
	void BE_Write64(const uint64_t value);

	void Read(uint8_t* dest, const size_t size);
	void Write(const uint8_t* source, const size_t size);

	void Seek(const size_t position);
	size_t Tell() const;

	void Clear();
	void Resize(const size_t size);

private:

	bool CanRead(const size_t size) const;
	bool CanWrite(const size_t size) const;

	SPOK_Blob::Blob& m_data;
	size_t m_cursor = 0;
};

