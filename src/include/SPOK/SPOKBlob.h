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

	static Blob FromString(const std::string& str);
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
};

class SPOK_BinaryWriter
{
public:
	SPOK_BinaryWriter(SPOK_Blob::Blob& data) : m_data(data) {}
	~SPOK_BinaryWriter() = default;

	void Write(const uint8_t value);

	void LE_Write16(const uint16_t value);
	void LE_Write32(const uint32_t value);
	void LE_Write64(const uint64_t value);

	void BE_Write16(const uint16_t value);
	void BE_Write32(const uint32_t value);
	void BE_Write64(const uint64_t value);

	void Write(const uint8_t* source, const size_t size);
	void Write(const SPOK_Blob::Blob& source);

	void Seek(const size_t position);
	size_t Tell() const;

	void Clear();
	void Resize(const size_t size);

private:

	bool CanWrite(const size_t size) const;

	SPOK_Blob::Blob& m_data;
	size_t m_cursor = 0;
};

class SPOK_BinaryReader
{
public:
	SPOK_BinaryReader(const SPOK_Blob::Blob& data) : m_data(data) {}
	~SPOK_BinaryReader() = default;

	uint8_t  Read();

	uint16_t LE_Read16();
	uint32_t LE_Read32();
	uint64_t LE_Read64();

	uint16_t BE_Read16();
	uint32_t BE_Read32();
	uint64_t BE_Read64();

	void Read(uint8_t* dest, const size_t size);
	SPOK_Blob::Blob Read(const size_t size);

	void Seek(const size_t position);
	size_t Tell() const;
private:

	bool CanRead(const size_t size) const;

	const SPOK_Blob::Blob& m_data;
	size_t m_cursor = 0;
};
