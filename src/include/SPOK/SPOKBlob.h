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

class SPOK_BinaryReader;
class SPOK_BinaryWriter;

class SPOK_Blob : public std::vector<uint8_t>
{
public:
	SPOK_Blob() : std::vector<uint8_t>() {};
	SPOK_Blob(size_type size) : std::vector<uint8_t>(size) {};
	SPOK_Blob(size_type size, const uint8_t& value) : std::vector<uint8_t>(size, value) {};
	SPOK_Blob(const uint8_t* data, size_type size) : std::vector<uint8_t>(data, data + size) {};
	SPOK_Blob(const std::vector<uint8_t>& other) : std::vector<uint8_t>(other) {};
	SPOK_Blob(const SPOK_Blob& other) : std::vector<uint8_t>(other) {};
	SPOK_Blob(SPOK_Blob&& other) noexcept : std::vector<uint8_t>(std::move(other)) {};
	SPOK_Blob(std::initializer_list<uint8_t> il) : std::vector<uint8_t>(il) {};
	template <class InputIt>
	SPOK_Blob(InputIt first, InputIt last) : std::vector<uint8_t>(first, last) {};

	SPOK_Blob& operator=(const SPOK_Blob& other)
	{
		std::vector<uint8_t>::operator=(other);
		return *this;
	};

	SPOK_Blob& operator=(SPOK_Blob&& other) noexcept
	{
		std::vector<uint8_t>::operator=(std::move(other));
		return *this;
	};

	~SPOK_Blob() = default;

	SPOK_BinaryReader GetReader() const;
	SPOK_BinaryWriter GetWriter();

	//constructors
	static SPOK_Blob New(const std::vector<uint8_t>& source);
	static SPOK_Blob New(const size_t size);
	static SPOK_Blob New(const uint8_t* data, const size_t size);

	//c style array conversion
	static void Copy2CStylePtr(const SPOK_Blob& source, uint8_t* destPtr, const size_t destSize, size_t& sizeOut);

	//hex conversions
	static std::string BlobToHex(const SPOK_Blob& blob);
	static SPOK_Blob HexToBlob(const std::string& hex);

	//base64 conversions
	static std::string BlobToBase64(const SPOK_Blob& blob);
	static SPOK_Blob Base64ToBlob(const std::string& base64);

	//string conversions
	static SPOK_Blob FromString(const std::string& str);
	static SPOK_Blob FromString(const std::wstring& str);

private:

};

class EndianSwap
{
public:
	static inline uint16_t Swap16(uint16_t value)
	{
		return (value >> 8) | (value << 8);
	};

	static inline uint32_t Swap32(uint32_t value)
	{
		return (value >> 24) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | (value << 24);
	};

	static inline uint64_t Swap64(uint64_t value)
	{
		return (value >> 56) | ((value >> 40) & 0x000000000000FF00) | ((value >> 24) & 0x0000000000FF0000) | ((value >> 8) & 0x00000000FF000000) | ((value << 8) & 0x000000FF00000000) | ((value << 24) & 0x0000FF0000000000) | ((value << 40) & 0x00FF000000000000) | (value << 56);
	};
};

class SPOK_BinaryWriter
{
public:
	SPOK_BinaryWriter(SPOK_Blob& data) : m_data(data) {}
	~SPOK_BinaryWriter() = default;

	void Write(const uint8_t value);

	void LE_Write16(const uint16_t value);
	void LE_Write32(const uint32_t value);
	void LE_Write64(const uint64_t value);

	void BE_Write16(const uint16_t value);
	void BE_Write32(const uint32_t value);
	void BE_Write64(const uint64_t value);

	void Write(const uint8_t* source, const size_t size);
	void Write(const SPOK_Blob& source);

	void Seek(const size_t position);
	size_t Tell() const;

	void Clear();
	void Resize(const size_t size);

	static SPOK_BinaryWriter New(SPOK_Blob& data);
private:

	bool CanWrite(const size_t size) const;

	SPOK_Blob& m_data;
	size_t m_cursor = 0;
};

class SPOK_BinaryReader
{
public:
	SPOK_BinaryReader(const SPOK_Blob& data) : m_data(data) {}
	~SPOK_BinaryReader() = default;

	uint8_t  Read();

	uint16_t LE_Read16();
	uint32_t LE_Read32();
	uint64_t LE_Read64();

	uint16_t BE_Read16();
	uint32_t BE_Read32();
	uint64_t BE_Read64();

	void Read(uint8_t* dest, const size_t size);
	SPOK_Blob Read(const size_t size);

	void Seek(const size_t position);
	size_t Tell() const;

	static SPOK_BinaryReader New(const SPOK_Blob& data);

private:

	bool CanRead(const size_t size) const;

	const SPOK_Blob& m_data;
	size_t m_cursor = 0;
};
