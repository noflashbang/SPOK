#include "SPOKBlob.h"
#include "SPOKBlob.h"
#include "SPOKBlob.h"
#include "SPOKBlob.h"
#include "SPOKBlob.h"
#include "SPOKError.h"

SPOK_BinaryReader SPOK_Blob::GetReader() const
{
	return SPOK_BinaryReader::New(*this);
}

SPOK_BinaryWriter SPOK_Blob::GetWriter()
{
	return SPOK_BinaryWriter::New(*this);
}

SPOK_Blob SPOK_Blob::New(const std::vector<uint8_t>& source)
{
	return SPOK_Blob(source);
}

SPOK_Blob SPOK_Blob::New(const size_t size)
{
	return SPOK_Blob(size, 0);
}
SPOK_Blob SPOK_Blob::New(const uint8_t* data, const size_t size)
{
	return SPOK_Blob(data, size);
}

void SPOK_Blob::Copy2CStylePtr(const SPOK_Blob& source, uint8_t* destPtr, const size_t destSize, size_t& sizeOut)
{
	sizeOut = source.size();
	if (destPtr == nullptr || destSize <= sizeOut)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_Blob::Copy2CStylePtr out of bounds");
	}
	memcpy_s(destPtr, destSize, source.data(), source.size());
}

std::string SPOK_Blob::BlobToHex(const SPOK_Blob& blob)
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

SPOK_Blob SPOK_Blob::HexToBlob(const std::string& hex)
{
	SPOK_Blob blob;
	blob.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		blob.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
	}
	return blob;
}

std::string SPOK_Blob::BlobToBase64(const SPOK_Blob& blob)
{
	static const std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string base64;
	base64.reserve((blob.size() + 2) / 3 * 4);
	for (size_t i = 0; i < blob.size(); i += 3)
	{
		uint32_t value = blob[i] << 16;
		if (i + 1 < blob.size())
		{
			value |= blob[i + 1] << 8;
		}
		if (i + 2 < blob.size())
		{
			value |= blob[i + 2];
		}
		base64.push_back(base64Chars[(value >> 18) & 0x3F]);
		base64.push_back(base64Chars[(value >> 12) & 0x3F]);
		if (i + 1 < blob.size())
		{
			base64.push_back(base64Chars[(value >> 6) & 0x3F]);
		}
		else
		{
			base64.push_back('=');
		}
		if (i + 2 < blob.size())
		{
			base64.push_back(base64Chars[value & 0x3F]);
		}
		else
		{
			base64.push_back('=');
		}
	}
	return base64;
}

SPOK_Blob SPOK_Blob::Base64ToBlob(const std::string& base64)
{
	static const std::array<uint8_t, 256> base64Values = []()
		{
			std::array<uint8_t, 256> values;
			values.fill(0xFF);
			for (uint8_t i = 0; i < 64; i++)
			{
				values["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
			}
			values['='] = 0;
			return values;
		}();
		SPOK_Blob blob;
		blob.reserve((base64.size() + 3) / 4 * 3);
		for (size_t i = 0; i < base64.size(); i += 4)
		{
			uint32_t value = base64Values[base64[i]] << 18;
			value = value | (base64Values[base64[i + 1]] << 12);
			if (base64[i + 2] != '=')
			{
				value = value | (base64Values[base64[i + 2]] << 6);
			}
			if (base64[i + 3] != '=')
			{
				value = value | base64Values[base64[i + 3]];
			}
			blob.push_back((value >> 16) & 0xFF);
			if (base64[i + 2] != '=')
			{
				blob.push_back((value >> 8) & 0xFF);
			}
			if (base64[i + 3] != '=')
			{
				blob.push_back(value & 0xFF);
			}
		}
		return blob;
}

SPOK_Blob SPOK_Blob::FromString(const std::string& str)
{
	return SPOK_Blob(str.begin(), str.end());
}

SPOK_Blob SPOK_Blob::FromString(const std::wstring& str)
{
	return SPOK_Blob(str.begin(), str.end());
}

uint8_t SPOK_BinaryReader::Read()
{
	if (CanRead(1) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::Read out of bounds");
	}
	uint8_t value = m_data[m_cursor];
	m_cursor++;
	return value;
}
uint16_t SPOK_BinaryReader::LE_Read16()
{
	if (CanRead(2) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::LE_Read16 out of bounds");
	}
	uint16_t value = m_data[m_cursor] | (m_data[m_cursor + 1] << 8);
	m_cursor += 2;
	return value;
}

uint32_t SPOK_BinaryReader::LE_Read32()
{
	if (CanRead(4) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::LE_Read32 out of bounds");
	}
	uint32_t value = (uint32_t)m_data[m_cursor] | ((uint32_t)m_data[m_cursor + 1] << 8) | ((uint32_t)m_data[m_cursor + 2] << 16) | ((uint32_t)m_data[m_cursor + 3] << 24);
	m_cursor += 4;
	return value;
}

uint64_t SPOK_BinaryReader::LE_Read64()
{
	if (CanRead(8) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::LE_Read64 out of bounds");
	}
	uint64_t value = (uint64_t)m_data[m_cursor] | ((uint64_t)m_data[m_cursor + 1] << 8) | ((uint64_t)m_data[m_cursor + 2] << 16) | ((uint64_t)m_data[m_cursor + 3] << 24) | ((uint64_t)m_data[m_cursor + 4] << 32) | ((uint64_t)m_data[m_cursor + 5] << 40) | ((uint64_t)m_data[m_cursor + 6] << 48) | ((uint64_t)m_data[m_cursor + 7] << 56);
	m_cursor += 8;
	return value;
}

uint16_t SPOK_BinaryReader::BE_Read16()
{
	return EndianSwap::Swap16(LE_Read16());
}

uint32_t SPOK_BinaryReader::BE_Read32()
{
	return EndianSwap::Swap32(LE_Read32());
}

uint64_t SPOK_BinaryReader::BE_Read64()
{
	return EndianSwap::Swap64(LE_Read64());
}

void SPOK_BinaryWriter::Write(const uint8_t value)
{
	if (CanWrite(1) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryWriter::Write out of bounds");
	}
	m_data[m_cursor] = value;
	m_cursor++;
}

void SPOK_BinaryWriter::LE_Write16(const uint16_t value)
{
	if (CanWrite(2) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryWriter::LE_Write16 out of bounds");
	}
	m_data[m_cursor] = value & 0xFF;
	m_data[m_cursor + 1] = (value >> 8) & 0xFF;
	m_cursor += 2;
}
void SPOK_BinaryWriter::LE_Write32(const uint32_t value)
{
	if (CanWrite(4) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryWriter::LE_Write32 out of bounds");
	}
	m_data[m_cursor] = value & 0xFF;
	m_data[m_cursor + 1] = (value >> 8) & 0xFF;
	m_data[m_cursor + 2] = (value >> 16) & 0xFF;
	m_data[m_cursor + 3] = (value >> 24) & 0xFF;
	m_cursor += 4;
}
void SPOK_BinaryWriter::LE_Write64(const uint64_t value)
{
	if (CanWrite(8) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryWriter::LE_Write64 out of bounds");
	}
	m_data[m_cursor] = value & 0xFF;
	m_data[m_cursor + 1] = (value >> 8) & 0xFF;
	m_data[m_cursor + 2] = (value >> 16) & 0xFF;
	m_data[m_cursor + 3] = (value >> 24) & 0xFF;
	m_data[m_cursor + 4] = (value >> 32) & 0xFF;
	m_data[m_cursor + 5] = (value >> 40) & 0xFF;
	m_data[m_cursor + 6] = (value >> 48) & 0xFF;
	m_data[m_cursor + 7] = (value >> 56) & 0xFF;
	m_cursor += 8;
}

void SPOK_BinaryWriter::BE_Write16(const uint16_t value)
{
	LE_Write16(EndianSwap::Swap16(value));
}
void SPOK_BinaryWriter::BE_Write32(const uint32_t value)
{
	LE_Write32(EndianSwap::Swap32(value));
}
void SPOK_BinaryWriter::BE_Write64(const uint64_t value)
{
	LE_Write64(EndianSwap::Swap64(value));
}

void SPOK_BinaryReader::Read(uint8_t* dest, const size_t size)
{
	if (CanRead(size) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::Read out of bounds");
	}
	memcpy_s(dest, size, m_data.data() + m_cursor, size);
	m_cursor += size;
}

SPOK_Blob SPOK_BinaryReader::Read(const size_t size)
{
	if (CanRead(size) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryReader::Read out of bounds");
	}
	auto blob = SPOK_Blob::New(m_data.data() + m_cursor, size);
	m_cursor += size;
	return blob;
}

void SPOK_BinaryWriter::Write(const uint8_t* source, const size_t size)
{
	if (CanWrite(size) == false)
	{
		SPOK_THROW_ERROR(SPOK_INSUFFICIENT_BUFFER, "SPOK_BinaryWriter::Write out of bounds");
	}
	memcpy_s(m_data.data() + m_cursor, m_data.size() - m_cursor, source, size);
	m_cursor += size;
}

void SPOK_BinaryWriter::Write(const SPOK_Blob& source)
{
	Write(source.data(), source.size());
}

void SPOK_BinaryReader::Seek(const size_t position)
{
	if (position < m_data.size())
	{
		m_cursor = position;
	}
}

void SPOK_BinaryWriter::Seek(const size_t position)
{
	if (position < m_data.size())
	{
		m_cursor = position;
	}
}
size_t SPOK_BinaryReader::Tell() const
{
	return m_cursor;
}
SPOK_BinaryReader SPOK_BinaryReader::New(const SPOK_Blob& data)
{
	return SPOK_BinaryReader(data);
}
size_t SPOK_BinaryWriter::Tell() const
{
	return m_cursor;
}

void SPOK_BinaryWriter::Clear()
{
	m_data.clear();
	m_cursor = 0;
}
void SPOK_BinaryWriter::Resize(const size_t size)
{
	m_data.resize(size);
}

SPOK_BinaryWriter SPOK_BinaryWriter::New(SPOK_Blob& data)
{
	return SPOK_BinaryWriter(data);
}

bool SPOK_BinaryReader::CanRead(const size_t size) const
{
	return m_cursor + size <= m_data.size();
}
bool SPOK_BinaryWriter::CanWrite(const size_t size) const
{
	return m_cursor + size <= m_data.size();
}