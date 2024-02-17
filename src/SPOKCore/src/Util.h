#pragma once

#include "StandardLib.h"

#define SAFE_CAST_TO_ULONG(x) ((x) <= std::numeric_limits<unsigned long>::max() ? static_cast<unsigned long>(x) : throw std::overflow_error("size_t value is too large to fit in an unsigned long"))
#define SAFE_CAST_TO_INT(x) ((x) <= std::numeric_limits<int>::max() ? static_cast<int>(x) : throw std::overflow_error("size_t value is too large to fit in an int"))
#define SAFE_CAST_TO_UINT8(x) ((x) <= std::numeric_limits<uint8_t>::max() ? static_cast<uint8_t>(x) : throw std::overflow_error("size_t value is too large to fit in a uint8_t"))