#pragma once

#include "StandardLib.h"

#define SAFE_CAST_TO_UINT32(x) ((x) <= std::numeric_limits<uint32_t>::max() ? static_cast<uint32_t>(x) : throw std::overflow_error("size_t value is too large to fit in an uint32_t"))
#define SAFE_CAST_TO_INT32(x) ((x) <= std::numeric_limits<int32_t>::max() ? static_cast<int32_t>(x) : throw std::overflow_error("size_t value is too large to fit in an int32_t"))
#define SAFE_CAST_TO_UINT8(x) ((x) <= std::numeric_limits<uint8_t>::max() ? static_cast<uint8_t>(x) : throw std::overflow_error("size_t value is too large to fit in a uint8_t"))