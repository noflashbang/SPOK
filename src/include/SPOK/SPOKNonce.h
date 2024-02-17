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

#include "SPOKApiTypes.h"
#include "SPOKCore.h"


class SPOK_Nonce
{
public:

	typedef std::array<uint8_t, SHA1_DIGEST_SIZE> Nonce;

	static Nonce Zero()
	{
		Nonce nonce;
		std::fill(nonce.begin(), nonce.end(), 0);
		return nonce;
	};

	static Nonce Make(const uint8_t* data, size_t size)
	{
		auto nonce = Zero();
		auto min = std::min(size, nonce.max_size());
		memcpy(nonce.data(), data, min);
		return nonce;
	};
};


