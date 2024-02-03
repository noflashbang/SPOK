
#include <SPOKApi.h>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("SPOK_Create returns a valid handle")
{
	SPOK_Handle handle = SPOK_Create();
	REQUIRE(handle != 0);
}