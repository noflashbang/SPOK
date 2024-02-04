
#include <SPOKClientApi.h>
#include <SPOKServerApi.h>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("SPC_Create returns a valid handle")
{
	SPOK_Handle handle = SPC_Create();
	REQUIRE(handle != 0);
}

TEST_CASE("SPS_Create returns a valid handle")
{
	SPOK_Handle handle = SPS_Create();
	REQUIRE(handle != 0);
}