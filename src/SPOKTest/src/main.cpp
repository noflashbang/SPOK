
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

TEST_CASE("SPC_AIKCreate")
{
	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
	bool exists = SPC_AIKExists(name, flag);
	
	if (exists)
	{
		SPC_AIKDelete(name, flag);
	}

	SPOK_Nonce nonce = { 0 };
	SPC_AIKCreate(name, flag, nonce);
}

TEST_CASE("SPC_AIKDelete")
{
	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
	bool exists = SPC_AIKExists(name, flag);

	if (exists)
	{
		SPC_AIKDelete(name, flag);
	}
}

TEST_CASE("SPC_AIKExists")
{
	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
	bool exists = SPC_AIKExists(name, flag);
	REQUIRE(exists == false);
}