
#include <SPOKCore.h>
#include <SPOKNonce.h>

#include <SPOKClientApi.h>
#include <SPOKServerApi.h>

#include <HasherUtil.h>
#include <SPOKBlob.h>


#include <catch2/catch_test_macros.hpp>

TEST_CASE("SPC_Create returns a valid handle")
{
	SPOK_Handle handle = SPC_Create();
	REQUIRE(handle == 0);
}

TEST_CASE("SPS_Create returns a valid handle")
{
	SPOK_Handle handle = SPS_Create();
	REQUIRE(handle == 0);
}

//DONT NEED TO DO THESE ALL THE TIME
//TEST_CASE("SPC_AIKCreate")
//{
//	std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name, flag);
//	
//	if (exists)
//	{
//		SPC_AIKDelete(name, flag);
//	}
//
//	SPOK_Nonce nonce = { 0 };
//	SPC_AIKCreate(name, flag, nonce);
//}
//
//TEST_CASE("SPC_AIKDelete")
//{
//	std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name, flag);
//
//	if (exists)
//	{
//		SPC_AIKDelete(name, flag);
//	}
//}
//
//TEST_CASE("SPC_AIKExists")
//{
//	std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name, flag);
//	REQUIRE(exists == false);
//}

TEST_CASE("SPC_AIKGetPublicKey")
{
 	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 512;
	
	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

	bool exists = SPC_AIKExists(name.c_str(), flag);

	if (!exists)
	{
		auto nonce = SPOK_Nonce::Zero();
		SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
	}

	//get the size
	SPC_AIKGetPublicKey(name.c_str(), flag, pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);
}

TEST_CASE("SPC_GetPublicEndorsementKey")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 512;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	//get the size
	SPC_GetEndorsementPublicKey(pBytes.get(), cbSize, sizeOut);

	SPOK_Blob::Blob blob = SPOK_Blob::New(pBytes.get(), sizeOut);

	auto hash = Hasher::PublicKeyHash(blob);
	auto str = SPOK_Blob::BlobToHex(hash);

	REQUIRE(sizeOut > 0);
	REQUIRE(str.size() > 0);
}

TEST_CASE("SPC_AIKGetChallengeBinding")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 1024;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

	bool exists = SPC_AIKExists(name.c_str(), flag);

	if (!exists)
	{
		auto nonce = SPOK_Nonce::Zero();
		SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
	}

	SPC_AIKGetChallengeBinding(name.c_str(), flag, pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);
}

TEST_CASE("SPC_GetPCRTable")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 1024;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	SPC_GetPCRTable(pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);
}