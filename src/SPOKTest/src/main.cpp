
#include <SPOKCore.h>
#include <SPOKNonce.h>

#include <SPOKClientApi.h>
#include <SPOKServerApi.h>

#include <HasherUtil.h>
#include <SPOKBlob.h>

#include <TcgLog.h>

#include <catch2/catch_test_macros.hpp>

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

TEST_CASE("RSA Operations")
{
	auto key_128 = BCryptUtil::GenerateRsaKeyPair(KeySize::RSA_1024);
	auto key_256 = BCryptUtil::GenerateRsaKeyPair(KeySize::RSA_2048);
	auto key_512 = BCryptUtil::GenerateRsaKeyPair(KeySize::RSA_4096);

	auto BCryptKey_128 = BCryptKey(key_128);
	auto BCryptKey_256 = BCryptKey(key_256);
	auto BCryptKey_512 = BCryptKey(key_512);

	auto pub_128 = BCryptKey_128.GetPublicKey();
	auto pub_256 = BCryptKey_256.GetPublicKey();
	auto pub_512 = BCryptKey_512.GetPublicKey();

	auto key_128_full = SPOK_Blob::BlobToBase64(key_128);
	auto key_256_full = SPOK_Blob::BlobToBase64(key_256);
	auto key_512_full = SPOK_Blob::BlobToBase64(key_512);

	auto key_128_pub = SPOK_Blob::BlobToBase64(pub_128);
	auto key_256_pub = SPOK_Blob::BlobToBase64(pub_256);
	auto key_512_pub = SPOK_Blob::BlobToBase64(pub_512);

	INFO("Key 128: " << key_128_full);
	INFO("Key 256: " << key_256_full);
	INFO("Key 512: " << key_512_full);

	INFO("Key 128 Pub: " << key_128_pub);
	INFO("Key 256 Pub: " << key_256_pub);
	INFO("Key 512 Pub: " << key_512_pub);

	auto secret = BCryptUtil::GetRandomBytes(32);

	auto enc_128 = BCryptKey_128.Encrypt(secret);
	auto enc_256 = BCryptKey_256.Encrypt(secret);
	auto enc_512 = BCryptKey_512.Encrypt(secret);

	auto dec_128 = BCryptKey_128.Decrypt(enc_128);
	auto dec_256 = BCryptKey_256.Decrypt(enc_256);
	auto dec_512 = BCryptKey_512.Decrypt(enc_512);

	REQUIRE(secret == dec_128);
	REQUIRE(secret == dec_256);
	REQUIRE(secret == dec_512);

	auto sig_128 = BCryptKey_128.Sign(secret);
	auto sig_256 = BCryptKey_256.Sign(secret);
	auto sig_512 = BCryptKey_512.Sign(secret);
		
	auto ver_128 = BCryptKey_128.Verify(secret, sig_128);
	auto ver_256 = BCryptKey_256.Verify(secret, sig_256);
	auto ver_512 = BCryptKey_512.Verify(secret, sig_512);

	REQUIRE(ver_128);
	REQUIRE(ver_256);
	REQUIRE(ver_512);
}


TEST_CASE("Platform RSA Operations")
{		
	//SPC_CreatePlatformKey(L"TestKey", NCRYPT_MACHINE_KEY::NO);

	auto secret = BCryptUtil::GetRandomBytes(32);
	
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 512;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	SPC_PlatformEncrypt(L"TestKey", NCRYPT_MACHINE_KEY::NO, secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto enc = SPOK_Blob::New(pBytes.get(), sizeOut);

	ZeroMemory(pBytes.get(), cbSize);

	SPC_PlatformDecrypt(L"TestKey", NCRYPT_MACHINE_KEY::NO, enc.data(), enc.size(), pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut == secret.size());
	REQUIRE(0 == memcmp(pBytes.get(), secret.data(), sizeOut));

	ZeroMemory(pBytes.get(), cbSize);

	SPC_PlatformSign(L"TestKey", NCRYPT_MACHINE_KEY::NO, secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto sig = SPOK_Blob::New(pBytes.get(), sizeOut);

	ZeroMemory(pBytes.get(), cbSize);

	auto isGood = SPC_PlatformVerifySignature(L"TestKey", NCRYPT_MACHINE_KEY::NO, secret.data(), secret.size(), sig.data(), sig.size());

	REQUIRE(isGood);
}


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

	INFO("EKPub Hash is " << str);
}

TEST_CASE("SPC_GetSRK")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 512;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	//get the size
	SPC_GetStorageRootKey(pBytes.get(), cbSize, sizeOut);

	SPOK_Blob::Blob blob = SPOK_Blob::New(pBytes.get(), sizeOut);

	auto hash = Hasher::PublicKeyHash(blob);
	auto str = SPOK_Blob::BlobToHex(hash);

	REQUIRE(sizeOut > 0);
	REQUIRE(str.size() > 0);

	INFO("EKPub Hash is " << str);
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

TEST_CASE("SPC_GetBootLog")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 90000;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	SPC_GetBootLog(pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);

	auto blob = SPOK_Blob::New(pBytes.get(), sizeOut);
	auto log = TcgLog::Parse(blob);

	REQUIRE(log.Events.size() > 0);
}

TEST_CASE("SPC_GetFilteredBootLog")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 90000;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	size_t sizeOut = 0;

	SPC_GetFilteredBootLog((PCR_13 | PCR_14), pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);

	auto blob = SPOK_Blob::New(pBytes.get(), sizeOut);
	auto log = TcgLog::Parse(blob);

	REQUIRE(log.Events.size() > 0);
}

TEST_CASE("SPC_AIKGetPlatformAttestation")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 90000;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

	bool exists = SPC_AIKExists(name.c_str(), flag);

	if (!exists)
	{
		auto nonce = SPOK_Nonce::Zero();
		SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
	}

	size_t sizeOut = 0;
	auto nonce = SPOK_Nonce::Zero();
	SPC_AIKGetPlatformAttestation(name.c_str(), flag, nonce.data(), nonce.size(), (PCR_13 | PCR_14), pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);
}

TEST_CASE("SPC_AIKGetKeyAttestation")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 90000;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

	std::wstring nameKey = L"TestKey";
	NCRYPT_MACHINE_KEY flagKey = NCRYPT_MACHINE_KEY::NO;

	bool exists = SPC_AIKExists(name.c_str(), flag);

	if (!exists)
	{
		auto nonce = SPOK_Nonce::Zero();
		SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
	}

	size_t sizeOut = 0;
	auto nonce = SPOK_Nonce::Zero();
	SPC_AIKGetKeyAttestation(name.c_str(), flag, nonce.data(), nonce.size(), nameKey.c_str(), flagKey, pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);
}