
#include <SPOKCore.h>
#include <SPOKNonce.h>

#include <SPOKClientApi.h>
#include <SPOKServerApi.h>

#include <HasherUtil.h>
#include <SPOKBlob.h>
#include <SPOKPcrs.h>

#include <TcgLog.h>

#include <catch2/catch_test_macros.hpp>

//DONT NEED TO DO THESE ALL THE TIME
//TEST_CASE("SPC_AIKCreate")
//{
//	const std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name.c_str(), flag);
//	
//	if (exists)
//	{
//		SPC_AIKDelete(name.c_str(), flag);
//	}
//
//	auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
//	SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
//}

//TEST_CASE("SPC_AIKDelete")
//{
//	const std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name.c_str(), flag);
//
//	if (exists)
//	{
//		SPC_AIKDelete(name.c_str(), flag);
//	}
//}

//TEST_CASE("SPC_AIKExists")
//{
//	const std::wstring name = L"TestAIK";
//	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;
//	bool exists = SPC_AIKExists(name.c_str(), flag);
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

	auto enc_128 = BCryptKey_128.Encrypt(secret, false);
	auto enc_256 = BCryptKey_256.Encrypt(secret, false);
	auto enc_512 = BCryptKey_512.Encrypt(secret, false);

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

TEST_CASE("Server RSA Operations")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 2048;

	pBytes = std::make_unique<unsigned char[]>(cbSize);
	size_t sizeOut = 0;
	
	SPS_GenerateRSAKeyPair(1024, pBytes.get(), cbSize, sizeOut);
	auto key_128 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);
	
	SPS_GenerateRSAKeyPair(2048, pBytes.get(), cbSize, sizeOut);
	auto key_256 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_GenerateRSAKeyPair(4096, pBytes.get(), cbSize, sizeOut);
	auto key_512 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	auto secret = BCryptUtil::GetRandomBytes(32);

	SPS_Encrypt(key_128.data(), key_128.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto enc_128 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Encrypt(key_256.data(), key_256.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto enc_256 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Encrypt(key_512.data(), key_512.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto enc_512 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Decrypt(key_128.data(), key_128.size(), enc_128.data(), enc_128.size(), pBytes.get(), cbSize, sizeOut);
	auto dec_128 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Decrypt(key_256.data(), key_256.size(), enc_256.data(), enc_256.size(), pBytes.get(), cbSize, sizeOut);
	auto dec_256 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Decrypt(key_512.data(), key_512.size(), enc_512.data(), enc_512.size(), pBytes.get(), cbSize, sizeOut);
	auto dec_512 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	REQUIRE(secret == dec_128);
	REQUIRE(secret == dec_256);
	REQUIRE(secret == dec_512);

	SPS_Sign(key_128.data(), key_128.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto sig_128 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Sign(key_256.data(), key_256.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto sig_256 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	SPS_Sign(key_512.data(), key_512.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);
	auto sig_512 = SPOK_Blob::New(pBytes.get(), sizeOut);
	ZeroMemory(pBytes.get(), cbSize);

	auto ver_128 = SPS_VerifySignature(key_128.data(), key_128.size(), secret.data(), secret.size(), sig_128.data(), sig_128.size());
	auto ver_256 = SPS_VerifySignature(key_256.data(), key_256.size(), secret.data(), secret.size(), sig_256.data(), sig_256.size());
	auto ver_512 = SPS_VerifySignature(key_512.data(), key_512.size(), secret.data(), secret.size(), sig_512.data(), sig_512.size());

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
		auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
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

	{
		bool exists = SPC_AIKExists(name.c_str(), flag);

		if (!exists)
		{
			auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
			SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
		}

		SPC_AIKGetChallengeBinding(name.c_str(), flag, pBytes.get(), cbSize, sizeOut);

		REQUIRE(sizeOut > 0);
	}
	{
		auto handle = SPS_AIKTpmAttest_Decode(pBytes.get(), sizeOut);

		REQUIRE((void*)handle != nullptr);

		auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
		auto valid = SPS_AIKAttest_Verify(handle, nonce.data(), nonce.size());

		REQUIRE(valid);

		SPC_GetEndorsementPublicKey(pBytes.get(), cbSize, sizeOut);
		auto ekPub = SPOK_Blob::New(pBytes.get(), sizeOut);

		auto secret = BCryptUtil::GetRandomBytes(32);

		SPS_AIKTpmAttest_GetChallenge(handle, ((uint16_t)0x000B), ekPub.data(), ekPub.size(), secret.data(), secret.size(), pBytes.get(), cbSize, sizeOut);

		SPS_AttestationDestroy(handle);

		REQUIRE(sizeOut > 0);
		auto challenge = SPOK_Blob::New(pBytes.get(), sizeOut);

		SPC_AIKActivateChallenge(name.c_str(), flag, challenge.data(), challenge.size(), pBytes.get(), cbSize, sizeOut);

		REQUIRE(sizeOut > 0);

		auto response = SPOK_Blob::New(pBytes.get(), sizeOut);

		bool validSecret = secret == response;
		REQUIRE(validSecret);
	}
}

TEST_CASE("BASE64")
{
	uint8_t data[] = { 0x00, 0x01, 0x02, 0x03, 0x04 };
	auto blob = SPOK_Blob::New(data, sizeof(data));
	auto b64 = SPOK_Blob::BlobToBase64(blob);
	auto blob2 = SPOK_Blob::Base64ToBlob(b64);

	REQUIRE(blob == blob2);
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
	size_t sizeOut = 0;
	pBytes = std::make_unique<unsigned char[]>(cbSize);

	SPOK_Blob::Blob aikPub;

	{
		std::wstring name = L"TestAIK";
		NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

		bool exists = SPC_AIKExists(name.c_str(), flag);

		if (!exists)
		{
			auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
			SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
		}

		SPC_AIKGetPublicKey(name.c_str(), flag, pBytes.get(), cbSize, sizeOut);
		aikPub = SPOK_Blob::New(pBytes.get(), sizeOut);
		
		auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestPlatformNonce"));
		SPC_AIKGetPlatformAttestation(name.c_str(), flag, nonce.data(), nonce.size(), (PCR_13 | PCR_14), pBytes.get(), cbSize, sizeOut);

		REQUIRE(sizeOut > 0);

	}
	{
		auto handle = SPS_AIKPlatformAttest_Decode(pBytes.get(), sizeOut);

		REQUIRE((void*)handle != nullptr);

		auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestPlatformNonce"));

		auto valid = SPS_AIKPlatformAttest_Verify(handle, nonce.data(), nonce.size(), aikPub.data(), aikPub.size());

		REQUIRE(valid);

		uint8_t hashSize;
		SPS_AIKPlatformAttest_GetPCR(handle, pBytes.get(), cbSize, sizeOut, hashSize);

		SPOK_Pcrs pcrs = SPOK_Pcrs(SPOK_Blob::New(pBytes.get(), sizeOut));

		REQUIRE(pcrs.GetMask() == (PCR_13 | PCR_14));
		REQUIRE(pcrs.GetDigestSize() == hashSize);
		REQUIRE(pcrs.GetBlob().size() > 0);

		SPS_AIKPlatformAttest_GetTcgLog(handle, pBytes.get(), cbSize, sizeOut);

		auto log = TcgLog::Parse(SPOK_Blob::New(pBytes.get(), sizeOut));
		REQUIRE(log.Events.size() > 0);

		SPS_AttestationDestroy(handle);
	}
}

TEST_CASE("SPC_ImportWrappedKey_AndAttest")
{
	std::unique_ptr<unsigned char[]> pBytes = nullptr;
	size_t cbSize = 90000;
	size_t sizeOut = 0;

	pBytes = std::make_unique<unsigned char[]>(cbSize);

	std::wstring name = L"TestAIK";
	NCRYPT_MACHINE_KEY flag = NCRYPT_MACHINE_KEY::NO;

	std::wstring nameKey = L"TestWrappedKey";
	NCRYPT_MACHINE_KEY flagKey = NCRYPT_MACHINE_KEY::NO;

	bool exists = SPC_AIKExists(name.c_str(), flag);

	if (!exists)
	{
		auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestNonce"));
		SPC_AIKCreate(name.c_str(), flag, nonce.data(), nonce.size());
	}

	//generate a key
	auto key = BCryptUtil::GenerateRsaKeyPair(KeySize::RSA_2048);

	//get the srk
	memset(pBytes.get(), 0, cbSize);
	SPC_GetStorageRootKey(pBytes.get(), cbSize, sizeOut);
	auto srk = SPOK_Blob::New(pBytes.get(), sizeOut);

	//get the aikpub
	SPC_AIKGetPublicKey(name.c_str(), flag, pBytes.get(), cbSize, sizeOut);
	auto aikPub = SPOK_Blob::New(pBytes.get(), sizeOut);

	//get the PCRs for the key
	memset(pBytes.get(), 0, cbSize);
	SPC_GetPCRTable(pBytes.get(), cbSize, sizeOut);
	auto pcrs = SPOK_Pcrs(SPOK_Blob::New(pBytes.get(), sizeOut));

	//filter to the PCRs we want
	auto filteredPcrs = pcrs.GetFiltered(PCR_13 | PCR_14);
	auto pcrsBlob = filteredPcrs.GetBlob();

	//wrap the key
	memset(pBytes.get(), 0, cbSize);
	SPS_WrapKeyForPlatformImport(key.data(), key.size(), srk.data(), srk.size(), pcrsBlob.data(), pcrsBlob.size(), pBytes.get(), cbSize, sizeOut);
	auto wrappedKey = SPOK_Blob::New(pBytes.get(), sizeOut);

	REQUIRE(wrappedKey.size() > 0);

	//get the public name from wrapped key
	SPS_WrappedKeyName(wrappedKey.data(), wrappedKey.size(), pBytes.get(), cbSize, sizeOut);
	auto wrappedKeyName = SPOK_Blob::New(pBytes.get(), sizeOut);
	
	REQUIRE(wrappedKeyName.size() > 0);

	//import the key
	SPC_PlatformImportWrappedKey(nameKey.c_str(), flagKey, wrappedKey.data(), wrappedKey.size());

	//get the attestation
	auto nonce = Hasher::Blob2Nonce(SPOK_Blob::FromString("TestKeyNonce"));
	SPC_AIKGetKeyAttestation(name.c_str(), flag, nonce.data(), nonce.size(), nameKey.c_str(), flagKey, pBytes.get(), cbSize, sizeOut);

	REQUIRE(sizeOut > 0);

	auto handle = SPS_AIKKeyAttest_Decode(pBytes.get(), sizeOut);
	auto valid = SPS_AIKKeyAttest_Verify(handle, nonce.data(), nonce.size(), aikPub.data(), aikPub.size(), wrappedKeyName.data(), wrappedKeyName.size());

	REQUIRE(valid);

	//release the attestation resources
	SPS_AttestationDestroy(handle);
}
