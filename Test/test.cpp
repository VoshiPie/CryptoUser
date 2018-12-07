#include "pch.h"
/** Testing the public functions in crypto::User in crypto.h */
#include "crypto.h" 

TEST(createNewCredentials, validPassword)
{
	std::vector<uint8_t> credentialsBlob;
	crypto::User user;
	bool status = user.createNewCredentials(
		"user1234", "isThisPasswordLongEnough", credentialsBlob);

	EXPECT_EQ(true, status);
}

TEST(createNewCredentials, shortPassword)
{
	std::vector<uint8_t> credentialsBlob;
	crypto::User user;
	bool status = user.createNewCredentials("user1234", "tooShortPw", credentialsBlob);

	EXPECT_EQ(false, status);
}

TEST(createNewCredentials, lowercaseTest)
{
	std::vector<uint8_t> credentialsBlob;
	crypto::User user;
	bool status = user.createNewCredentials(
		"user1234", "password missing upper case", credentialsBlob);

	EXPECT_EQ(false, status);
}

TEST(createNewCredentials, uppercaseTest)
{
	std::vector<uint8_t> credentialsBlob;
	crypto::User user;
	bool status = user.createNewCredentials(
		"user1234", "password missing upper case", credentialsBlob);

	EXPECT_EQ(false, status);
}

TEST(verifyCredentials, validPasswordAndUsername)
{
	std::vector<uint8_t> credentialsBlob;
	bool status = false;

	{
		crypto::User user;
		user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);
	}

	{
		crypto::User user;
		status = user.verifyCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);
	}

	EXPECT_EQ(true, status);
}

TEST(verifyCredentials, invalidPassword)
{
	std::vector<uint8_t> credentialsBlob;
	bool status = false;

	{
		crypto::User user;
		user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);
	}

	{
		crypto::User user;
		status = user.verifyCredentials("user1234", "TheWrongPassword", credentialsBlob);
	}

	EXPECT_EQ(false, status);
}

TEST(verifyCredentials, invalidUserName)
{
	std::vector<uint8_t> credentialsBlob;
	bool status = false;

	{
		crypto::User user;
		user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);
	}

	{
		crypto::User user;
		status = user.verifyCredentials("invalidUsername", "ThisPasswordIsValid", credentialsBlob);
	}

	EXPECT_EQ(false, status);
}

TEST(encryptFile, nonEmptyFileData)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "This is data that I want to encrypt";
	bool status = user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	EXPECT_EQ(true, status);
}

TEST(encryptFile, emptyFileData)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "";
	bool status = user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, validEncryptedBlob)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "file data to encrypt";
	user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	crypto::User::CryptoFile cryptoFile;
	bool status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);
	if (true == status)
	{
		if (memcmp(cryptoFile.data.data(), fileDataToEncrypt.data(), cryptoFile.data.size()) != 0)
		{
			status = false;
		}
	}

	EXPECT_EQ(true, status);
}

TEST(decryptFile, corruptEncryptedBlob)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "file data to encrypt";
	user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	/** Corrupt blob data */
	encryptedBlob.at(0x40) = encryptedBlob.at(0x40) + 1;

	crypto::User::CryptoFile cryptoFile;
	bool status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, corruptKeyInEncryptedBlob)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "file data to encrypt";
	user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	/** Corrupt blob key */
	encryptedBlob.at(0x20) = encryptedBlob.at(0x20) + 1;

	crypto::User::CryptoFile cryptoFile;
	bool status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, tooSmallEncryptedBlob)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	std::string fileDataToEncrypt = "file data to encrypt";
	user.encryptNewFileData(fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	/** Reduce size of the blob */
	encryptedBlob.resize(encryptedBlob.size() - 5);

	crypto::User::CryptoFile cryptoFile;
	bool status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, emptyEncryptedBlob)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	crypto::User::CryptoFile cryptoFile;
	bool status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, invalidUser)
{
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	{
		crypto::User user;
		user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

		std::string fileDataToEncrypt = "file data to encrypt";
		user.encryptNewFileData(fileDataToEncrypt.data(),
			fileDataToEncrypt.size(), encryptedBlob);
	}

	bool status = false;

	{
		crypto::User user;
		user.createNewCredentials("anotherUser", "ThisPasswordIsValid", credentialsBlob);

		crypto::User::CryptoFile cryptoFile;
		status = user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile);
	}

	EXPECT_EQ(false, status);
}

TEST(decryptFile, emptyCryptoFileParameters)
{

	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	crypto::User::CryptoFile cryptoFile;
	std::string fileDataToEncrypt = "file data to encrypt";
	bool status = user.encryptFileData(cryptoFile.cryptoParams, fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	EXPECT_EQ(false, status);
}

TEST(decryptFile, invalidCryptoFileParameters)
{

	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	crypto::User user;
	user.createNewCredentials("user1234", "ThisPasswordIsValid", credentialsBlob);

	crypto::User::CryptoFile cryptoFile;
	cryptoFile.cryptoParams.iv.resize(7);
	cryptoFile.cryptoParams.key.resize(13);
	std::string fileDataToEncrypt = "file data to encrypt";
	bool status = user.encryptFileData(cryptoFile.cryptoParams, fileDataToEncrypt.data(),
		fileDataToEncrypt.size(), encryptedBlob);

	EXPECT_EQ(false, status);
}
