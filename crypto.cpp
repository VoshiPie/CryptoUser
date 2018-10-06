
#include "crypto.h"
#include <array>

/** cryptopp includes*/
#include "aes.h"
#include "modes.h"
#include "pwdbased.h"
#include "sha.h"
#include "osrng.h"
#include "crc.h"

namespace crypto
{

constexpr size_t verificationSaltOffset = 0x20;
constexpr size_t masterKeySaltOffset = 0x30;
constexpr size_t usernameOffset = 0x40;

bool User::passwordIsSafe(const std::string& password) const
{
	constexpr size_t minPasswordSize = 0x10;

	if (password.size() < minPasswordSize)
	{
		return false;
	}

	if (std::count_if(password.begin(), password.end(), islower) == 0)
	{
		return false;
	}

	if (std::count_if(password.begin(), password.end(), isupper) == 0)
	{
		return false;
	}

	return true;
}

/** Create a verification key that has a low dependency to the encryption key*/
bool User::createVerificationKey(const std::string& password,
	const std::vector<uint8_t>& verificationSalt, std::vector<uint8_t>& verificationKey)
{
	constexpr uint32_t numberOfPkdf2IterationsVerification = 0x8000;

	std::vector<uint8_t> saltedPassword(password.begin(), password.end());
	saltedPassword.insert(saltedPassword.end(),
		verificationSalt.begin(), verificationSalt.end());

	std::vector<uint8_t> saltedPasswordDigest(CryptoPP::SHA1::DIGESTSIZE);
	CryptoPP::SHA1 sha1;
	sha1.Update(saltedPassword.data(), saltedPassword.size());
	sha1.Final(saltedPasswordDigest.data());

	verificationKey.resize(CryptoPP::AES::MAX_KEYLENGTH * 2);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;

	size_t iterations = pbkdf2.DeriveKey(verificationKey.data(), verificationKey.size(),
		0, saltedPasswordDigest.data(), saltedPasswordDigest.size(), verificationSalt.data(),
		verificationSalt.size(), numberOfPkdf2IterationsVerification);

	if (numberOfPkdf2IterationsVerification != iterations)
	{
		return false;
	}

	/** Keep the second half for verification */
	verificationKey.erase(verificationKey.begin(),
		verificationKey.begin() + verificationKey.size() / 2);

	return true;
}

bool User::createEncryptionKey(const std::string& password,
	const std::vector<uint8_t>& salt, std::vector<uint8_t>& encryptionKey)
{
	constexpr uint32_t numberOfPkdf2IterationsEncryption = 0x4000;

	encryptionKey.resize(CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

	size_t iterations = pbkdf2.DeriveKey(encryptionKey.data(), encryptionKey.size(), 
		0, (uint8_t*)(password.data()), password.size(), 
		salt.data(), salt.size(), numberOfPkdf2IterationsEncryption);

	if (numberOfPkdf2IterationsEncryption != iterations)
	{
		return false;
	}

	return true;
}

void User::generateKeyAndIv(CryptoParams& cryptoParams)
{
	CryptoPP::AutoSeededRandomPool ran;

	cryptoParams.key.resize(CryptoPP::AES::MAX_KEYLENGTH);
	ran.GenerateBlock(cryptoParams.key.data(), cryptoParams.key.size());

	cryptoParams.iv.resize(CryptoPP::AES::BLOCKSIZE);
	ran.GenerateBlock(cryptoParams.iv.data(), cryptoParams.iv.size());
}

bool User::encryptNewFileData(
	const void* data, size_t size, std::vector<uint8_t>& encryptedBlob)
{
	if (0 == size)
	{
		return false;
	}

	CryptoParams fileParams;
	generateKeyAndIv(fileParams);

	if (!encryptFileData(fileParams, data, size, encryptedBlob))
	{
		return false;
	}

	return true;
}

bool User::encryptFileData(const CryptoParams& cryptoParams,
	const void* data, size_t size, std::vector<uint8_t>& encryptedBlob)
{
	if (m_credentials.masterKey.empty())
	{
		return false;
	}

	if (cryptoParams.key.size() != CryptoPP::AES::MAX_KEYLENGTH)
	{
		return false;
	}

	if (cryptoParams.iv.size() != CryptoPP::AES::BLOCKSIZE)
	{
		return false;
	}

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryption(
		cryptoParams.key.data(), cryptoParams.key.size(), cryptoParams.iv.data());

	uint64_t decryptedSize = (uint64_t)size + CryptoPP::CRC32::DIGESTSIZE;
	size_t paddedSize = (size_t)decryptedSize;
	size_t modBlockSize = decryptedSize % CryptoPP::AES::BLOCKSIZE;
	if (modBlockSize)
	{
		paddedSize += CryptoPP::AES::BLOCKSIZE - modBlockSize;
	}

	encryptedBlob.resize(sizeof(decryptedSize) + cryptoParams.key.size() + 
		cryptoParams.iv.size() + paddedSize);

	/** Encrypt the file key with the master key */
	std::vector<uint8_t> encryptedFileKey(cryptoParams.key.size());
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption keyEncryption(
		m_credentials.masterKey.data(), m_credentials.masterKey.size());
	keyEncryption.ProcessData(encryptedFileKey.data(), 
		cryptoParams.key.data(), cryptoParams.key.size());

	/** create a blob with the iv, encrypted key and the encrypted data */
	memcpy(encryptedBlob.data(), &decryptedSize, sizeof(decryptedSize));
	memcpy(encryptedBlob.data() + sizeof(decryptedSize), 
		encryptedFileKey.data(), encryptedFileKey.size());
	memcpy(encryptedBlob.data()  + sizeof(decryptedSize) + encryptedFileKey.size(),
		cryptoParams.iv.data(), cryptoParams.iv.size());

	std::vector<uint8_t> paddedData(paddedSize);
	memcpy(paddedData.data(), data, size);

	/**Adding a checmsum for decryption validation*/
	CryptoPP::CRC32 crc;
	crc.CalculateDigest(paddedData.data() + size, (uint8_t*)data, size);

	aesEncryption.ProcessData(encryptedBlob.data() + sizeof(decryptedSize) +
		encryptedFileKey.size() + cryptoParams.iv.size(), paddedData.data(), paddedData.size());

	return true;
}

bool User::decryptFileData(const void* data, size_t size, CryptoFile& cryptoData)
{
	if (m_credentials.masterKey.empty())
	{
		return false;
	}

	if (size < (CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE + sizeof(uint64_t)))
	{
		return false;
	}

	/**
	 * Copy over the following data
	 * 8 bytes size
	 * 32 bytes key (encrypted with the master key)
	 * 16 bytes iv
	 * The rest is encrypted data
	 */
	uint64_t originalFileSizeWihtCrc(*(uint64_t*)data);
	cryptoData.cryptoParams.key.resize(CryptoPP::AES::MAX_KEYLENGTH); /** aes 256 keys size */
	cryptoData.cryptoParams.iv.resize(CryptoPP::AES::BLOCKSIZE);
	cryptoData.data.resize(size - sizeof(originalFileSizeWihtCrc) -
		cryptoData.cryptoParams.key.size() - cryptoData.cryptoParams.iv.size());

	memcpy(cryptoData.cryptoParams.key.data(), (const uint8_t*)data + sizeof(originalFileSizeWihtCrc),
		cryptoData.cryptoParams.key.size());
	memcpy(cryptoData.cryptoParams.iv.data(), (const uint8_t*)data + sizeof(originalFileSizeWihtCrc) +
		cryptoData.cryptoParams.key.size(), cryptoData.cryptoParams.iv.size());

	if (cryptoData.data.size() % CryptoPP::AES::BLOCKSIZE)
	{
		return false; /** format is corrupt*/
	}

	/** The file key is encrypted with the master key, decrypt it first*/
	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption keyDecryption(
		m_credentials.masterKey.data(), m_credentials.masterKey.size());
	keyDecryption.ProcessData(cryptoData.cryptoParams.key.data(),
		cryptoData.cryptoParams.key.data(), cryptoData.cryptoParams.key.size());

	/** Use the decrypted file key to decrypt the file data */
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryption( cryptoData.cryptoParams.key.data(), 
		cryptoData.cryptoParams.key.size(), cryptoData.cryptoParams.iv.data());
	aesDecryption.ProcessData(cryptoData.data.data(), (const uint8_t*)data + size - 
		cryptoData.data.size(), cryptoData.data.size());

	if (originalFileSizeWihtCrc > cryptoData.data.size())
	{
		return false;
	}

	if (originalFileSizeWihtCrc < CryptoPP::CRC32::DIGESTSIZE)
	{
		return false;
	}

	size_t originalFileSize = (size_t)originalFileSizeWihtCrc - CryptoPP::CRC32::DIGESTSIZE;
	CryptoPP::CRC32 crc;
	std::array<uint8_t, CryptoPP::CRC32::DIGESTSIZE> crcValue;
	crc.CalculateDigest(crcValue.data(), cryptoData.data.data(), originalFileSize);

	if (memcmp(cryptoData.data.data() + originalFileSize, crcValue.data(), crcValue.size()) != 0)
	{
		return false;
	}

	if (originalFileSize < cryptoData.data.size())
	{
		cryptoData.data.resize((size_t)originalFileSize);
	}

	return true;
}

bool User::createNewCredentials(const std::string& username,
	const std::string& password, std::vector<uint8_t>& verificationBlob)
{
	if (!passwordIsSafe(password))
	{
		return false;
	}

	m_credentials.username = username;

	CryptoPP::AutoSeededRandomPool ran;

	std::vector<uint8_t> verificationSalt(CryptoPP::AES::BLOCKSIZE);
	ran.GenerateBlock(verificationSalt.data(), verificationSalt.size());

	std::vector<uint8_t> salt(CryptoPP::AES::BLOCKSIZE);
	ran.GenerateBlock(salt.data(), salt.size());

	std::vector<uint8_t> verificationKey;
	if (!createVerificationKey(password, verificationSalt, verificationKey))
	{
		return false;
	}

	if (!createEncryptionKey(password, salt, m_credentials.masterKey))
	{
		return false;
	}

	verificationBlob.resize(usernameOffset + username.size());

	memcpy(verificationBlob.data(), verificationKey.data(), verificationKey.size());
	memcpy(verificationBlob.data() + verificationSaltOffset, 
		verificationSalt.data(), verificationSalt.size());
	memcpy(verificationBlob.data() + masterKeySaltOffset,
		salt.data(), salt.size());
	memcpy(verificationBlob.data() + usernameOffset,
		username.data(), username.size());

	return true;
}

bool User::verifyCredentials(const std::string& username,
	const std::string& password, const std::vector<uint8_t>& verificationBlob)
{
	if (verificationBlob.size() < (usernameOffset + username.size()))
	{
		return false;
	}

	m_credentials.username.resize(verificationBlob.size() - usernameOffset);
	std::copy(verificationBlob.begin() + usernameOffset, verificationBlob.begin() +
		usernameOffset + m_credentials.username.size(), m_credentials.username.begin());

	if (m_credentials.username != username)
	{
		return false;
	}

	std::vector<uint8_t> verificationSalt(CryptoPP::AES::BLOCKSIZE);
	memcpy(verificationSalt.data(),
		verificationBlob.data() + verificationSaltOffset, verificationSalt.size());

	std::vector<uint8_t> salt(CryptoPP::AES::BLOCKSIZE);
	memcpy(salt.data(), verificationBlob.data() + masterKeySaltOffset, salt.size());

	std::vector<uint8_t> verificationKey;
	if (!createVerificationKey(password, verificationSalt, verificationKey))
	{
		return false;
	}

	if (memcmp(verificationBlob.data(), verificationKey.data(), 
		verificationKey.size()) != 0)
	{
		return false;
	}

	if (!createEncryptionKey(password, salt, m_credentials.masterKey))
	{
		return false;
	}

	return true;
}

}