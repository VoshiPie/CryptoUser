#ifndef _CRYPTO_USER_H_
#define _CRYPTO_USER_H_

#include <vector>
#include <string>
#include "stdint.h"

namespace crypto
{

class User
{
public:

	struct CryptoParams
	{
		std::vector<uint8_t> key;
		std::vector<uint8_t> iv;
	};

	struct CryptoFile
	{
		CryptoParams cryptoParams;
		std::vector<uint8_t> data;
	};

	struct Credentials
	{
		std::vector<uint8_t> masterKey;
		std::string username;
	};

	/**
	 * Creates a verification blob that later can be verified with username and password
	 * Inputs: username, password
	 * (password must be 16 characters long and include both lower and upper case characters)
	 * Output: verificationBlob	(includes everything to verify a users credentials)
	 * Returns true if success
	 */
	bool createNewCredentials(const std::string& username, 
		const std::string& password, std::vector<uint8_t>& verificationBlob);

	/**
	* Verifies existing verification blob with username and password
	* Inputs: username, password, verificationBlob
	* (password must be 16 characters long and include both lower and upper case characters)
	* Returns true if success
	*/
	bool verifyCredentials(const std::string& username, const std::string& password,
		const std::vector<uint8_t>& verificationBlob);

	/** 
	 * Encrypt file with existing keys
	 * Inputs: cryptoParams, data, size		(cryptoParams contains key and iv)
	 * Output: encryptedBlob	(the key and iv are baked into the encryptedBlob)
	 * Returns true if success
	 */
	bool encryptFileData(const CryptoParams& cryptoParams,
		const void* data, size_t size, std::vector<uint8_t>& encryptedBlob);

	/** 
	 * Creates keys for file, then encrypts it. 
	 * Inputs: data, size
	 * Output: encryptedBlob	(the key and iv are baked into the encryptedBlob)
	 * Returns true if success
	 */
	bool encryptNewFileData(const void* data, size_t size, std::vector<uint8_t>& encryptedBlob);

	/** 
	 * Inputs data, size	(data is an encryptedBlob)
	 * Output: cryptoData	(contains key, iv and the decrypted file data)
	 * Returns true if success
	 */
	bool decryptFileData(const void* data, size_t size, CryptoFile& cryptoData);

private:

	bool passwordIsSafe(const std::string& password) const;

	bool createVerificationKey(const std::string& password,
		const std::vector<uint8_t>& verificationSalt, std::vector<uint8_t>& verificationKey);

	bool createEncryptionKey(const std::string& password,
		const std::vector<uint8_t>& salt, std::vector<uint8_t>& encryptionKey);

	void generateKeyAndIv(CryptoParams& cryptoParams);

	Credentials m_credentials;
};

}
#endif /** !_CRYPTO_USER_H_*/
