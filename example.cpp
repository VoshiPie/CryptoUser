
#include "crypto.h"

/**
* Example usage of crypto.h
*/

int main()
{
	/** 
	 * This data could be saved as files, you can create a credentials file (credentialBlob) for each user 
	 * and multiple files (encryptedBlobs) for each credential file
	 */
	std::vector<uint8_t> credentialsBlob;
	std::vector<uint8_t> encryptedBlob;

	/** At some stage you might want to create credentials for a user, create a new instance for each user */
	{
		crypto::User user;
		if (!user.createNewCredentials("user1234", "ThisPasswordisValid", credentialsBlob))
		{
			printf("Unable to create new credentials, \
				password needs to be 16 characters minimum, lower and upper case!");
			/** Handle error*/
		}

		/** A user can encrypt filedata so that it is bound to the users credentials */
		std::string fileDataToEncrypt = "This is data that I want to encrypt";
		
		if (!user.encryptNewFileData(fileDataToEncrypt.data(),
			fileDataToEncrypt.size(), encryptedBlob))
		{
			printf("Unable to encrypt file");
			/** Handle error*/
		}
	}

	/** How to verify credentials and use them when you have a credentialsBlob */
	{
		crypto::User user;
		if (!user.verifyCredentials("user1234", "ThisPasswordisValid", credentialsBlob))
		{
			printf("Incorrect username or password");
			/** Handle error*/
		}

		crypto::User::CryptoFile cryptoFile;
		if (!user.decryptFileData(encryptedBlob.data(), encryptedBlob.size(), cryptoFile))
		{
			printf("Failed to decrypt file data");
			/** Handle error*/
		}

		/** Change or add some data and encrypt it again */
		std::string moreFileDataToEncrypt = " / This was added to the file data";
		cryptoFile.data.resize(cryptoFile.data.size() + moreFileDataToEncrypt.size());
		memcpy(cryptoFile.data.data() + cryptoFile.data.size() - moreFileDataToEncrypt.size(),
			moreFileDataToEncrypt.data(), moreFileDataToEncrypt.size());

		if (!user.encryptFileData(cryptoFile.cryptoParams,
			cryptoFile.data.data(), cryptoFile.data.size(), encryptedBlob))
		{
			printf("Failed to encrypt file data with existing keys");
			/** Handle error*/
		}
	}

	return 0;
}