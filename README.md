# CryptoUser

Code for creating and verifying credentials with support for data encryption/decryption using the credentials.

Dependencies:

CryptoPP
  
    To build crypto.cpp you will need cryptopp which you can find at https://github.com/weidai11/cryptopp
    
    For visual studio:
    
    - Build cryptlib.lib
    - In your project, add the path to your cryptopp folder to Additional Include Directories
    - Add cryptlib.lib as Additional Dependencies and it's path to Additional Library Directories

Google Test
  
    Test.cpp uses google test.
    
    For visual studio
    
    - Create a google test project,
    - Add crypto.h and add crypto.cpp to the test project 
    (alternative create a lib with crypto.h/crypto.cpp and link it)
    - Link cryptlib to the test project
