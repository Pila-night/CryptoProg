#pragma once
#include <stdio.h>
#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
class AES {
public:
    AES();
    void encrypt(const std::string& password, const std::string& orig_file,
                 const std::string& key_file, const std::string& iv_file,
                 const std::string& encr_file);
    
    void decrypt(const std::string& key_file, const std::string& iv_file,
                 const std::string& decr_file, const std::string& output_file);

private:
    const size_t keyLength = CryptoPP::AES::MAX_KEYLENGTH;
};
