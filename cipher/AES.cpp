#include "AES.h"
#include <iostream>

AES::AES() {
    
}

void AES::encrypt(const std::string& password, const std::string& orig_file,
                  const std::string& key_file, const std::string& iv_file,
                  const std::string& encr_file) 
                  {
    CryptoPP::SecByteBlock key(keyLength);
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    CryptoPP::AutoSeededRandomPool prng;

    
    CryptoPP::SecByteBlock salt(16); 
    prng.GenerateBlock(salt, salt.size());

    pbkdf.DeriveKey(key.data(), key.size(), 0,
                    (CryptoPP::byte*)password.data(), password.size(),
                    salt.data(), salt.size(), 
                    10000, 0.0f); 


    CryptoPP::StringSource(key, key.size(), true,
                            new CryptoPP::HexEncoder(
                                new CryptoPP::FileSink(key_file.c_str())));
    std::clog << "Ключ был сгенерирован и сохранен в файл: " << key_file << std::endl;

    
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    
    CryptoPP::StringSource(iv, sizeof(iv), true,
                           new CryptoPP::HexEncoder(
                               new CryptoPP::FileSink(iv_file.c_str())));
    std::clog << "IV сгенерирован и сохранен в файл: " << iv_file << std::endl;

    
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    
    CryptoPP::FileSource(orig_file.c_str(), true,
                          new CryptoPP::StreamTransformationFilter(encr,
                                  new CryptoPP::FileSink(encr_file.c_str())));
    std::clog << "Файл " << orig_file << " был зашифрован. Результат шифрования сохранен в файл: " << encr_file << std::endl;
}
void AES::decrypt(const std::string& key_file, const std::string& iv_file,
                  const std::string& decr_file, const std::string& output_file) {
    CryptoPP::SecByteBlock key(keyLength);
    
    CryptoPP::FileSource(key_file.c_str(), true,
                         new CryptoPP::HexDecoder(
                             new CryptoPP::ArraySink(key, key.size())));
    std::clog << "Ключ прочитан из файла: " << key_file << std::endl;

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::FileSource(iv_file.c_str(), true,
                         new CryptoPP::HexDecoder(
                             new CryptoPP::ArraySink(iv, sizeof(iv))));
    std::clog << "IV прочитан из файла: " << iv_file << std::endl;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::FileSource(decr_file.c_str(), true,
                         new CryptoPP::StreamTransformationFilter(decr,
                             new CryptoPP::FileSink(output_file.c_str())));
    std::clog << "Файл " << decr_file << " был расшифрован. Результат сохранен в файл: " << output_file << std::endl;
}

