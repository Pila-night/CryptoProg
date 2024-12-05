#include <iostream>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <boost/program_options.hpp>
using namespace std;

namespace po = boost::program_options;

template <typename HashType>
std::string goHash(const std::string& filename) {
    namespace CPP = CryptoPP;
    HashType hash;
    std::string digest;
    CPP::FileSource fileSource(filename.c_str(), true,
        new CPP::HashFilter(hash,
            new CPP::HexEncoder(
                new CPP::StringSink(digest)
            )
        )
    );

    return digest;
}


int main(int argc, char** argv) {
    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "Вызов справки")
            ("Input,I", po::value<std::string>(), "Файл для хэширования")
            ("Hash,H", po::value<std::string>()->default_value("SHA256"), "|SHA1|SHA224|SHA256|SHA384|SHA512|")
            ;
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            cout << "Usage: "<< argv[0]<<" -H SHA1|SHA224|SHA256|SHA384|SHA512 -I файл_для_хеширования" << "\n";
            return 1;
        }
        if (!vm.count("Input")) {
            cout << "Не указан файл с текстом для хэширования\n";
            cout << desc << "\n";
            cout << "Usage: "<< argv[0]<<" -H SHA1|SHA224|SHA256|SHA384|SHA512 -I файл_для_хеширования" << "\n";
            return 1;
        }
        string filename = vm["Input"].as<std::string>();
        string hashType = vm["Hash"].as<std::string>();
        std::string digest;
        if (hashType == "SHA1") {
            digest = goHash<CryptoPP::SHA1>(filename);
        } else if (hashType == "SHA224") {
            digest = goHash<CryptoPP::SHA224>(filename);
        } else if (hashType == "SHA256") {
            digest = goHash<CryptoPP::SHA256>(filename);
        } else if (hashType == "SHA384") {
            digest = goHash<CryptoPP::SHA384>(filename);
        } else if (hashType == "SHA512") {
            digest = goHash<CryptoPP::SHA512>(filename);
        } else {
            cout << "Неподдерживаемый хэш: " << hashType << endl;
            return 1;
        }
        cout << digest << endl;
        return 0; 

    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
}
