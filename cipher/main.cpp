#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include "AES.h"

namespace po = boost::program_options;

void checkFileExists(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.good()) {
        throw std::runtime_error("Файл не найден: " + filename);
    }
}

int main() {
    AES aes;
    std::string action;

    while (true) {
        std::cout << "Вы хотите зашифровать или расшифровать файл? (1 - зашифрование, 2 - расшифрование, q - выход): ";
        std::cin >> action;

        try {
            if (action == "1") {
                std::string orig_file, key_file, iv_file, encr_file, password;

                std::cout << "Введите имя файла для шифрования: ";
                std::cin >> orig_file;
                checkFileExists(orig_file);

                std::cout << "Введите имя файла для сохранения ключа: ";
                std::cin >> key_file;

                std::cout << "Введите имя файла для сохранения вектора инициализации (IV): ";
                std::cin >> iv_file;

                std::cout << "Введите имя выходного зашифрованного файла: ";
                std::cin >> encr_file;

                std::cout << "Введите пароль для шифрования: ";
                std::cin >> password;
                if (orig_file == key_file || orig_file == iv_file || orig_file == encr_file ||
            key_file == iv_file || key_file == encr_file || iv_file == encr_file) {
                    std::cerr << "Ошибка: Имена файлов не должны совпадать!" << std::endl;
                    continue;  
                }

                aes.encrypt(password, orig_file, key_file, iv_file, encr_file);
                std::cout << "Файл успешно зашифрован!" << std::endl;

            } else if (action == "2") {
                std::string key_file, iv_file, decr_file, output_file;

                std::cout << "Введите имя файла с ключом: ";
                std::cin >> key_file;
                checkFileExists(key_file);

                std::cout << "Введите имя файла с вектором инициализации (IV): ";
                std::cin >> iv_file;
                checkFileExists(iv_file);

                std::cout << "Введите имя зашифрованного файла: ";
                std::cin >> decr_file;
                checkFileExists(decr_file);

                std::cout << "Введите имя выходного файла для расшифровки: ";
                std::cin >> output_file;

                if (decr_file == output_file || key_file == output_file || iv_file == output_file) {
                    std::cerr << "Ошибка: Имена файлов не должны совпадать!" << std::endl;
                    continue;  
                }

                aes.decrypt(key_file, iv_file, decr_file, output_file);
                std::cout << "Файл успешно расшифрован!" << std::endl;
                } else if (action == "q") {
                std::cout << "Выход из программы." << std::endl;
                break;

            } else {
                std::cerr << "Ошибка: Неизвестное действие. Пожалуйста, введите '1', '2' или 'q'." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }
    }

    return 0;
}
