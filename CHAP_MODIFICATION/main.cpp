#include <iostream>
#include <map>
#include <string> 

//файлы для подключения библиотеки Crypto++
#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/des.h" // DES algorithm
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededX917RNG
#include "../cryptopp860/sha.h"
#include "../cryptopp860/base64.h"

using namespace CryptoPP;
using namespace std;

const unsigned int BLOCKSIZE = 64;

//функция хеширования sha256 с выводом base64
string SHA256HashString(string aString) {
    string digest;
    SHA256 hash;

    StringSource foo(aString, true, new HashFilter(hash, new Base64Encoder(new StringSink(digest))));

    return digest;
}


// функция декодирования из base64
string Decoder(string aString) {
    string decoded;

    Base64Decoder decoder;
    decoder.Put((byte*)aString.data(), aString.size());
    decoder.MessageEnd();

    word64 size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }

    return decoded;
}

// класс сервер
class Server
{
private:
    // контейнер для хранения данных вида [ключ — значение]
    map <string, string> db;
    map <string, string> db_N;
public:
    //функция генерации случайного числа
    string generator_N1(string login) {
        string hash_N;
        // выделение памяти
        byte* pcbScratch;

        pcbScratch = new byte[BLOCKSIZE];

        // Создание криптографически стойкого генератора
        AutoSeededX917RNG<DES_EDE3> rng;
        string N_str;

        const auto found_N2 = db.find(login);

        if (found_N2 != db.cend()) {
            cout << "Server: Генерация числа N1..." << endl;
            rng.GenerateBlock(pcbScratch, BLOCKSIZE); //генерация случайного числа
            for (int i = 0; i < BLOCKSIZE; i++) {
                N_str += pcbScratch[i];
            }
            cout << "Server: Генерация прошла успешно. N1 = " << SHA256HashString(N_str) << endl;
            db_N[login] = N_str;
            return N_str;
        }
        delete[] pcbScratch;
    }

    // функция регистрации
    int registration(string login, string password)
    {
        const auto found = db.find(login);
        if (found == db.cend()) {
            db[login] = SHA256HashString(password); // шифрование пароля с помощью sha256

            for (auto it = db.begin(); it != db.end(); ++it) {
                cout << "Server: Регистрация прошла. Данные в базе db: '" << (*it).first << "' : " << (*it).second << endl;
                return true;
            }
        }
        else {
            cout << "Server: Error. Пользователь уже зарегистрирован с таким логином." << endl;
            return false;
        }

    }
    // функция проверки аутентификации
    string auth(string login, string N_2, string password) {
        const auto found = db.find(login);
        const auto found_N = db_N.find(login);
        string hash_N = SHA256HashString(db_N[login]);
        string hash_N2 = SHA256HashString(N_2);

        string new_pass_server = SHA256HashString(Decoder(hash_N) + Decoder(db[login]));
        cout << "Server: Новый пароль, сгенерированный Server: " << new_pass_server << endl;

        if (found != db.cend() and found_N != db_N.cend()) {
            if (Decoder(new_pass_server) != Decoder(password)) {
                cout << "Server: Неверный пароль!!!!!!" << endl;
                return "false";
            }
            else {
                string second_pass_server = SHA256HashString(Decoder(hash_N2) + Decoder(db[login]));
                cout << "Server: Успешная аутентификация у Server. Пароль = " << second_pass_server <<  endl;
                return second_pass_server;
            }
        }
        else {
            cout << "Server: Неверный логин = '" << login << "' " << endl;
            return "false";
        }
    }
};

//Класс Пользователь
class User
{
private:
    // контейнер для хранения данных вида [ключ — значение]
    map <string, string> db_user;
    map <string, string> db_N2;
public:
    string generator_N2(string login) {
        string hash_N;
        byte* pcbScratch;

        pcbScratch = new byte[BLOCKSIZE];

        // Создание криптографически стойкого генератора
        AutoSeededX917RNG<DES_EDE3> rng;
        string N_str;

        const auto found_N2 = db_user.find(login);

        if (found_N2 != db_user.cend()) {
            cout << "User: Генерация числа N2..." << endl; //генерация случайного числа
            rng.GenerateBlock(pcbScratch, BLOCKSIZE);
            for (int i = 0; i < BLOCKSIZE; i++) {
                N_str += pcbScratch[i];
            }
            cout << "User: Генерация прошла успешно. N2 = " << SHA256HashString(N_str) << endl;
            db_N2[login] = N_str;
            return N_str;
        }
        delete[] pcbScratch;
    }
    //функция регистрации пользователя
    void regisration_user(Server& server, string login, string password) {

        string pass = SHA256HashString(password);
        cout << "User: Исходные данные. Логин = '" << login << "', пароль = " << pass << endl;

        cout << "User: Регистрация..." << endl;
        bool status_registration = server.registration(login, password);
        if (status_registration == true) {
            db_user[login] = password;
            cout << "User: Успешная регистрация." << endl;
        }
        else {
            cout << "User: Ошибка при регистрации." << endl;
        }
    }

    //функция аутентификации пользователя
    void auth_user(Server& server, string login, string password) {
        string hash_pass = SHA256HashString(password);
        cout << "User: Аутентификация...Введенный пароль: " << hash_pass << endl;

        string N1 = server.generator_N1(login);
        string N2 = generator_N2(login);

        string hash_N = SHA256HashString(N1);
        string hash_N2 = SHA256HashString(N2);

        cout << "User: Server передал случайное число N1 с помощью криптографически стойкого генератора = " << hash_N << endl;
        cout << endl;
        string pass = SHA256HashString(Decoder(hash_N) + Decoder(hash_pass));
        cout << "User: Новый пароль, сгенерированный User с N1: " << pass << endl;

        string pass_auth = server.auth(login, N2, pass);
        string second_pass_user = SHA256HashString(Decoder(hash_N2) + Decoder(hash_pass));
        cout << "User: Новый пароль, сгенерированный User с N2: " << second_pass_user << endl;

        if (pass_auth != "false") {
            const auto found = db_user.find(login);
            const auto found_N = db_N2.find(login);

            if (found != db_user.cend() and found_N != db_N2.cend()) {
                if (Decoder(pass_auth) == Decoder(second_pass_user)) {
                    cout << "User: Успешная аутентификация у User." << endl;
                }
                else {
                    cout << "User: Ошибка при аутентификации." << endl;
                }
            }  
        }
        else {
            cout << "User: Ошибка при аутентификации!(" << endl;
        }
    }
};


int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");
    Server objCHAPServer; // объявление Server
    User objCHAPUser; // объявление User

    // Корректные данные
    //objCHAPUser.regisration_user(objCHAPServer, "Boby", "qwerty123");
    //objCHAPUser.auth_user(objCHAPServer, "Boby", "qwerty123");

    //Некорректный пароль
    objCHAPUser.regisration_user(objCHAPServer, "Alice", "123");
    objCHAPUser.auth_user(objCHAPServer, "Alice", "qr1258963");


    system("pause");
    return 0;
}
