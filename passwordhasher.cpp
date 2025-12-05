#include "passwordhasher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
// #include <iomanip>
#include <vector>

// Константы для Base64 кодирования
static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const int PasswordHasher::PBKDF2_ITERATIONS;
const int PasswordHasher::HASH_LENGTH;

std::string PasswordHasher::hashPassword(const std::string& password)
{
    // 1. Генерируем соль
    std::string salt = generateSalt(16);

    // 2. Вычисляем PBKDF2
    unsigned char hash[HASH_LENGTH];

    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.length(),
        reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        HASH_LENGTH,
        hash
        );

    if (result != 1) {
        throw std::runtime_error("PBKDF2 hash failed");
    }

    // 3. Кодируем хеш в Base64
    std::string hashB64 = base64Encode(hash, HASH_LENGTH);

    // 4. Формируем итоговую строку: алгоритм:итерации:соль:хеш
    std::stringstream ss;
    ss << "pbkdf2_sha256:" << PBKDF2_ITERATIONS << ":" << salt << ":" << hashB64;

    return ss.str();
}

bool PasswordHasher::verifyPassword(const std::string& password, const std::string& hash)
{
    try {
        // 1. Парсим строку хеша: алгоритм:итерации:соль:хеш
        size_t pos1 = hash.find(':');
        if (pos1 == std::string::npos) return false;

        size_t pos2 = hash.find(':', pos1 + 1);
        if (pos2 == std::string::npos) return false;

        size_t pos3 = hash.find(':', pos2 + 1);
        if (pos3 == std::string::npos) return false;

        std::string algorithm = hash.substr(0, pos1);
        std::string iterationsStr = hash.substr(pos1 + 1, pos2 - pos1 - 1);
        std::string salt = hash.substr(pos2 + 1, pos3 - pos2 - 1);
        std::string storedHash = hash.substr(pos3 + 1);

        // 2. Проверяем алгоритм
        if (algorithm != "pbkdf2_sha256") {
            return false;
        }

        // 3. Преобразуем итерации
        int iterations = std::stoi(iterationsStr);
        if (iterations <= 0) return false;

        // 4. Декодируем сохраненный хеш из Base64
        unsigned char decodedHash[HASH_LENGTH];
        int decodedLen = base64Decode(storedHash, decodedHash);
        if (decodedLen != HASH_LENGTH) return false;

        // 5. Вычисляем хеш для предоставленного пароля
        unsigned char computedHash[HASH_LENGTH];
        int result = PKCS5_PBKDF2_HMAC(
            password.c_str(), password.length(),
            reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
            iterations,
            EVP_sha256(),
            HASH_LENGTH,
            computedHash
            );

        if (result != 1) return false;

        // 6. Сравниваем хеши (защита от атак по времени)
        return CRYPTO_memcmp(decodedHash, computedHash, HASH_LENGTH) == 0;
    }
    catch (...) {
        // Любая ошибка парсинга или вычислений
        return false;
    }
}

std::string PasswordHasher::generateSalt(int length)
{
    if (length < 8 || length > 64) {
        throw std::invalid_argument("Salt length must be between 8 and 64 bytes");
    }

    std::vector<unsigned char> salt(length);

    // Генерируем криптографически безопасную случайную соль
    if (RAND_bytes(salt.data(), length) != 1) {
        throw std::runtime_error("Failed to generate cryptographically secure salt");
    }

    // Кодируем в Base64 для хранения
    return base64Encode(salt.data(), length);
}

std::string PasswordHasher::base64Encode(const unsigned char* data, int length)
{
    std::string result;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (length--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                result += BASE64_CHARS[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            result += BASE64_CHARS[char_array_4[j]];

        while (i++ < 3)
            result += '=';
    }

    return result;
}

int PasswordHasher::base64Decode(const std::string& input, unsigned char* output)
{
    int length = input.length();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    int output_idx = 0;

    // Создаем таблицу для быстрого поиска Base64 символов
    static int table[256];
    static bool table_initialized = false;

    if (!table_initialized) {
        for (i = 0; i < 256; i++) table[i] = -1;
        for (i = 0; i < 64; i++) table[(unsigned char)BASE64_CHARS[i]] = i;
        table_initialized = true;
    }

    i = 0;
    while (length-- && input[in_] != '=') {
        unsigned char c = input[in_++];
        if (table[c] == -1) return -1;  // Недопустимый символ

        char_array_4[i++] = c;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = table[char_array_4[i]];

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                output[output_idx++] = char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = table[char_array_4[j]];

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++)
            output[output_idx++] = char_array_3[j];
    }

    return output_idx;
}
