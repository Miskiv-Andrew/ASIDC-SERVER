#include "passwordhasher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
// #include <iomanip>
#include <vector>


// НОВЫЕ инклуды для новых методов:
#include <algorithm>    // для std::transform, std::reverse, std::shuffle
#include <cctype>       // для std::isupper, std::islower, std::isdigit
#include <set>          // для std::set
#include <random>       // для std::random_device, std::mt19937, std::uniform_int_distribution
#include <functional>

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


// Проверка наличия заглавных букв
bool PasswordHasher::hasUpperCase(const std::string& str) {
    for (char c : str) {
        if (std::isupper(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

// Проверка наличия строчных букв
bool PasswordHasher::hasLowerCase(const std::string& str) {
    for (char c : str) {
        if (std::islower(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

// Проверка наличия цифр
bool PasswordHasher::hasDigits(const std::string& str) {
    for (char c : str) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

// Проверка наличия специальных символов
bool PasswordHasher::hasSpecialChars(const std::string& str) {
    const std::string special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    for (char c : str) {
        if (special_chars.find(c) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Проверка на распространенные слабые пароли
bool PasswordHasher::isCommonPassword(const std::string& password) {
    static const std::vector<std::string> common_passwords = {
        "password", "123456", "12345678", "1234", "qwerty",
        "admin", "welcome", "monkey", "letmein", "password1",
        "12345", "123456789", "admin123", "qwerty123", "111111",
        "abc123", "passw0rd", "superman", "iloveyou", "sunshine"
    };

    std::string lower_password = password;
    std::transform(lower_password.begin(), lower_password.end(),
                   lower_password.begin(), ::tolower);

    for (const auto& common : common_passwords) {
        if (lower_password == common) {
            return true;
        }
    }

    return false;
}

// Проверка на простые последовательности
bool PasswordHasher::containsSequence(const std::string& password) {
    if (password.length() < 3) return false;

    // Проверка цифровых последовательностей (123, 456, 789 и т.д.)
    for (size_t i = 0; i < password.length() - 2; i++) {
        if (isdigit(password[i]) && isdigit(password[i+1]) && isdigit(password[i+2])) {
            int diff1 = password[i+1] - password[i];
            int diff2 = password[i+2] - password[i+1];
            if (diff1 == diff2 && (diff1 == 1 || diff1 == -1)) {
                return true;
            }
        }
    }

    // Проверка буквенных последовательностей (abc, xyz и т.д.)
    const std::string keyboard_sequences[] = {
        "qwerty", "asdfgh", "zxcvbn", "йцукен", "фывапр"
    };

    std::string lower_password = password;
    std::transform(lower_password.begin(), lower_password.end(),
                   lower_password.begin(), ::tolower);

    for (const auto& seq : keyboard_sequences) {
        if (lower_password.find(seq) != std::string::npos) {
            return true;
        }
    }

    return false;
}

// Проверка на содержание логина
bool PasswordHasher::containsLogin(const std::string& password, const std::string& login) {
    if (login.empty() || password.empty()) return false;

    std::string lower_password = password;
    std::string lower_login = login;

    std::transform(lower_password.begin(), lower_password.end(),
                   lower_password.begin(), ::tolower);
    std::transform(lower_login.begin(), lower_login.end(),
                   lower_login.begin(), ::tolower);

    // Проверяем, содержится ли логин в пароле
    if (lower_password.find(lower_login) != std::string::npos) {
        return true;
    }

    // Проверяем обратный порядок
    std::string reversed_login = lower_login;
    std::reverse(reversed_login.begin(), reversed_login.end());
    if (lower_password.find(reversed_login) != std::string::npos) {
        return true;
    }

    return false;
}

// Основная функция валидации сложности пароля
bool PasswordHasher::validatePasswordComplexity(const std::string& password,
                                                std::string& error_msg) {
    error_msg.clear();

    // 1. Проверка длины
    if (password.length() < 8) {
        error_msg = "Password must be at least 8 characters long";
        return false;
    }

    // 2. Проверка разнообразия символов
    if (!hasUpperCase(password)) {
        error_msg = "Password must contain at least one uppercase letter";
        return false;
    }

    if (!hasLowerCase(password)) {
        error_msg = "Password must contain at least one lowercase letter";
        return false;
    }

    if (!hasDigits(password)) {
        error_msg = "Password must contain at least one digit";
        return false;
    }

    if (!hasSpecialChars(password)) {
        error_msg = "Password must contain at least one special character (!@#$%^&* etc.)";
        return false;
    }

    // 3. Проверка на слабые пароли
    if (isCommonPassword(password)) {
        error_msg = "Password is too common. Choose a more unique password";
        return false;
    }

    // 4. Проверка на последовательности
    if (containsSequence(password)) {
        error_msg = "Password contains simple sequences (123, abc, qwerty, etc.)";
        return false;
    }

    // 5. Проверка на повторяющиеся символы (aaa, 111 и т.д.)
    if (password.length() >= 3) {
        for (size_t i = 0; i < password.length() - 2; i++) {
            if (password[i] == password[i+1] && password[i] == password[i+2]) {
                error_msg = "Password contains repeating characters (aaa, 111, etc.)";
                return false;
            }
        }
    }

    return true;
}

// Расчет силы пароля
int PasswordHasher::calculatePasswordStrength(const std::string& password,
                                              const std::string& user_login) {
    if (password.empty()) return 0;

    int score = 0;

    // 1. Длина пароля (макс 30 баллов)
    size_t len = password.length();
    if (len >= 8) score += 10;
    if (len >= 12) score += 10;
    if (len >= 16) score += 10;

    // 2. Разнообразие символов (макс 40 баллов)
    if (hasUpperCase(password)) score += 10;
    if (hasLowerCase(password)) score += 10;
    if (hasDigits(password)) score += 10;
    if (hasSpecialChars(password)) score += 10;

    // 3. Штрафы за слабые места (макс -30 баллов)
    if (isCommonPassword(password)) score -= 20;
    if (containsSequence(password)) score -= 15;
    if (!user_login.empty() && containsLogin(password, user_login)) score -= 10;

    // 4. Уникальность символов
    std::set<char> unique_chars(password.begin(), password.end());
    double uniqueness = static_cast<double>(unique_chars.size()) / len;
    if (uniqueness >= 0.8) score += 10;
    else if (uniqueness >= 0.6) score += 5;

    // Ограничиваем диапазон 0-100
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    return score;
}

// Генерация безопасного пароля
std::string PasswordHasher::generateSecurePassword(int length) {
    if (length < 8) length = 12;

    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    const std::string all_chars = lowercase + uppercase + digits + special;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, all_chars.size() - 1);

    std::string password;

    // Гарантируем наличие всех типов символов
    password += lowercase[dis(gen) % lowercase.size()];
    password += uppercase[dis(gen) % uppercase.size()];
    password += digits[dis(gen) % digits.size()];
    password += special[dis(gen) % special.size()];

    // Заполняем оставшуюся длину
    for (int i = 4; i < length; i++) {
        password += all_chars[dis(gen)];
    }

    // Перемешиваем пароль
    std::shuffle(password.begin(), password.end(), gen);

    return password;
}
