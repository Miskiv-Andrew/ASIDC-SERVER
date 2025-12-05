#ifndef PASSWORDHASHER_H
#define PASSWORDHASHER_H

#include <string>

/**
 * @class PasswordHasher
 * @brief Класс для безопасного хеширования и проверки паролей.
 *
 * Использует алгоритм PBKDF2-HMAC-SHA256 из OpenSSL.
 * Предоставляет статические методы для работы с паролями.
 * Кросс-платформенный (Windows/Linux).
 */
class PasswordHasher
{
public:
    /**
     * @brief Хеширует пароль с помощью PBKDF2-HMAC-SHA256.
     *
     * Генерирует случайную соль и создает хеш пароля.
     * Формат результата: "алгоритм:итерации:соль:хеш"
     *
     * @param password Пароль в открытом виде.
     * @return Строка с хешем в формате "pbkdf2_sha256:10000:salt:hash".
     */
    static std::string hashPassword(const std::string& password);

    /**
     * @brief Проверяет пароль по сохраненному хешу.
     *
     * Извлекает параметры из строки хеша и проверяет соответствие пароля.
     *
     * @param password Пароль для проверки.
     * @param hash Хеш в формате "алгоритм:итерации:соль:хеш".
     * @return true если пароль верный, false если неверный.
     */
    static bool verifyPassword(const std::string& password, const std::string& hash);

    /**
     * @brief Генерирует криптографически безопасную случайную соль.
     *
     * @param length Длина соли в байтах (по умолчанию 16).
     * @return Соль в Base64 кодировке.
     */
    static std::string generateSalt(int length = 16);

private:
    // Константы для алгоритма
    static const int PBKDF2_ITERATIONS = 10000;  // Количество итераций PBKDF2
    static const int HASH_LENGTH = 32;           // Длина хеша SHA-256 (32 байта)

    /**
     * @brief Кодирует бинарные данные в Base64.
     *
     * @param data Указатель на бинарные данные.
     * @param length Длина данных в байтах.
     * @return Строка в Base64.
     */
    static std::string base64Encode(const unsigned char* data, int length);

    /**
     * @brief Декодирует строку Base64 в бинарные данные.
     *
     * @param input Строка в Base64.
     * @param output Буфер для результата (должен быть достаточного размера).
     * @return Длина декодированных данных или -1 при ошибке.
     */
    static int base64Decode(const std::string& input, unsigned char* output);
};

#endif // PASSWORDHASHER_H
