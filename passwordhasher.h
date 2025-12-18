#ifndef PASSWORDHASHER_H
#define PASSWORDHASHER_H

#include <string>
#include <vector>

/**
 * @class PasswordHasher
 * @brief Класс для безопасного хеширования и проверки паролей.
 *
 * Использует алгоритм PBKDF2-HMAC-SHA256 из OpenSSL.
 * Предоставляет статические методы для работы с паролями.
 * Кросс-платформенный (Windows/Linux).
 *
 * @note Все методы класса статические - экземпляр класса не требуется.
 */
class PasswordHasher
{
public:
    // === Основные методы работы с паролями ===

    /**
     * @brief Хеширует пароль с помощью PBKDF2-HMAC-SHA256.
     *
     * Генерирует случайную соль и создает хеш пароля.
     * Формат результата: "алгоритм:итерации:соль:хеш"
     *
     * @param password Пароль в открытом виде.
     * @return Строка с хешем в формате "pbkdf2_sha256:10000:salt:hash".
     * @throw std::runtime_error при ошибке хеширования.
     */
    static std::string hashPassword(const std::string& password);

    /**
     * @brief Проверяет пароль по сохраненному хешу.
     *
     * Извлекает параметры из строки хеша и проверяет соответствие пароля.
     *
     * @param password Пароль для проверки (в открытом виде).
     * @param hash Хеш в формате "алгоритм:итерации:соль:хеш".
     * @return true если пароль верный, false если неверный или ошибка парсинга.
     */
    static bool verifyPassword(const std::string& password, const std::string& hash);

    /**
     * @brief Генерирует криптографически безопасную случайную соль.
     *
     * @param length Длина соли в байтах (по умолчанию 16).
     * @return Соль в Base64 кодировке.
     * @throw std::invalid_argument если длина вне допустимого диапазона (8-64 байта).
     * @throw std::runtime_error при ошибке генерации случайных чисел.
     */
    static std::string generateSalt(int length = 16);

    // === Методы проверки безопасности паролей ===

    /**
     * @brief Проверяет сложность пароля по политике безопасности.
     *
     * Требования к паролю:
     * 1. Минимум 8 символов
     * 2. Хотя бы одна заглавная буква
     * 3. Хотя бы одна строчная буква
     * 4. Хотя бы одна цифра
     * 5. Хотя бы один специальный символ
     * 6. Не должен быть в списке распространенных слабых паролей
     * 7. Не должен содержать простых последовательностей
     *
     * @param password Пароль для проверки.
     * @param error_msg[out] Сообщение об ошибке если пароль не соответствует требованиям.
     * @return true если пароль соответствует политике безопасности.
     */
    static bool validatePasswordComplexity(const std::string& password,
                                           std::string& error_msg);

    /**
     * @brief Вычисляет силу пароля (0-100 баллов).
     *
     * Критерии оценки:
     * - Длина пароля
     * - Разнообразие символов (буквы, цифры, специальные символы)
     * - Отсутствие последовательностей (qwerty, 12345 и т.д.)
     * - Отсутствие личной информации (логин, имя и т.д.)
     *
     * @param password Пароль для оценки.
     * @param user_login Логин пользователя (для проверки совпадений, опционально).
     * @return Оценка от 0 (очень слабый) до 100 (очень сильный).
     */
    static int calculatePasswordStrength(const std::string& password,
                                         const std::string& user_login = "");

    /**
     * @brief Генерирует случайный безопасный пароль.
     *
     * Создает пароль, который гарантированно соответствует политике безопасности.
     *
     * @param length Длина пароля (по умолчанию 12 символов).
     * @return Случайный пароль, соответствующий политике безопасности.
     * @note Если указана длина меньше 8, будет использовано значение по умолчанию (12).
     */
    static std::string generateSecurePassword(int length = 12);

private:
    // === Константы алгоритма ===
    static const int PBKDF2_ITERATIONS = 10000;  ///< Количество итераций PBKDF2
    static const int HASH_LENGTH = 32;           ///< Длина хеша SHA-256 в байтах

    // === Вспомогательные методы для кодирования ===

    /**
     * @brief Кодирует бинарные данные в Base64.
     *
     * @param data Указатель на бинарные данные.
     * @param length Длина данных в байтах.
     * @return Строка в Base64 кодировке.
     */
    static std::string base64Encode(const unsigned char* data, int length);

    /**
     * @brief Декодирует строку Base64 в бинарные данные.
     *
     * @param input Строка в Base64 кодировке.
     * @param output Буфер для результата (должен быть достаточного размера).
     * @return Длина декодированных данных в байтах или -1 при ошибке.
     */
    static int base64Decode(const std::string& input, unsigned char* output);

    // === Приватные методы для валидации паролей ===

    /**
     * @brief Проверяет наличие заглавных букв в строке.
     *
     * @param str Строка для проверки.
     * @return true если есть хотя бы одна заглавная буква.
     */
    static bool hasUpperCase(const std::string& str);

    /**
     * @brief Проверяет наличие строчных букв в строке.
     *
     * @param str Строка для проверки.
     * @return true если есть хотя бы одна строчная буква.
     */
    static bool hasLowerCase(const std::string& str);

    /**
     * @brief Проверяет наличие цифр в строке.
     *
     * @param str Строка для проверки.
     * @return true если есть хотя бы одна цифра.
     */
    static bool hasDigits(const std::string& str);

    /**
     * @brief Проверяет наличие специальных символов в строке.
     *
     * Специальные символы: !@#$%^&*()_+-=[]{}|;:,.<>?
     *
     * @param str Строка для проверки.
     * @return true если есть хотя бы один специальный символ.
     */
    static bool hasSpecialChars(const std::string& str);

    /**
     * @brief Проверяет, является ли пароль распространенным слабым паролем.
     *
     * @param password Пароль для проверки.
     * @return true если пароль находится в списке распространенных слабых паролей.
     */
    static bool isCommonPassword(const std::string& password);

    /**
     * @brief Проверяет наличие простых последовательностей в пароле.
     *
     * Обнаруживает:
     * - Цифровые последовательности (123, 456, 789 и т.д.)
     * - Клавиатурные последовательности (qwerty, asdfgh, zxcvbn)
     *
     * @param password Пароль для проверки.
     * @return true если обнаружены простые последовательности.
     */
    static bool containsSequence(const std::string& password);

    /**
     * @brief Проверяет, содержит ли пароль логин пользователя.
     *
     * Проверяет прямое и обратное вхождение логина в пароль
     * (без учета регистра).
     *
     * @param password Пароль для проверки.
     * @param login Логин пользователя.
     * @return true если пароль содержит логин.
     */
    static bool containsLogin(const std::string& password, const std::string& login);

    // === Список слабых паролей ===

    /**
     * @brief Возвращает список распространенных слабых паролей.
     *
     * @return Константная ссылка на вектор со слабыми паролями.
     * @note Список включает самые популярные ненадежные пароли.
     */
    static const std::vector<std::string>& getCommonPasswords();
};

#endif // PASSWORDHASHER_H
