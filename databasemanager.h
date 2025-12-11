#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <string>
#include <memory>
#include <nanodbc/nanodbc.h>
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#include <QDebug>

#include "passwordhasher.h"


// Структура для результата аутентификации
struct AuthResult {
    int user_id;           // ID пользователя (0 при ошибке)
    std::string role;      // Роль ("admin", "operator", "executor")
    std::string name;      // ФИО пользователя (для отображения)
    bool success;          // Флаг успешности
    std::string error_msg; // Сообщение об ошибке (если success=false)

    // Конструктор по умолчанию
    AuthResult() : user_id(0), success(false) {}

    // Конструктор для успешного результата
    AuthResult(int id, const std::string& user_role, const std::string& user_name)
        : user_id(id), role(user_role), name(user_name), success(true) {}

    // Конструктор для ошибки
    AuthResult(const std::string& error)
        : user_id(0), success(false), error_msg(error) {}
};


// Структура для результата проверки токена
struct TokenValidationResult {
    int user_id;           // ID пользователя (0 при невалидном токене)
    std::string role;      // Роль пользователя
    std::string name;      // Имя пользователя
    std::string login;     // Логин (для удобства)
    bool valid;            // Флаг валидности токена
    std::string error_msg; // Сообщение об ошибке (если valid=false)

    // Конструктор по умолчанию
    TokenValidationResult() : user_id(0), valid(false) {}

    // Конструктор для валидного токена
    TokenValidationResult(int id, const std::string& user_role,
                          const std::string& user_name, const std::string& user_login)
        : user_id(id), role(user_role), name(user_name),
        login(user_login), valid(true) {}

    // Конструктор для ошибки
    TokenValidationResult(const std::string& error)
        : user_id(0), valid(false), error_msg(error) {}
};

/**
 * @class DatabaseManager
 * @brief Класс для управления подключением и выполнением запросов к базе данных.
 *
 * Чистый C++ класс без зависимостей от Qt. Предоставляет интерфейс для работы
 * с базой данных через ODBC DSN "GuarderDB". Использует библиотеку nanodbc
 * для выполнения SQL-запросов.
 *
 * Архитектура: один экземпляр на все время работы сервера, постоянное соединение.
 */
class DatabaseManager
{
public:
    /**
     * @brief Конструктор по умолчанию.
     *
     * Инициализирует внутренние поля значениями по умолчанию.
     * Не устанавливает соединение с БД - для этого нужно вызвать initialize().
     */
    DatabaseManager();

    /**
     * @brief Деструктор.
     *
     * Автоматически закрывает соединение с базой данных при уничтожении объекта.
     */
    ~DatabaseManager();

    // === Основные методы управления подключением ===

    /**
     * @brief Инициализирует соединение с базой данных.
     *
     * Устанавливает постоянное соединение через ODBC DSN. Проверяет соединение
     * простым тестовым запросом "SELECT 1". Если соединение уже установлено,
     * предыдущее закрывается перед созданием нового.
     *
     * @param connectionString Строка подключения ODBC. По умолчанию "DSN=GuarderDB".
     * @return true - соединение успешно установлено, false - произошла ошибка.
     */
    bool initialize(const std::string& connectionString = "DSN=GuarderDB");

    /**
     * @brief Проверяет активность соединения с БД.
     *
     * @return true - соединение активно, false - соединение отсутствует или разорвано.
     */
    bool isConnected() const;

    /**
     * @brief Закрывает соединение с базой данных.
     *
     * Безопасно освобождает ресурсы соединения. Если соединение не было установлено,
     * метод не выполняет никаких действий.
     */
    void disconnect();

    /**
     * @brief Возвращает текст последней ошибки.
     *
     * Используется для диагностики проблем при подключении или выполнении запросов.
     *
     * @return Текст последней зарегистрированной ошибки или пустая строка.
     */
    std::string getLastError() const;

    /**
     * @brief Аутентификация пользователя
     *
     * Используется для диагностики проблем при подключении или выполнении запросов.
     *
     * @return Структура с данными инициализации
     */
    AuthResult authenticateUser(const std::string& login, const std::string& password);





    /**
     * @brief Создает новый токен аутентификации для пользователя.
     *
     * Генерирует криптографически безопасный токен, сохраняет его в таблицу tokens
     * с привязкой к указанному пользователю. Токен имеет ограниченный срок действия
     * (по умолчанию 24 часа с момента создания).
     *
     * @param user_id ID пользователя, для которого создается токен.
     * @param ip_address IP-адрес клиента, с которого выполняется запрос.
     * @param user_agent Заголовок User-Agent клиентского приложения/браузера.
     *
     * @return Сгенерированный токен в виде hex-строки (64 символа).
     *         Пустая строка возвращается в случае ошибки.
     *
     * @note Токен автоматически помечается как невалидный после истечения срока действия.
     * @note Для одного пользователя может существовать несколько активных токенов
     *       (разные устройства/браузеры).
     */
    std::string createAuthToken(int user_id,
                                    const std::string& ip_address,
                                    const std::string& user_agent);

        /**
     * @brief Проверяет валидность токена аутентификации.
     *
     * Выполняет поиск токена в таблице tokens, проверяет:
     * 1. Существование токена в БД
     * 2. Не истек ли срок действия (expires_at > текущее время)
     * 3. Не помечен ли токен как подозрительный (is_suspicious = FALSE)
     *
     * При успешной проверке возвращает информацию о пользователе, связанном с токеном.
     *
     * @param token Токен для проверки (в формате hex-строки).
     *
     * @return Структура TokenValidationResult, содержащая:
     *         - user_id: ID пользователя (0 при невалидном токене)
     *         - role: роль пользователя в системе
     *         - name: ФИО пользователя
     *         - login: логин пользователя
     *         - valid: флаг валидности токена (true/false)
     *         - error_msg: сообщение об ошибке (если valid = false)
     *
     * @note Метод обновляет поле last_activity при успешной проверке.
     * @note Для несуществующих или истекших токенов возвращает valid = false.
     */
    TokenValidationResult validateToken(const std::string& token);


    /**
     * @brief Обновляет время последней активности для указанного токена.
     *
     * Метод выполняет обновление поля last_activity в таблице tokens,
     * устанавливая его значение в текущее время сервера БД (NOW()).
     * Это позволяет отслеживать активность пользователей и автоматически
     * удалять неиспользуемые токены по истечении определенного периода.
     *
     * @param token Токен, для которого нужно обновить время активности.
     *             Должен быть валидным токеном, существующим в таблице tokens.
     *
     * @note Метод вызывается из validateToken() при каждой успешной проверке токена.
     * @note Использует SQL-функцию NOW(), которая возвращает текущее время сервера БД,
     *       что обеспечивает консистентность времени между всеми узлами системы.
     * @note Ошибки выполнения запроса игнорируются (catch(...)), чтобы не прерывать
     *       основную операцию проверки токена из-за несущественной проблемы обновления
     *       времени активности.
     *
     * @exception Не бросает исключения наружу. Все исключения перехватываются
     *            и игнорируются внутри метода.
     *
     * @warning Не обновляет токены с истекшим сроком действия (expires_at < NOW()).
     *          Такие токены должны быть удалены через cleanupExpiredTokens().
     *
     * @see validateToken()
     * @see cleanupExpiredTokens()
     */
    void updateTokenActivity(const std::string& token);






    /**
     * @brief Инвалидирует (аннулирует) токен аутентификации.
     *
     * Удаляет токен из таблицы tokens, делая его недействительным для
     * последующей аутентификации. Используется при выходе пользователя из системы
     * или принудительном разлогине администратором.
     *
     * @param token Токен для инвалидации.
     *
     * @return true - токен успешно удален или не существовал,
     *         false - произошла ошибка при удалении.
     *
     * @note Удаление несуществующего токена считается успешной операцией.
     * @note После вызова этого метода validateToken() для данного токена
     *       будет возвращать valid = false.
     */
    bool invalidateToken(const std::string& token);



    struct UserInfo {
        int id;
        std::string login;
        std::string name;
        std::string role;
        std::string phone;
        std::string email;
        bool is_active;
        std::string created_at;
    };

    struct CreateUserResult {
        int user_id;
        bool success;
        std::string error_msg;
    };

    struct UpdateUserResult {
        bool success;
        std::string error_msg;
    };


    struct DeleteUserResult {
        bool success;
        std::string error_msg;
    };

    struct ChangePasswordResult {
        bool success;
        std::string error_msg;
    };



    std::vector<UserInfo> getUsersList();

    CreateUserResult createUser(const std::string& login, const std::string& password,
                                const std::string& name, const std::string& role,
                                const std::string& phone = "", const std::string& email = "");

    UpdateUserResult updateUser(int user_id,
                                const std::string& name = "",
                                const std::string& role = "",
                                const std::string& phone = "",
                                const std::string& email = "",
                                bool is_active = true);

    // реально не удаляем, а только is_active = 0
    DeleteUserResult deleteUser(int user_id);

    ChangePasswordResult changePassword(int user_id,
                                        const std::string& old_password,
                                        const std::string& new_password);


private:
    // === Приватные поля ===

    std::unique_ptr<nanodbc::connection> connection_; ///< Умный указатель на соединение с БД
    bool isConnected_;                                 ///< Флаг активности соединения
    mutable std::string lastError_;                    ///< Текст последней ошибки (mutable для const методов)


    /**
     * @brief Мьютексы для потокобезопасности
     *
     * @note:
     *
     *  dbMutex_  - обращение к базам данных
     *
     *  authMutex_ - авторизация
     *
     *  tokenMutex_ - работа с токенами
     *
     */

    std::mutex dbMutex_;
    std::mutex authMutex_;
    std::mutex tokenMutex_;

    // === Вспомогательные методы ===

    /**
     * @brief Устанавливает текст последней ошибки.
     *
     * Внутренний метод для единообразной записи ошибок. Также выводит
     * сообщение об ошибке в стандартный поток ошибок (stderr).
     *
     * @param error Текст ошибки для сохранения.
     */
    void setLastError(const std::string& error) const;

private:
    /**
     * @brief Генерирует криптографически безопасный токен.
     *
     * Использует системный генератор случайных чисел для создания токена
     * заданной длины. Результат преобразуется в hex-строку.
     *
     * @param length Длина токена в байтах (по умолчанию 32 байта = 64 hex-символа).
     *
     * @return Сгенерированный токен в виде hex-строки.
     *
     * @note Для генерации используется std::random_device или /dev/urandom.
     * @note Длина выходной строки = length * 2 (hex-кодирование).
     */
    std::string generateSecureToken(size_t length = 32);

    /**
     * @brief Очищает таблицу tokens от устаревших записей.
     *
     * Удаляет из таблицы tokens все записи, у которых истек срок действия
     * (expires_at < текущее время). Вызывается периодически или при создании
     * новых токенов для поддержания чистоты БД.
     *
     * @return Количество удаленных записей.
     *
     * @note Метод безопасен для конкурентного выполнения.
     * @note Рекомендуется вызывать не чаще чем раз в час.
     */
    int cleanupExpiredTokens();
};

#endif // DATABASEMANAGER_H
