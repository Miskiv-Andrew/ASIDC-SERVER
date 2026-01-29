#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <string>
#include <memory>
#include "nanodbc.h"
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#include "passwordhasher.h"

/**
 * @struct AuthResult
 * @brief Результат аутентификации пользователя.
 */
struct AuthResult {
    int user_id;           ///< ID пользователя (0 при ошибке)
    std::string role;      ///< Роль ("admin", "operator", "executor")
    std::string name;      ///< ФИО пользователя (для отображения)
    bool success;          ///< Флаг успешности операции
    std::string error_msg; ///< Сообщение об ошибке (если success=false)

    /// @brief Конструктор по умолчанию.
    AuthResult() : user_id(0), success(false) {}

    /// @brief Конструктор для успешного результата.
    AuthResult(int id, const std::string& user_role, const std::string& user_name)
        : user_id(id), role(user_role), name(user_name), success(true) {}

    /// @brief Конструктор для ошибки.
    AuthResult(const std::string& error)
        : user_id(0), success(false), error_msg(error) {}
};

/**
 * @struct TokenValidationResult
 * @brief Результат проверки токена аутентификации.
 */
struct TokenValidationResult {
    int user_id;           ///< ID пользователя (0 при невалидном токене)
    std::string role;      ///< Роль пользователя
    std::string name;      ///< Имя пользователя
    std::string login;     ///< Логин (для удобства)
    bool valid;            ///< Флаг валидности токена
    std::string error_msg; ///< Сообщение об ошибке (если valid=false)

    // Поля для отслеживания безопасности:
    std::string initial_ip; ///< IP-адрес при создании токена
    std::string last_ip;    ///< Последний использованный IP-адрес
    std::string user_agent; ///< User-Agent клиента
    bool ip_changed;        ///< Флаг изменения IP-адреса
    bool is_suspicious;     ///< Флаг подозрительности токена

    /// @brief Конструктор по умолчанию.
    TokenValidationResult()
        : user_id(0),
        valid(false),
        ip_changed(false),
        is_suspicious(false) {}

    /// @brief Конструктор для валидного токена.
    TokenValidationResult(int id, const std::string& user_role,
                          const std::string& user_name, const std::string& user_login)
        : user_id(id),
        role(user_role),
        name(user_name),
        login(user_login),
        valid(true),
        ip_changed(false),
        is_suspicious(false) {}

    /// @brief Конструктор для ошибки.
    TokenValidationResult(const std::string& error)
        : user_id(0),
        valid(false),
        error_msg(error),
        ip_changed(false),
        is_suspicious(false) {}
};


/**
 * @struct DeviceWriteResult
 * @brief Результат записи данных устройства.
 */
struct DeviceWriteResult {
    bool success;          ///< Флаг успешности операции
    int status;            ///< Статус: 0 - успех, 1 - ошибка в данных, 2 - устройство не найдено, 3 - ошибка БД
    std::string message;   ///< Сообщение об ошибке или успехе

    DeviceWriteResult() : success(false), status(3) {}
    DeviceWriteResult(int s, const std::string& msg) : success(s == 0), status(s), message(msg) {}
};

struct MeasureRow {
    std::string timestamp;
    std::string key;
    std::string value;
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
     * @brief Выполняет произвольный SQL запрос без возврата результата.
     *
     * Используется для выполнения DDL команд (CREATE, ALTER, DROP) и DML команд
     * (INSERT, UPDATE, DELETE) которые не возвращают набор данных.
     *
     * @param query SQL запрос для выполнения.
     * @return true - запрос выполнен успешно, false - произошла ошибка.
     *
     * @note Для SELECT запросов используйте другие методы.
     * @note Поддерживает многострочные запросы и комментарии SQL.
     * @warning Метод не выполняет валидацию SQL - убедитесь в корректности запроса.
     */
    bool executeQuery(const std::string& query);

    /**
     * @brief Инициализирует все необходимые stored procedures в БД.
     *
     * Создает или пересоздает процедуры, необходимые для работы системы.
     * Вызывается автоматически при инициализации соединения с БД.
     *
     * @return true если все процедуры созданы успешно, false при ошибке.
     */
    bool initializeStoredProcedures();

    // === Методы аутентификации и работы с пользователями ===

    /**
     * @brief Аутентифицирует пользователя по логину и паролю.
     *
     * @param login Логин пользователя.
     * @param password Пароль пользователя (в открытом виде).
     * @return Структура AuthResult с результатом аутентификации.
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
     * @param current_ip Текущий IP-адрес клиента (для проверки безопасности).
     * @param current_user_agent Текущий User-Agent клиента (для проверки безопасности).
     * @return Структура TokenValidationResult с результатом проверки.
     *
     * @note Метод обновляет поле last_activity при успешной проверке.
     * @note Для несуществующих или истекших токенов возвращает valid = false.
     */
    TokenValidationResult validateToken(const std::string& token,
                                        const std::string& current_ip = "",
                                        const std::string& current_user_agent = "");

    /**
     * @brief Помечает токен как подозрительный.
     *
     * @param token Токен для пометки.
     * @param reason Причина пометки (для логов).
     * @return true если успешно, false при ошибке.
     */
    bool markTokenAsSuspicious(const std::string& token,
                               const std::string& reason = "");

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
     * @note Ошибки выполнения запроса игнорируются, чтобы не прерывать основную операцию.
     * @warning Не обновляет токены с истекшим сроком действия.
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
     * @return true - токен успешно удален или не существовал,
     *         false - произошла ошибка при удалении.
     *
     * @note Удаление несуществующего токена считается успешной операцией.
     */
    bool invalidateToken(const std::string& token);

    /**
     * @brief Записывает данные устройства через stored procedure.
     *
     * Вызывает MySQL процедуру save_device_measures для сохранения данных.
     *
     * @param jsonInput JSON-строка с данными устройства в формате:
     *                  {"dev_id":"1","keys":[{"temp":23.5},{"hum":45.2},...]}
     * @return DeviceWriteResult с результатом операции.
     */
    DeviceWriteResult saveDeviceMeasures(const std::string& jsonInput);

    std::vector<MeasureRow> readDeviceMeasures(
        int devId,
        const std::optional<std::string>& dateFrom,
        const std::optional<std::string>& dateTo,
        const std::optional<std::string>& areaPolygon,
        const std::optional<std::string>& keysJson,
        int limit,
        int offset
        );

    int getMeasuresTotalCount(int devId);

    // === Структуры для возврата результатов ===

    /**
     * @struct UserInfo
     * @brief Информация о пользователе.
     */
    struct UserInfo {
        int id;                ///< ID пользователя
        std::string login;     ///< Логин
        std::string name;      ///< ФИО пользователя
        std::string role;      ///< Роль в системе
        std::string phone;     ///< Телефон
        std::string email;     ///< Email
        bool is_active;        ///< Флаг активности
        std::string created_at;///< Дата создания
    };

    /**
     * @struct CreateUserResult
     * @brief Результат создания пользователя.
     */
    struct CreateUserResult {
        int user_id;           ///< ID созданного пользователя
        bool success;          ///< Флаг успешности операции
        std::string error_msg; ///< Сообщение об ошибке

        /// @brief Конструктор по умолчанию.
        CreateUserResult() : user_id(0), success(false) {}

        /// @brief Конструктор для успеха.
        CreateUserResult(int id) : user_id(id), success(true) {}
    };

    /**
     * @struct UpdateUserResult
     * @brief Результат обновления пользователя.
     */
    struct UpdateUserResult {
        bool success;          ///< Флаг успешности операции
        std::string error_msg; ///< Сообщение об ошибке
    };

    /**
     * @struct DeleteUserResult
     * @brief Результат деактивации пользователя.
     */
    struct DeleteUserResult {
        bool success;          ///< Флаг успешности операции
        std::string error_msg; ///< Сообщение об ошибке
    };

    /**
     * @struct ChangePasswordResult
     * @brief Результат смены пароля.
     */
    struct ChangePasswordResult {
        bool success;          ///< Флаг успешности операции
        std::string error_msg; ///< Сообщение об ошибке
    };

    /**
     * @struct RefreshTokenResult
     * @brief Результат обновления токена.
     */
    struct RefreshTokenResult {
        std::string new_token; ///< Новый токен
        int user_id;           ///< ID пользователя
        std::string role;      ///< Роль пользователя
        std::string name;      ///< Имя пользователя
        std::string login;     ///< Логин пользователя
        bool success;          ///< Флаг успешности операции
        std::string error_msg; ///< Сообщение об ошибке

        /// @brief Конструктор по умолчанию.
        RefreshTokenResult() : user_id(0), success(false) {}

        /// @brief Конструктор для ошибки.
        RefreshTokenResult(const std::string& error)
            : user_id(0), success(false), error_msg(error) {}
    };

    // === Методы управления пользователями ===

    /**
     * @brief Получает список всех пользователей системы.
     *
     * @return Вектор структур UserInfo с информацией о пользователях.
     */
    std::vector<UserInfo> getUsersList();

    /**
     * @brief Создает нового пользователя.
     *
     * @param login Логин пользователя.
     * @param password Пароль пользователя.
     * @param name ФИО пользователя.
     * @param role Роль пользователя.
     * @param phone Телефон пользователя (опционально).
     * @param email Email пользователя (опционально).
     * @return Результат операции создания пользователя.
     */
    CreateUserResult createUser(const std::string& login, const std::string& password,
                                const std::string& name, const std::string& role,
                                const std::string& phone = "", const std::string& email = "");

    /**
     * @brief Обновляет данные пользователя.
     *
     * @param user_id ID пользователя для обновления.
     * @param name Новое ФИО (опционально).
     * @param role Новая роль (опционально).
     * @param phone Новый телефон (опционально).
     * @param email Новый email (опционально).
     * @param is_active Новый статус активности (опционально).
     * @return Результат операции обновления.
     */
    UpdateUserResult updateUser(int user_id,
                                const std::string& name = "",
                                const std::string& role = "",
                                const std::string& phone = "",
                                const std::string& email = "",
                                bool is_active = true);

    /**
     * @brief Деактивирует пользователя.
     *
     * Устанавливает is_active = 0 и удаляет все активные токены пользователя.
     *
     * @param user_id ID пользователя для деактивации.
     * @return Результат операции деактивации.
     */
    DeleteUserResult deleteUser(int user_id);

    /**
     * @brief Смена пароля пользователем.
     *
     * Требует знания старого пароля. После успешной смены все активные токены
     * пользователя удаляются (принудительный выход со всех устройств).
     *
     * @param user_id ID пользователя.
     * @param old_password Старый пароль.
     * @param new_password Новый пароль.
     * @return Результат операции смены пароля.
     */
    ChangePasswordResult changePassword(int user_id,
                                        const std::string& old_password,
                                        const std::string& new_password);

    /**
     * @brief Обновляет токен аутентификации.
     *
     * Создает новый токен и инвалидирует старый. Используется для продления сессии
     * без повторного ввода пароля.
     *
     * @param old_token Старый токен для обновления.
     * @return Результат операции обновления токена.
     */
    RefreshTokenResult refreshAuthToken(const std::string& old_token);

    /**
     * @brief Сброс пароля пользователя администратором.
     *
     * Администратор может сбросить пароль любому пользователю без знания старого пароля.
     * Все активные токены пользователя инвалидируются.
     *
     * @param target_user_id ID пользователя, которому сбрасывается пароль.
     * @param new_password Новый пароль (должен соответствовать политике безопасности).
     * @return Результат операции сброса пароля.
     */
    ChangePasswordResult resetUserPassword(int target_user_id, const std::string& new_password);

private:
    // === Приватные поля ===
    std::unique_ptr<nanodbc::connection> connection_; ///< Умный указатель на соединение с БД
    bool isConnected_;                                 ///< Флаг активности соединения
    mutable std::string lastError_;                    ///< Текст последней ошибки (mutable для const методов)

    /// @brief Мьютекс для операций с базой данных.
    std::mutex dbMutex_;
    /// @brief Мьютекс для операций аутентификации.
    std::mutex authMutex_;
    /// @brief Мьютекс для операций с токенами.
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

    /**
     * @brief Генерирует криптографически безопасный токен.
     *
     * Использует системный генератор случайных чисел для создания токена
     * заданной длины. Результат преобразуется в hex-строку.
     *
     * @param length Длина токена в байтах (по умолчанию 32 байта = 64 hex-символа).
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
