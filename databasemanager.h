#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <string>
#include <memory>
#include <nanodbc/nanodbc.h>
#include <mutex>
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

private:
    // === Приватные поля ===

    std::unique_ptr<nanodbc::connection> connection_; ///< Умный указатель на соединение с БД
    bool isConnected_;                                 ///< Флаг активности соединения
    mutable std::string lastError_;                    ///< Текст последней ошибки (mutable для const методов)

    std::mutex dbMutex_;

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
};

#endif // DATABASEMANAGER_H
