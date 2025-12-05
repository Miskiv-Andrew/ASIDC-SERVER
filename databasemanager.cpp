#include "databasemanager.h"
#include <iostream>

/**
 * @brief Конструктор DatabaseManager.
 *
 * Инициализирует все поля значениями по умолчанию:
 * - connection_ = nullptr (соединение не установлено)
 * - isConnected_ = false (флаг неактивен)
 * - lastError_ = "" (ошибок нет)
 *
 * Выводит отладочное сообщение в консоль при создании объекта.
 */
DatabaseManager::DatabaseManager()
    : connection_(nullptr)
    , isConnected_(false)
{
    // Отладочный вывод (можно убрать в релизной версии)
    std::cout << "[DatabaseManager] The object has been created" << std::endl;
}

/**
 * @brief Деструктор DatabaseManager.
 *
 * Автоматически вызывает disconnect() для безопасного закрытия соединения
 * с базой данных. Если соединение активно, оно будет корректно закрыто.
 */
DatabaseManager::~DatabaseManager()
{
    disconnect();
}

/**
 * @brief Инициализирует соединение с базой данных.
 *
 * Последовательность действий:
 * 1. Закрывает предыдущее соединение (если было)
 * 2. Создает новое соединение через nanodbc
 * 3. Выполняет тестовый запрос для проверки работоспособности
 * 4. Устанавливает флаг isConnected_ и очищает ошибки при успехе
 *
 * @param connectionString Строка подключения ODBC.
 * @return true при успешном подключении, false при ошибке.
 */
bool DatabaseManager::initialize(const std::string& connectionString)
{
    // Закрываем предыдущее соединение (если оно было)
    disconnect();

    try {
        // Пытаемся установить соединение через ODBC
        // Конструктор nanodbc::connection может выбросить исключение
        // при неверных параметрах подключения или недоступности сервера
        connection_ = std::make_unique<nanodbc::connection>(connectionString);

        // Выполняем простой тестовый запрос для проверки соединения
        // Если соединение нерабочее, execute() выбросит исключение
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, "SELECT 1");  // Простейший запрос
        nanodbc::execute(stmt);              // Выполняем запрос

        // Если дошли сюда - соединение рабочее
        isConnected_ = true;
        lastError_.clear();  // Очищаем предыдущие ошибки

        // Отладочный вывод (можно убрать в релизной версии)
        std::cout << "[DatabaseManager] Successful connection to the database via:"
                  << connectionString << std::endl;

        return true;
    }
    catch (const nanodbc::database_error& e) {
        // Обработка специфических ошибок базы данных:
        // - неверный DSN или драйвер
        // - неправильные учетные данные
        // - недоступность сервера БД
        setLastError(std::string("Ошибка базы данных: ") + e.what());
    }
    catch (const std::exception& e) {
        // Обработка общих ошибок:
        // - проблемы с памятью (std::make_unique)
        // - сетевые проблемы
        // - другие стандартные исключения
        setLastError(std::string("Общая ошибка: ") + e.what());
    }
    catch (...) {
        // Обработка любых других исключений (нестандартных)
        setLastError("Неизвестная ошибка при подключении к БД");
    }

    // Если дошли сюда - подключение не удалось
    return false;
}

/**
 * @brief Проверяет активность соединения с БД.
 *
 * Возвращает значение флага isConnected_, который устанавливается
 * в true при успешном initialize() и сбрасывается в false при disconnect().
 *
 * @return true если соединение активно, false в противном случае.
 */
bool DatabaseManager::isConnected() const
{
    return isConnected_;
}

/**
 * @brief Закрывает соединение с базой данных.
 *
 * Безопасно освобождает ресурсы соединения. Метод идемпотентен - многократный
 * вызов не приводит к ошибкам. После вызова isConnected() вернет false.
 */
void DatabaseManager::disconnect()
{
    if (connection_) {
        // Умный указатель автоматически закрывает соединение при reset()
        connection_.reset();
        isConnected_ = false;  // Сбрасываем флаг активности

        // Отладочный вывод (можно убрать в релизной версии)
        std::cout << "[DatabaseManager] The connection to the database was closed." << std::endl;
    }
}

/**
 * @brief Возвращает текст последней ошибки.
 *
 * Полезен для диагностики проблем. Например, если initialize() вернул false,
 * этот метод покажет, что именно пошло не так.
 *
 * @return Текст последней ошибки или пустая строка если ошибок не было.
 */
std::string DatabaseManager::getLastError() const
{
    return lastError_;
}


AuthResult DatabaseManager::authenticateUser(const std::string& login, const std::string& password)
{
    AuthResult result;

    // Проверка подключения к базе данных
    if (!connection_ || !connection_->connected())
    {
        result.error_msg = "Database not connected";
        return result;
    }

    // Проверка входных данных
    if (login.empty() || password.empty())
    {
        result.error_msg = "Login and password cannot be empty";
        return result;
    }

    try
    {
        // SQL-запрос
        const std::string sql =
            "SELECT id, name, role, password_hash, "
            "CASE WHEN is_active = 1 THEN 'ACTIVE' ELSE 'INACTIVE' END as status "
            "FROM users "
            "WHERE login = ?";

        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, login.c_str());

        nanodbc::result results = nanodbc::execute(stmt);

        // Нет результатов = пользователь не найден
        if (!results.next())
        {
            result.error_msg = "User not found";
            return result;
        }

        // Извлечение данных с проверкой на NULL
        int user_id = -1;
        std::string name, role, password_hash, status;

        if (!results.is_null(0)) user_id = results.get<int>(0);
        if (!results.is_null(1)) name = results.get<std::string>(1);
        if (!results.is_null(2)) role = results.get<std::string>(2);
        if (!results.is_null(3)) password_hash = results.get<std::string>(3);
        if (!results.is_null(4)) status = results.get<std::string>(4);

        // Проверка активности
        if (status != "ACTIVE")
        {
            result.error_msg = "User account is deactivated";
            return result;
        }

        // Проверка пароля
        if (!PasswordHasher::verifyPassword(password, password_hash))
        {
            result.error_msg = "Invalid password";
            return result;
        }

        // Успешная аутентификация
        result.user_id = user_id;
        result.name = name;
        result.role = role;
        result.success = true;

        return result;
    }
    catch (const nanodbc::database_error& e)
    {
        result.error_msg = std::string("Database error: ") + e.what();
        return result;
    }
    catch (const std::exception& e)
    {
        result.error_msg = std::string("Error: ") + e.what();
        return result;
    }
    catch (...)
    {
        result.error_msg = "Unknown error during authentication";
        return result;
    }
}







/**
 * @brief Устанавливает текст последней ошибки.
 *
 * Внутренний метод для единообразного сохранения ошибок. Выводит
 * сообщение об ошибке в stderr для отладки.
 *
 * @param error Текст ошибки для сохранения.
 */
void DatabaseManager::setLastError(const std::string& error) const
{
    lastError_ = error;  // Сохраняем текст ошибки

    // Выводим в стандартный поток ошибок для отладки
    // В будущем можно заменить на запись в лог-файл
    std::cerr << "[DatabaseManager Ошибка] " << error << std::endl;
}
