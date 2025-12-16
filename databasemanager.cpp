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
    // Блокируем метод
    std::lock_guard<std::mutex> lock(authMutex_);

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



std::string DatabaseManager::generateSecureToken(size_t length)
{
    // Буфер для случайных байт
    std::vector<unsigned char> buffer(length);

    // Используем криптографически безопасный генератор случайных чисел
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);

    // Заполняем буфер случайными байтами
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<unsigned char>(dist(rd));
    }

    // Преобразуем в hex-строку
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (unsigned char byte : buffer) {
        ss << std::setw(2) << static_cast<int>(byte);
    }

    return ss.str();
}

int DatabaseManager::cleanupExpiredTokens()
{
    if (!isConnected_) {
        return 0;
    }

    try {
        std::string sql = "DELETE FROM tokens WHERE expires_at < NOW()";
        nanodbc::statement stmt(*connection_);
        nanodbc::execute(stmt);

        // Получаем количество удаленных строк
        // (nanodbc не возвращает rows affected для DELETE,
        // можно использовать ROW_COUNT() в MySQL)

        std::cout << "[INFO] Expired tokens cleanup performed" << std::endl;
        return 1; // В реальности нужно возвращать реальное количество

    } catch (...) {
        // Игнорируем ошибки очистки
        return 0;
    }
}

std::string DatabaseManager::createAuthToken(int user_id, const std::string &ip_address, const std::string &user_agent)
{
    std::lock_guard<std::mutex> lock(tokenMutex_);

    // Проверка входных параметров
    if (user_id <= 0) {
        std::cerr << "[ERROR] Invalid user_id for token creation" << std::endl;
        return "";
    }

    if (!isConnected_) {
        std::cerr << "[ERROR] Database not connected for token creation" << std::endl;
        return "";
    }

    try {
        // Генерируем токен
        std::string token = generateSecureToken(32);

        // Вычисляем время истечения
        auto now = std::chrono::system_clock::now();
        auto expires_time = now + std::chrono::hours(24);
        std::time_t expires_time_t = std::chrono::system_clock::to_time_t(expires_time);
        std::tm expires_tm = *std::gmtime(&expires_time_t);

        char expires_str[20];
        std::strftime(expires_str, sizeof(expires_str),
                      "%Y-%m-%d %H:%M:%S", &expires_tm);

        // SQL запрос
        std::string sql =
            "INSERT INTO tokens (token, user_id, expires_at, initial_ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?)";

        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);


        // 1. Токен (строка)
        stmt.bind(0, token.c_str());

        // nanodbc ожидает указатель на данные и размер
        stmt.bind(1, &user_id, 1);

        // 3. expires_at (строка)
        stmt.bind(2, expires_str);

        // 4. IP (строка, может быть NULL)
        if (ip_address.empty()) {
            stmt.bind_null(3);
        }

        else {
            stmt.bind(3, ip_address.c_str());
        }

        // 5. User-Agent (строка, может быть NULL)
        if (user_agent.empty()) {
            stmt.bind_null(4);
        } else {
            stmt.bind(4, user_agent.c_str());
        }

        // Выполняем запрос
        nanodbc::execute(stmt);

        // Очистка старых токенов
        cleanupExpiredTokens();

        return token;

    }
    catch (const nanodbc::database_error& e) {
        std::cerr << "[ERROR] Database error creating token: " << e.what() << std::endl;
        return "";
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Error creating token: " << e.what() << std::endl;
        return "";
    }
    catch (...) {
        std::cerr << "[ERROR] Unknown error creating token" << std::endl;
        return "";
    }
}


void DatabaseManager::updateTokenActivity(const std::string &token)
{
    try {
        std::string sql = "UPDATE tokens SET last_activity = NOW() WHERE token = ?";
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, token.c_str());
        nanodbc::execute(stmt);
    }

    catch (...) {
        // Игнорируем ошибки обновления активности
    }
}

bool DatabaseManager::invalidateToken(const std::string& token)
{
    if (token.empty() || !isConnected_) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tokenMutex_);

    try {
        std::string sql = "DELETE FROM tokens WHERE token = ?";
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, token.c_str());
        nanodbc::execute(stmt);

        return true;
    }
    catch (...) {
        return false;
    }
}


// TokenValidationResult DatabaseManager::validateToken(const std::string& token,
//                                                      const std::string& current_ip)
// {
//     // Проверка входных параметров
//     if (token.empty()) {
//         return TokenValidationResult("Token cannot be empty");
//     }

//     if (!isConnected_) {
//         return TokenValidationResult("Database not connected");
//     }

//     std::lock_guard<std::mutex> lock(tokenMutex_);

//     try {
//         // SQL запрос: проверяем токен и получаем информацию о пользователе
//         // Включаем проверку expires_at > NOW() на уровне SQL
//         std::string sql =
//             "SELECT t.user_id, u.login, u.name, u.role, t.expires_at, "
//             "t.is_suspicious, t.initial_ip, t.user_agent, t.last_ip "
//             "FROM tokens t "
//             "JOIN users u ON t.user_id = u.id "
//             "WHERE t.token = ? "
//             "AND t.expires_at > NOW()";

//         nanodbc::statement stmt(*connection_);
//         nanodbc::prepare(stmt, sql);
//         stmt.bind(0, token.c_str());

//         nanodbc::result results = nanodbc::execute(stmt);

//         // Токен не найден или истек
//         if (!results.next()) {
//             return TokenValidationResult("Token not found or expired");
//         }

//         // Извлекаем данные
//         int user_id = -1;
//         std::string login, name, role, expires_at_str;
//         std::string initial_ip, user_agent, last_ip;
//         int is_suspicious_int = 0;

//         if (!results.is_null(0)) user_id = results.get<int>(0);
//         if (!results.is_null(1)) login = results.get<std::string>(1);
//         if (!results.is_null(2)) name = results.get<std::string>(2);
//         if (!results.is_null(3)) role = results.get<std::string>(3);
//         if (!results.is_null(4)) expires_at_str = results.get<std::string>(4);
//         if (!results.is_null(5)) is_suspicious_int = results.get<int>(5);
//         if (!results.is_null(6)) initial_ip = results.get<std::string>(6);
//         if (!results.is_null(7)) user_agent = results.get<std::string>(7);
//         if (!results.is_null(8)) last_ip = results.get<std::string>(8);

//         // Создаем объект результата
//         TokenValidationResult result(user_id, role, name, login);
//         result.initial_ip = initial_ip;
//         result.last_ip = last_ip;
//         result.user_agent = user_agent;
//         result.is_suspicious = (is_suspicious_int == 1);

//         // Проверяем не помечен ли токен как подозрительный
//         if (result.is_suspicious) {
//             result.valid = false;
//             result.error_msg = "Token marked as suspicious";
//             return result;
//         }

//         // === НОВАЯ ЛОГИКА: Проверка IP-адреса ===
//         if (!current_ip.empty() && !initial_ip.empty()) {
//             // Проверяем, изменился ли IP
//             result.ip_changed = (current_ip != initial_ip);

//             if (result.ip_changed) {
//                 // IP изменился - помечаем токен как подозрительный
//                 try {
//                     std::string updateSql =
//                         "UPDATE tokens SET is_suspicious = TRUE, last_ip = ? WHERE token = ?";
//                     nanodbc::statement updateStmt(*connection_);
//                     nanodbc::prepare(updateStmt, updateSql);
//                     updateStmt.bind(0, current_ip.c_str());
//                     updateStmt.bind(1, token.c_str());
//                     updateStmt.execute();

//                     result.is_suspicious = true;
//                     result.valid = false;
//                     result.error_msg = "Suspicious activity detected: IP address changed from " +
//                                        initial_ip + " to " + current_ip;

//                     std::cout << "[SECURITY] Token marked as suspicious: IP changed "
//                               << initial_ip << " -> " << current_ip
//                               << " (user: " << login << ")" << std::endl;

//                     return result;
//                 }
//                 catch (const std::exception& e) {
//                     std::cerr << "[ERROR] Failed to mark token as suspicious: "
//                               << e.what() << std::endl;
//                 }
//             }
//             else {
//                 // IP не изменился, просто обновляем last_ip
//                 try {
//                     std::string updateIpSql = "UPDATE tokens SET last_ip = ? WHERE token = ?";
//                     nanodbc::statement updateIpStmt(*connection_);
//                     nanodbc::prepare(updateIpStmt, updateIpSql);
//                     updateIpStmt.bind(0, current_ip.c_str());
//                     updateIpStmt.bind(1, token.c_str());
//                     updateIpStmt.execute();

//                     result.last_ip = current_ip; // Обновляем в результате
//                 }
//                 catch (...) {
//                     // Игнорируем ошибки обновления IP
//                 }
//             }
//         }

//         // Обновляем last_activity
//         updateTokenActivity(token);

//         return result;
//     }
//     catch (const nanodbc::database_error& e) {
//         return TokenValidationResult(std::string("Database error: ") + e.what());
//     }
//     catch (const std::exception& e) {
//         return TokenValidationResult(std::string("Error: ") + e.what());
//     }
//     catch (...) {
//         return TokenValidationResult("Unknown error validating token");
//     }
// }




TokenValidationResult DatabaseManager::validateToken(const std::string& token,
                                                     const std::string& current_ip,
                                                     const std::string& current_user_agent)
{
    // Проверка входных параметров
    if (token.empty()) {
        return TokenValidationResult("Token cannot be empty");
    }

    if (!isConnected_) {
        return TokenValidationResult("Database not connected");
    }

    std::lock_guard<std::mutex> lock(tokenMutex_);

    try {
        // SQL запрос: проверяем токен и получаем информацию о пользователе
        // Включаем проверку expires_at > NOW() на уровне SQL
        std::string sql =
            "SELECT t.user_id, u.login, u.name, u.role, t.expires_at, "
            "t.is_suspicious, t.initial_ip, t.user_agent, t.last_ip "
            "FROM tokens t "
            "JOIN users u ON t.user_id = u.id "
            "WHERE t.token = ? "
            "AND t.expires_at > NOW()";

        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, token.c_str());

        nanodbc::result results = nanodbc::execute(stmt);

        // Токен не найден или истек
        if (!results.next()) {
            return TokenValidationResult("Token not found or expired");
        }

        // Извлекаем данные
        int user_id = -1;
        std::string login, name, role, expires_at_str;
        std::string initial_ip, stored_user_agent, last_ip;
        int is_suspicious_int = 0;

        if (!results.is_null(0)) user_id = results.get<int>(0);
        if (!results.is_null(1)) login = results.get<std::string>(1);
        if (!results.is_null(2)) name = results.get<std::string>(2);
        if (!results.is_null(3)) role = results.get<std::string>(3);
        if (!results.is_null(4)) expires_at_str = results.get<std::string>(4);
        if (!results.is_null(5)) is_suspicious_int = results.get<int>(5);
        if (!results.is_null(6)) initial_ip = results.get<std::string>(6);
        if (!results.is_null(7)) stored_user_agent = results.get<std::string>(7);
        if (!results.is_null(8)) last_ip = results.get<std::string>(8);

        // Создаем объект результата
        TokenValidationResult result(user_id, role, name, login);
        result.initial_ip = initial_ip;
        result.last_ip = last_ip;
        result.user_agent = stored_user_agent;
        result.is_suspicious = (is_suspicious_int == 1);

        // Проверяем не помечен ли токен как подозрительный
        if (result.is_suspicious) {
            result.valid = false;
            result.error_msg = "Token marked as suspicious";
            return result;
        }

        bool security_issue_detected = false;
        std::string security_reason = "";

        // === ПРОВЕРКА IP-АДРЕСА ===
        if (!current_ip.empty() && !initial_ip.empty()) {
            // Проверяем, изменился ли IP
            result.ip_changed = (current_ip != initial_ip);

            if (result.ip_changed) {
                security_issue_detected = true;
                security_reason = "IP address changed from " + initial_ip + " to " + current_ip;
            }
            else {
                // IP не изменился, просто обновляем last_ip
                try {
                    std::string updateIpSql = "UPDATE tokens SET last_ip = ? WHERE token = ?";
                    nanodbc::statement updateIpStmt(*connection_);
                    nanodbc::prepare(updateIpStmt, updateIpSql);
                    updateIpStmt.bind(0, current_ip.c_str());
                    updateIpStmt.bind(1, token.c_str());
                    updateIpStmt.execute();

                    result.last_ip = current_ip; // Обновляем в результате
                }
                catch (...) {
                    // Игнорируем ошибки обновления IP
                }
            }
        }

        // === ПРОВЕРКА USER-AGENT ===
        if (!current_user_agent.empty() && !stored_user_agent.empty()) {
            // Проверяем, изменился ли User-Agent
            bool user_agent_changed = (current_user_agent != stored_user_agent);

            if (user_agent_changed) {
                if (security_issue_detected) {
                    security_reason += " and User-Agent changed";
                } else {
                    security_issue_detected = true;
                    security_reason = "User-Agent changed";
                }
            }
        }

        // Если обнаружена проблема безопасности
        if (security_issue_detected) {
            try {
                std::string updateSql =
                    "UPDATE tokens SET is_suspicious = TRUE WHERE token = ?";
                nanodbc::statement updateStmt(*connection_);
                nanodbc::prepare(updateStmt, updateSql);
                updateStmt.bind(0, token.c_str());
                updateStmt.execute();

                result.is_suspicious = true;
                result.valid = false;
                result.error_msg = "Suspicious activity detected: " + security_reason;

                std::cout << "[SECURITY] Token marked as suspicious: " << security_reason
                          << " (user: " << login << ")" << std::endl;

                return result;
            }
            catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to mark token as suspicious: "
                          << e.what() << std::endl;
            }
        }

        // Обновляем last_activity
        updateTokenActivity(token);

        return result;
    }
    catch (const nanodbc::database_error& e) {
        return TokenValidationResult(std::string("Database error: ") + e.what());
    }
    catch (const std::exception& e) {
        return TokenValidationResult(std::string("Error: ") + e.what());
    }
    catch (...) {
        return TokenValidationResult("Unknown error validating token");
    }
}













bool DatabaseManager::markTokenAsSuspicious(const std::string& token,
                                            const std::string& reason)
{
    if (token.empty() || !isConnected_) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tokenMutex_);

    try {
        std::string sql = "UPDATE tokens SET is_suspicious = TRUE WHERE token = ?";
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, token.c_str());
        stmt.execute();

        if (!reason.empty()) {
            std::cout << "[SECURITY] Token marked as suspicious: " << reason << std::endl;
        }

        return true;
    }
    catch (...) {
        return false;
    }
}





std::vector<DatabaseManager::UserInfo> DatabaseManager::getUsersList()
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    std::vector<UserInfo> users;

    if (!isConnected_) {
        return users;
    }

    try {
        std::string sql =
            "SELECT id, login, name, role, phone, email, is_active, created_at "
            "FROM users "
            "ORDER BY id";

        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);  // <-- ДОБАВИТЬ prepare
        nanodbc::result results = nanodbc::execute(stmt);  // <-- БЕЗ sql

        while (results.next()) {
            UserInfo user;

            if (!results.is_null(0)) user.id = results.get<int>(0);
            if (!results.is_null(1)) user.login = results.get<std::string>(1);
            if (!results.is_null(2)) user.name = results.get<std::string>(2);
            if (!results.is_null(3)) user.role = results.get<std::string>(3);
            if (!results.is_null(4)) user.phone = results.get<std::string>(4);
            if (!results.is_null(5)) user.email = results.get<std::string>(5);
            if (!results.is_null(6)) user.is_active = results.get<int>(6) == 1;
            if (!results.is_null(7)) user.created_at = results.get<std::string>(7);

            users.push_back(user);
        }

        return users;

    }
    catch (const std::exception& e) {
        setLastError(std::string("Failed to get users list: ") + e.what());
        std::cerr << "[ERROR] getUsersList: " << e.what() << std::endl;  // ДОБАВИТЬ
        return users;
    }
}







// DatabaseManager::CreateUserResult DatabaseManager::createUser(
//     const std::string& login, const std::string& password,
//     const std::string& name, const std::string& role,
//     const std::string& phone, const std::string& email)
// {
//     std::lock_guard<std::mutex> lock(dbMutex_);
//     CreateUserResult result;

//     if (!isConnected_) {
//         result.error_msg = "Database not connected";
//         return result;
//     }

//     // Валидация входных данных
//     if (login.empty() || password.empty() || name.empty() || role.empty()) {
//         result.error_msg = "Login, password, name and role are required";
//         return result;
//     }

//     if (role != "admin" && role != "operator" && role != "executor") {
//         result.error_msg = "Invalid role. Must be: admin, operator, executor";
//         return result;
//     }

//     // НОВАЯ ПРОВЕРКА: Валидация сложности пароля
//     std::string complexity_error;
//     if (!PasswordHasher::validatePasswordComplexity(password, complexity_error)) {
//         result.error_msg = complexity_error;
//         return result;
//     }

//     // ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА: Пароль не должен содержать логин
//     std::string lower_password = password;
//     std::string lower_login = login;

//     // Приводим к нижнему регистру для сравнения
//     for (char& c : lower_password) c = std::tolower(c);
//     for (char& c : lower_login) c = std::tolower(c);

//     if (lower_password.find(lower_login) != std::string::npos) {
//         result.error_msg = "Password should not contain the login";
//         return result;
//     }

//     try {
//         // Проверяем, не существует ли уже такой логин
//         std::string checkSql = "SELECT COUNT(*) FROM users WHERE login = ?";
//         nanodbc::statement checkStmt(*connection_);
//         nanodbc::prepare(checkStmt, checkSql);
//         checkStmt.bind(0, login.c_str());

//         nanodbc::result checkResult = checkStmt.execute();
//         if (checkResult.next()) {
//             int count = checkResult.get<int>(0);
//             if (count > 0) {
//                 result.error_msg = "Login already exists";
//                 return result;
//             }
//         }

//         // Генерируем хеш пароля
//         std::string passwordHash = PasswordHasher::hashPassword(password);

//         // Извлекаем соль из хеша (формат: алгоритм:итерации:соль:хеш)
//         size_t pos1 = passwordHash.find(':');
//         size_t pos2 = passwordHash.find(':', pos1 + 1);
//         size_t pos3 = passwordHash.find(':', pos2 + 1);

//         if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
//             result.error_msg = "Password hash generation failed";
//             return result;
//         }

//         std::string salt = passwordHash.substr(pos2 + 1, pos3 - pos2 - 1);

//         // Вставляем пользователя в БД
//         std::string insertSql =
//             "INSERT INTO users (login, name, role, phone, email, password_hash, salt, is_active) "
//             "VALUES (?, ?, ?, ?, ?, ?, ?, 1)";

//         nanodbc::statement insertStmt(*connection_);
//         nanodbc::prepare(insertStmt, insertSql);

//         insertStmt.bind(0, login.c_str());
//         insertStmt.bind(1, name.c_str());
//         insertStmt.bind(2, role.c_str());

//         if (phone.empty()) {
//             insertStmt.bind_null(3);
//         } else {
//             insertStmt.bind(3, phone.c_str());
//         }

//         if (email.empty()) {
//             insertStmt.bind_null(4);
//         } else {
//             insertStmt.bind(4, email.c_str());
//         }

//         insertStmt.bind(5, passwordHash.c_str());
//         insertStmt.bind(6, salt.c_str());

//         insertStmt.execute();

//         // Получаем ID созданного пользователя
//         std::string getIdSql = "SELECT LAST_INSERT_ID()";

//         nanodbc::statement idStmt(*connection_);
//         nanodbc::prepare(idStmt, getIdSql);
//         nanodbc::result idResult = idStmt.execute();

//         if (idResult.next()) {
//             result.user_id = idResult.get<int>(0);
//         }

//         result.success = true;
//         return result;

//     } catch (const nanodbc::database_error& e) {
//         result.error_msg = std::string("Database error: ") + e.what();
//         return result;
//     } catch (const std::exception& e) {
//         result.error_msg = std::string("Error: ") + e.what();
//         return result;
//     }
// }



DatabaseManager::CreateUserResult DatabaseManager::createUser(
    const std::string& login, const std::string& password,
    const std::string& name, const std::string& role,
    const std::string& phone, const std::string& email)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    CreateUserResult result;

    if (!isConnected_) {
        result.error_msg = "Database not connected";
        return result;
    }

    // Валидация входных данных
    if (login.empty() || password.empty() || name.empty() || role.empty()) {
        result.error_msg = "Login, password, name and role are required";
        return result;
    }

    if (role != "admin" && role != "operator" && role != "executor") {
        result.error_msg = "Invalid role. Must be: admin, operator, executor";
        return result;
    }

    // НОВАЯ ПРОВЕРКА: Валидация сложности пароля
    std::string complexity_error;
    bool is_valid = PasswordHasher::validatePasswordComplexity(password, complexity_error);
    std::cout << "[DEBUG createUser] Password validation for user '" << login
              << "': password='" << password
              << "', valid=" << (is_valid ? "true" : "false")
              << ", error='" << complexity_error << "'" << std::endl;

    if (!is_valid) {
        result.error_msg = complexity_error;
        result.success = false;  // ДОБАВИТЬ ЭТУ СТРОЧКУ
        return result;
    }

    // ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА: Пароль не должен содержать логин
    std::string lower_password = password;
    std::string lower_login = login;

    // Приводим к нижнему регистру для сравнения
    for (char& c : lower_password) c = std::tolower(c);
    for (char& c : lower_login) c = std::tolower(c);

    if (lower_password.find(lower_login) != std::string::npos) {
        result.error_msg = "Password should not contain the login";
        return result;
    }

    try {
        // Проверяем, не существует ли уже такой логин
        std::string checkSql = "SELECT COUNT(*) FROM users WHERE login = ?";
        nanodbc::statement checkStmt(*connection_);
        nanodbc::prepare(checkStmt, checkSql);
        checkStmt.bind(0, login.c_str());

        nanodbc::result checkResult = checkStmt.execute();
        if (checkResult.next()) {
            int count = checkResult.get<int>(0);
            if (count > 0) {
                result.error_msg = "Login already exists";
                return result;
            }
        }

        // Генерируем хеш пароля
        std::string passwordHash = PasswordHasher::hashPassword(password);

        // Извлекаем соль из хеша (формат: алгоритм:итерации:соль:хеш)
        size_t pos1 = passwordHash.find(':');
        size_t pos2 = passwordHash.find(':', pos1 + 1);
        size_t pos3 = passwordHash.find(':', pos2 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
            result.error_msg = "Password hash generation failed";
            return result;
        }

        std::string salt = passwordHash.substr(pos2 + 1, pos3 - pos2 - 1);

        // Вставляем пользователя в БД
        std::string insertSql =
            "INSERT INTO users (login, name, role, phone, email, password_hash, salt, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)";

        nanodbc::statement insertStmt(*connection_);
        nanodbc::prepare(insertStmt, insertSql);

        insertStmt.bind(0, login.c_str());
        insertStmt.bind(1, name.c_str());
        insertStmt.bind(2, role.c_str());

        if (phone.empty()) {
            insertStmt.bind_null(3);
        } else {
            insertStmt.bind(3, phone.c_str());
        }

        if (email.empty()) {
            insertStmt.bind_null(4);
        } else {
            insertStmt.bind(4, email.c_str());
        }

        insertStmt.bind(5, passwordHash.c_str());
        insertStmt.bind(6, salt.c_str());

        insertStmt.execute();

        // Получаем ID созданного пользователя
        std::string getIdSql = "SELECT LAST_INSERT_ID()";

        nanodbc::statement idStmt(*connection_);
        nanodbc::prepare(idStmt, getIdSql);
        nanodbc::result idResult = idStmt.execute();

        if (idResult.next()) {
            result.user_id = idResult.get<int>(0);
        }

        result.success = true;
        return result;

    } catch (const nanodbc::database_error& e) {
        result.error_msg = std::string("Database error: ") + e.what();
        return result;
    } catch (const std::exception& e) {
        result.error_msg = std::string("Error: ") + e.what();
        return result;
    }
}



DatabaseManager::UpdateUserResult DatabaseManager::updateUser(
    int user_id, const std::string& name, const std::string& role,
    const std::string& phone, const std::string& email, bool is_active)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    UpdateUserResult result;

    if (!isConnected_) {
        result.error_msg = "Database not connected";
        return result;
    }

    if (user_id <= 0) {
        result.error_msg = "Invalid user ID";
        return result;
    }

    try {
        // Проверяем существование пользователя
        std::string checkSql = "SELECT COUNT(*) FROM users WHERE id = ?";
        nanodbc::statement checkStmt(*connection_);
        nanodbc::prepare(checkStmt, checkSql);
        checkStmt.bind(0, &user_id, 1);

        nanodbc::result checkResult = checkStmt.execute();
        if (checkResult.next()) {
            int count = checkResult.get<int>(0);
            if (count == 0) {
                result.error_msg = "User not found";
                return result;
            }
        }

        // Проверка роли
        if (!role.empty() && role != "admin" && role != "operator" && role != "executor") {
            result.error_msg = "Invalid role. Must be: admin, operator, executor";
            return result;
        }

        // Формируем динамический SQL запрос
        std::vector<std::string> updates;
        std::vector<nanodbc::statement> bindStatements;

        if (!name.empty()) {
            updates.push_back("name = ?");
        }
        if (!role.empty()) {
            updates.push_back("role = ?");
        }
        if (!phone.empty()) {
            updates.push_back("phone = ?");
        }
        if (!email.empty()) {
            updates.push_back("email = ?");
        }
        updates.push_back("is_active = ?");

        if (updates.empty()) {
            result.error_msg = "No fields to update";
            return result;
        }

        std::string sql = "UPDATE users SET ";
        for (size_t i = 0; i < updates.size(); ++i) {
            sql += updates[i];
            if (i < updates.size() - 1) {
                sql += ", ";
            }
        }
        sql += " WHERE id = ?";

        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);

        int bindIndex = 0;
        if (!name.empty()) {
            stmt.bind(bindIndex++, name.c_str());
        }
        if (!role.empty()) {
            stmt.bind(bindIndex++, role.c_str());
        }
        if (!phone.empty()) {
            stmt.bind(bindIndex++, phone.c_str());
        }
        if (!email.empty()) {
            stmt.bind(bindIndex++, email.c_str());
        }

        int active_int = is_active ? 1 : 0;
        stmt.bind(bindIndex++, &active_int, 1);
        stmt.bind(bindIndex++, &user_id, 1);

        nanodbc::execute(stmt);

        result.success = true;
        return result;

    } catch (const nanodbc::database_error& e) {
        result.error_msg = std::string("Database error: ") + e.what();
        return result;
    } catch (const std::exception& e) {
        result.error_msg = std::string("Error: ") + e.what();
        return result;
    }
}


DatabaseManager::DeleteUserResult DatabaseManager::deleteUser(int user_id)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    DeleteUserResult result;

    if (!isConnected_) {
        result.error_msg = "Database not connected";
        return result;
    }

    if (user_id <= 0) {
        result.error_msg = "Invalid user ID";
        return result;
    }

    try {
        // Проверяем существование пользователя
        std::string checkSql = "SELECT COUNT(*) FROM users WHERE id = ?";
        nanodbc::statement checkStmt(*connection_);
        nanodbc::prepare(checkStmt, checkSql);
        checkStmt.bind(0, &user_id, 1);

        nanodbc::result checkResult = checkStmt.execute();
        if (checkResult.next()) {
            int count = checkResult.get<int>(0);
            if (count == 0) {
                result.error_msg = "User not found";
                return result;
            }
        }

        // Деактивируем пользователя (is_active = 0)
        std::string updateSql = "UPDATE users SET is_active = 0 WHERE id = ?";
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, updateSql);
        stmt.bind(0, &user_id, 1);

        stmt.execute();

        // Удаляем все активные токены пользователя
        std::string deleteTokensSql = "DELETE FROM tokens WHERE user_id = ?";
        nanodbc::statement tokenStmt(*connection_);
        nanodbc::prepare(tokenStmt, deleteTokensSql);
        tokenStmt.bind(0, &user_id, 1);
        tokenStmt.execute();

        result.success = true;
        return result;

    } catch (const nanodbc::database_error& e) {
        result.error_msg = std::string("Database error: ") + e.what();
        return result;
    } catch (const std::exception& e) {
        result.error_msg = std::string("Error: ") + e.what();
        return result;
    }
}

// DatabaseManager::ChangePasswordResult DatabaseManager::changePassword(
//     int user_id, const std::string& old_password, const std::string& new_password)
// {
//     std::lock_guard<std::mutex> lock(authMutex_);
//     ChangePasswordResult result;

//     if (!isConnected_) {
//         result.error_msg = "Database not connected";
//         return result;
//     }

//     if (user_id <= 0 || old_password.empty() || new_password.empty()) {
//         result.error_msg = "Invalid parameters";
//         return result;
//     }

//     // Проверка сложности нового пароля (минимум 8 символов)
//     if (new_password.length() < 8) {
//         result.error_msg = "New password must be at least 8 characters long";
//         return result;
//     }

//     try {
//         // Получаем текущий хеш пароля
//         std::string sql = "SELECT password_hash FROM users WHERE id = ? AND is_active = 1";
//         nanodbc::statement stmt(*connection_);
//         nanodbc::prepare(stmt, sql);
//         stmt.bind(0, &user_id, 1);

//         nanodbc::result results = stmt.execute();

//         if (!results.next()) {
//             result.error_msg = "User not found or inactive";
//             return result;
//         }

//         std::string current_hash;
//         if (!results.is_null(0)) {
//             current_hash = results.get<std::string>(0);
//         }

//         if (current_hash.empty()) {
//             result.error_msg = "Password hash not found";
//             return result;
//         }

//         // Проверяем старый пароль
//         if (!PasswordHasher::verifyPassword(old_password, current_hash)) {
//             result.error_msg = "Current password is incorrect";
//             return result;
//         }

//         // Старый и новый пароль не должны совпадать
//         if (old_password == new_password) {
//             result.error_msg = "New password must be different from current password";
//             return result;
//         }

//         // Генерируем новый хеш
//         std::string new_hash = PasswordHasher::hashPassword(new_password);

//         // Извлекаем соль из нового хеша
//         size_t pos1 = new_hash.find(':');
//         size_t pos2 = new_hash.find(':', pos1 + 1);
//         size_t pos3 = new_hash.find(':', pos2 + 1);

//         if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
//             result.error_msg = "Password hash generation failed";
//             return result;
//         }

//         std::string new_salt = new_hash.substr(pos2 + 1, pos3 - pos2 - 1);

//         // Обновляем пароль в БД
//         std::string updateSql = "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?";
//         nanodbc::statement updateStmt(*connection_);
//         nanodbc::prepare(updateStmt, updateSql);

//         updateStmt.bind(0, new_hash.c_str());
//         updateStmt.bind(1, new_salt.c_str());
//         updateStmt.bind(2, &user_id, 1);

//         updateStmt.execute();

//         // Удаляем все активные токены пользователя (принудительный выход со всех устройств)
//         std::string deleteTokensSql = "DELETE FROM tokens WHERE user_id = ?";
//         nanodbc::statement tokenStmt(*connection_);
//         nanodbc::prepare(tokenStmt, deleteTokensSql);
//         tokenStmt.bind(0, &user_id, 1);
//         tokenStmt.execute();

//         result.success = true;
//         return result;

//     } catch (const nanodbc::database_error& e) {
//         result.error_msg = std::string("Database error: ") + e.what();
//         return result;
//     } catch (const std::exception& e) {
//         result.error_msg = std::string("Error: ") + e.what();
//         return result;
//     }
// }



DatabaseManager::ChangePasswordResult DatabaseManager::changePassword(
    int user_id, const std::string& old_password, const std::string& new_password)
{
    std::lock_guard<std::mutex> lock(authMutex_);
    ChangePasswordResult result;

    if (!isConnected_) {
        result.error_msg = "Database not connected";
        return result;
    }

    if (user_id <= 0 || old_password.empty() || new_password.empty()) {
        result.error_msg = "Invalid parameters";
        return result;
    }

    // НОВАЯ ПРОВЕРКА: Валидация сложности пароля
    std::string complexity_error;
    if (!PasswordHasher::validatePasswordComplexity(new_password, complexity_error)) {
        result.error_msg = complexity_error;
        return result;
    }

    // Старый и новый пароль не должны совпадать
    if (old_password == new_password) {
        result.error_msg = "New password must be different from current password";
        return result;
    }

    try {
        // Получаем текущий хеш пароля
        std::string sql = "SELECT password_hash, login FROM users WHERE id = ? AND is_active = 1";
        nanodbc::statement stmt(*connection_);
        nanodbc::prepare(stmt, sql);
        stmt.bind(0, &user_id, 1);

        nanodbc::result results = stmt.execute();

        if (!results.next()) {
            result.error_msg = "User not found or inactive";
            return result;
        }

        std::string current_hash;
        std::string user_login;

        if (!results.is_null(0)) {
            current_hash = results.get<std::string>(0);
        }
        if (!results.is_null(1)) {
            user_login = results.get<std::string>(1);
        }

        if (current_hash.empty()) {
            result.error_msg = "Password hash not found";
            return result;
        }

        // Проверяем старый пароль
        if (!PasswordHasher::verifyPassword(old_password, current_hash)) {
            result.error_msg = "Current password is incorrect";
            return result;
        }

        // ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА: Не допускать пароли, содержащие логин
        if (!user_login.empty()) {
            // Простая проверка: пароль не должен содержать логин
            std::string lower_password = new_password;
            std::string lower_login = user_login;

            // Приводим к нижнему регистру для сравнения
            for (char& c : lower_password) c = std::tolower(c);
            for (char& c : lower_login) c = std::tolower(c);

            if (lower_password.find(lower_login) != std::string::npos) {
                result.error_msg = "Password should not contain your login";
                return result;
            }
        }

        // Генерируем новый хеш
        std::string new_hash = PasswordHasher::hashPassword(new_password);

        // Извлекаем соль из нового хеша
        size_t pos1 = new_hash.find(':');
        size_t pos2 = new_hash.find(':', pos1 + 1);
        size_t pos3 = new_hash.find(':', pos2 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
            result.error_msg = "Password hash generation failed";
            return result;
        }

        std::string new_salt = new_hash.substr(pos2 + 1, pos3 - pos2 - 1);

        // Обновляем пароль в БД
        std::string updateSql = "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?";
        nanodbc::statement updateStmt(*connection_);
        nanodbc::prepare(updateStmt, updateSql);

        updateStmt.bind(0, new_hash.c_str());
        updateStmt.bind(1, new_salt.c_str());
        updateStmt.bind(2, &user_id, 1);

        updateStmt.execute();

        // Удаляем все активные токены пользователя (принудительный выход со всех устройств)
        std::string deleteTokensSql = "DELETE FROM tokens WHERE user_id = ?";
        nanodbc::statement tokenStmt(*connection_);
        nanodbc::prepare(tokenStmt, deleteTokensSql);
        tokenStmt.bind(0, &user_id, 1);
        tokenStmt.execute();

        result.success = true;
        return result;

    } catch (const nanodbc::database_error& e) {
        result.error_msg = std::string("Database error: ") + e.what();
        return result;
    } catch (const std::exception& e) {
        result.error_msg = std::string("Error: ") + e.what();
        return result;
    }
}











DatabaseManager::RefreshTokenResult DatabaseManager::refreshAuthToken(const std::string& old_token)
{
    std::lock_guard<std::mutex> lock(tokenMutex_);
    RefreshTokenResult result;

    // Проверка входных параметров
    if (old_token.empty()) {
        result.error_msg = "Token cannot be empty";
        return result;
    }

    if (!isConnected_) {
        result.error_msg = "Database not connected";
        return result;
    }

    try {
        // 1. Проверяем существование и валидность старого токена
        std::string checkSql =
            "SELECT t.user_id, u.login, u.name, u.role, t.expires_at, t.is_suspicious, "
            "t.initial_ip, t.user_agent "
            "FROM tokens t "
            "JOIN users u ON t.user_id = u.id "
            "WHERE t.token = ? "
            "AND u.is_active = 1";

        nanodbc::statement checkStmt(*connection_);
        nanodbc::prepare(checkStmt, checkSql);
        checkStmt.bind(0, old_token.c_str());

        nanodbc::result checkResult = checkStmt.execute();

        // Токен не найден или пользователь неактивен
        if (!checkResult.next()) {
            result.error_msg = "Token not found or user inactive";
            return result;
        }

        // Извлекаем данные
        int user_id = -1;
        std::string login, name, role, expires_at_str, initial_ip, user_agent;
        int is_suspicious_int = 0;

        if (!checkResult.is_null(0)) user_id = checkResult.get<int>(0);
        if (!checkResult.is_null(1)) login = checkResult.get<std::string>(1);
        if (!checkResult.is_null(2)) name = checkResult.get<std::string>(2);
        if (!checkResult.is_null(3)) role = checkResult.get<std::string>(3);
        if (!checkResult.is_null(4)) expires_at_str = checkResult.get<std::string>(4);
        if (!checkResult.is_null(5)) is_suspicious_int = checkResult.get<int>(5);
        if (!checkResult.is_null(6)) initial_ip = checkResult.get<std::string>(6);
        if (!checkResult.is_null(7)) user_agent = checkResult.get<std::string>(7);

        // Проверка подозрительности
        if (is_suspicious_int == 1) {
            result.error_msg = "Token marked as suspicious, cannot refresh";
            return result;
        }

        // Проверяем, что токен истекает в течение часа
        // В MySQL: TIMESTAMPDIFF(MINUTE, NOW(), expires_at) <= 60
        // Упрощенная проверка - считаем что все активные токены можно обновлять

        // 2. Генерируем новый токен
        std::string new_token = generateSecureToken(32);

        // Вычисляем новое время истечения (+24 часа)
        auto now = std::chrono::system_clock::now();
        auto expires_time = now + std::chrono::hours(24);
        std::time_t expires_time_t = std::chrono::system_clock::to_time_t(expires_time);
        std::tm expires_tm = *std::gmtime(&expires_time_t);

        char expires_str[20];
        std::strftime(expires_str, sizeof(expires_str),
                      "%Y-%m-%d %H:%M:%S", &expires_tm);

        // 3. Создаем новый токен в БД
        std::string insertSql =
            "INSERT INTO tokens (token, user_id, expires_at, initial_ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?)";

        nanodbc::statement insertStmt(*connection_);
        nanodbc::prepare(insertStmt, insertSql);

        insertStmt.bind(0, new_token.c_str());
        insertStmt.bind(1, &user_id, 1);
        insertStmt.bind(2, expires_str);
        insertStmt.bind(3, initial_ip.empty() ? nullptr : initial_ip.c_str());
        insertStmt.bind(4, user_agent.empty() ? nullptr : user_agent.c_str());

        insertStmt.execute();

        // 4. Удаляем старый токен
        std::string deleteSql = "DELETE FROM tokens WHERE token = ?";
        nanodbc::statement deleteStmt(*connection_);
        nanodbc::prepare(deleteStmt, deleteSql);
        deleteStmt.bind(0, old_token.c_str());
        deleteStmt.execute();

        // 5. Заполняем результат
        result.new_token = new_token;
        result.user_id = user_id;
        result.login = login;
        result.name = name;
        result.role = role;
        result.success = true;

        std::cout << "[INFO] Token refreshed for user: " << login
                  << " (user_id: " << user_id << ")" << std::endl;

        return result;

    } catch (const nanodbc::database_error& e) {
        result.error_msg = std::string("Database error: ") + e.what();
        std::cerr << "[ERROR] refreshAuthToken DB error: " << e.what() << std::endl;
        return result;
    } catch (const std::exception& e) {
        result.error_msg = std::string("Error: ") + e.what();
        std::cerr << "[ERROR] refreshAuthToken error: " << e.what() << std::endl;
        return result;
    } catch (...) {
        result.error_msg = "Unknown error refreshing token";
        std::cerr << "[ERROR] refreshAuthToken unknown error" << std::endl;
        return result;
    }
}


