#include "servercore.h"
#include "civetweb.h"
#include <chrono>
#include <ctime>
#include <unordered_map>
#include <mutex>

// В начале servercore.cpp
#include <fstream>      // для std::ifstream
#include <string>       // для std::string
#include <chrono>       // для std::chrono
#include <ctime>        // для std::time_t, std::tm
// #include <sstream>      // для std::stringstream
// #include <iomanip>      // для std::setw, std::setfill


#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <linux/limits.h>
#endif



/**
 * @class RateLimiter
 * @brief Ограничитель частоты запросов для защиты от брутфорса
 *
 * Хранит счётчики попыток входа по IP-адресам.
 * Правила:
 * - Макс 5 попыток в минуту с одного IP
 * - После 10 неудачных попыток - блокировка на 15 минут
 * - Успешный сброс счётчика при успешном входе
 */
class RateLimiter {
private:
    struct AttemptInfo {
        int failed_attempts;      // Количество неудачных попыток
        int total_attempts;       // Общее количество попыток (для минуты)
        std::chrono::steady_clock::time_point window_start; // Начало минутного окна
        std::chrono::steady_clock::time_point blocked_until; // Блокировка до
    };

    std::unordered_map<std::string, AttemptInfo> attempts_;
    std::mutex mutex_;

    // Константы (можно вынести в настройки)
    static const int MAX_ATTEMPTS_PER_MINUTE = 5;
    static const int MAX_FAILED_ATTEMPTS = 10;
    static const int BLOCK_MINUTES = 15;

public:
    /**
     * @brief Проверяет, разрешён ли запрос с данного IP
     * @param ip_address IP-адрес клиента
     * @param is_successful true если попытка успешная (сбрасывает счётчики)
     * @return std::pair<bool, std::string>
     *         first: true если доступ разрешён
     *         second: сообщение об ошибке если доступ запрещён
     */
    std::pair<bool, std::string> checkRequest(const std::string& ip_address, bool is_successful = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();

        // Находим или создаём запись для IP
        auto& info = attempts_[ip_address];

        // 1. Проверка блокировки
        if (now < info.blocked_until) {
            auto remaining = std::chrono::duration_cast<std::chrono::minutes>(info.blocked_until - now).count();
            return {false, "Too many failed attempts. Blocked for " + std::to_string(remaining) + " more minutes"};
        }

        // 2. Сброс блокировки если истекла
        if (info.blocked_until != std::chrono::steady_clock::time_point{} && now >= info.blocked_until) {
            info.failed_attempts = 0;
            info.blocked_until = std::chrono::steady_clock::time_point{};
        }

        // 3. Сброс счётчика попыток если минута истекла
        auto minute_ago = now - std::chrono::minutes(1);
        if (info.window_start < minute_ago) {
            info.total_attempts = 0;
            info.window_start = now;
        }

        // 4. Проверка общего количества попыток в минуту
        if (info.total_attempts >= MAX_ATTEMPTS_PER_MINUTE) {
            return {false, "Too many requests. Try again later"};
        }

        // 5. Обработка результата попытки
        if (is_successful) {
            // Успешный вход - сбрасываем всё
            info.failed_attempts = 0;
            info.total_attempts = 0;
            info.blocked_until = std::chrono::steady_clock::time_point{};
            info.window_start = now;
            return {true, ""};
        } else {
            // Неудачная попытка
            info.total_attempts++;
            info.failed_attempts++;

            // 6. Проверка на блокировку по неудачным попыткам
            if (info.failed_attempts >= MAX_FAILED_ATTEMPTS) {
                info.blocked_until = now + std::chrono::minutes(BLOCK_MINUTES);
                return {false, "Account temporarily locked due to too many failed attempts"};
            }

            return {true, ""};
        }
    }

    /**
     * @brief Очистка старых записей (вызывать периодически)
     * @param max_age_minutes Максимальный возраст записи в минутах
     */
    void cleanupOldEntries(int max_age_minutes = 60) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        auto threshold = now - std::chrono::minutes(max_age_minutes);

        for (auto it = attempts_.begin(); it != attempts_.end(); ) {
            // Удаляем записи, которые не обновлялись больше max_age_minutes минут
            // и не заблокированы
            if (it->second.blocked_until < now &&
                it->second.window_start < threshold) {
                it = attempts_.erase(it);
            } else {
                ++it;
            }
        }
    }
};



static RateLimiter g_rateLimiter;


ServerCore* ServerCore::currentInstance = nullptr;

// Максимальный размер тела запроса (1 МБ)
static const size_t MAX_REQUEST_BODY_SIZE = 1024 * 1024;

ServerCore::ServerCore() : serverContext(nullptr), serverRunning(false), currentPort(0)
{
    // в конструктор:
    currentInstance = this;
}

ServerCore::~ServerCore()
{
    stopServer();
    currentInstance = nullptr;
}


// bool ServerCore::startServer(int https_port)
// {
//     if (serverRunning) {
//         stopServer();
//     }

//     // Валидация порта
//     if (https_port <= 0 || https_port > 65535) {
//         lastError = "Invalid HTTPS port number: " + std::to_string(https_port);
//         return false;
//     }

//     std::string pem_path = "D:\\SERVERS\\Qt projects\\stage_1\\CV_WEB\\src\\ssl_certs\\server.pem";

//     // std::string pem_path = "ssl_certs/server.pem";

//     // Формируем строку порта с 's' для HTTPS (например "8443s")
//     std::string ports_str = std::to_string(https_port) + "s";

//     const char *options[] = {
//         "listening_ports", ports_str.c_str(),
//         "ssl_certificate", pem_path.c_str(),
//         "num_threads", "5",
//         NULL
//     };

//     // Создаем структуру callback-функций
//     struct mg_callbacks callbacks;
//     memset(&callbacks, 0, sizeof(callbacks));
//     callbacks.begin_request = handleRequest;

//     serverContext = mg_start(&callbacks, NULL, options);

//     if (!serverContext) {
//         lastError = "mg_start returned NULL";
//         serverRunning = false;
//         return false;
//     }

//     serverRunning = true;
//     currentPort = https_port;  // Сохраняем реальный порт
//     lastError.clear();

//     // logMessage("HTTPS server started on port " + std::to_string(https_port) + " (HTTPS only)");
//     return true;
// }




bool ServerCore::startServer(int https_port)
{
    if (serverRunning) {
        stopServer();
    }

    // Валидация порта
    if (https_port <= 0 || https_port > 65535) {
        lastError = "Invalid HTTPS port number: " + std::to_string(https_port);
        return false;
    }

    // Путь к SSL сертификату - рядом с исполняемым файлом
    std::string pem_path;

    // 1. Получаем путь к исполняемому файлу
#ifdef _WIN32

    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    std::string exe_dir = exe_path;
    size_t last_slash = exe_dir.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        exe_dir = exe_dir.substr(0, last_slash + 1);
    }
    pem_path = exe_dir + "ssl_certs\\server.pem";

#else

    // Linux/Unix
    char exe_path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", exe_path, PATH_MAX);
    if (count != -1) {
        std::string exe_dir = exe_path;
        size_t last_slash = exe_dir.find_last_of('/');
        if (last_slash != std::string::npos) {
            exe_dir = exe_dir.substr(0, last_slash + 1);
        }
        pem_path = exe_dir + "ssl_certs/server.pem";
    } else {
        // fallback - текущая директория
        pem_path = "ssl_certs/server.pem";

    }
#endif

    // 2. Проверка существования файла сертификата
    std::ifstream cert_file(pem_path);
    if (!cert_file.good()) {
        // Попробовать альтернативный путь (просто в текущей директории)
        pem_path = "server.pem";
        std::ifstream alt_cert_file(pem_path);
        if (!alt_cert_file.good()) {
            lastError = "SSL certificate file not found. Expected at: " + pem_path +
                        " or in executable directory/ssl_certs/";
            return false;
        }
        alt_cert_file.close();
    } else {
        cert_file.close();
    }

    // Формируем строку порта с 's' для HTTPS
    std::string ports_str = std::to_string(https_port) + "s";

    const char *options[] = {
        "listening_ports", ports_str.c_str(),
        "ssl_certificate", pem_path.c_str(),
        "num_threads", "5",
        NULL
    };

    // Создаем структуру callback-функций
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = handleRequest;

    serverContext = mg_start(&callbacks, NULL, options);

    if (!serverContext) {
        lastError = "mg_start failed. SSL certificate: " + pem_path;
        serverRunning = false;
        return false;
    }

    serverRunning = true;
    currentPort = https_port;
    lastError.clear();

    return true;
}

void ServerCore::stopServer()
{
    if (serverContext) {
        mg_stop((mg_context*)serverContext);
        serverContext = nullptr;
    }
    serverRunning = false;    
}

bool ServerCore::isRunning() const
{
    return serverRunning;
}

std::string ServerCore::getLastError() const
{
    return lastError;
}


int ServerCore::getServerPort() const
{
    return currentPort;
}

void ServerCore::setLogCallback(LogCallback callback)
{
    logCallback_ = callback;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


int ServerCore::handleRequest(mg_connection *conn)
{
    const struct mg_request_info* req_info = mg_get_request_info(conn);

    if (!req_info) {
        return 0;
    }

    std::string uri = req_info->request_uri;
    std::string method = req_info->request_method;

    logMessage(method + " " + uri);

    // РАЗРЕШАЕМ ТОЛЬКО POST
    if (method != "POST") {
        mg_send_http_error(conn, 405, "Method Not Allowed. Use POST only.");
        return 1;
    }

    // МАРШРУТИЗАЦИЯ
    if (uri == "/") {
        handlePostRoot(conn);
    }
    else if (uri == "/api/status") {
        handlePostStatus(conn);
    }
    else if (uri == "/api/test") {
        handlePostTest(conn);  // опционально
    }
    else if (uri == "/api/auth/login") {
        handlePostAuthLogin(conn);
    }

    // else if (uri == "/api/auth/validate") {
    //     handlePostAuthValidate(conn);
    // }

    else if (uri == "/api/auth/logout") {
        handlePostAuthLogout(conn);
    }
    else if (uri == "/api/users/list") {
        handlePostUsersList(conn);
    }
    else if (uri == "/api/users/create") {
        handlePostUsersCreate(conn);
    }

    else if (uri == "/api/users/update") {
        handlePostUsersUpdate(conn);
    }

    else if (uri == "/api/users/delete") {
        handlePostUsersDelete(conn);
    }

    else if (uri == "/api/auth/change-password") {
        handlePostAuthChangePassword(conn);
    }

    else if (uri == "/api/auth/refresh") {
        handlePostAuthRefresh(conn);
    }

    else if (uri == "/api/dev/write") {
        handleDeviceDataWrite(conn);
    }

    else if(uri == "/api/dev/read") {
        handleDeviceDataRead(conn);
    }

    else {
        mg_send_http_error(conn, 404, "Not Found");
        logMessage("404 Not Found: " + uri);
    }

    return 1;
}


void ServerCore::handlePostRoot(mg_connection *conn)
{
    // std::string response = "Radiation Monitoring Server\n"
    //                        "HTTP Server is running\n"
    //                        "Use /api/status for server status";
    // sendResponse(conn, response, "text/plain");

    std::string response = "Radiation Monitoring Server\n"
                           "HTTP Server is running\n"
                           "Use POST /api/auth/login for authentication";
    sendResponse(conn, response, "text/plain");
}

void ServerCore::handlePostStatus(mg_connection *conn)
{
    // std::string response = "{\n"
    //                        "  \"status\": \"running\",\n"
    //                        "  \"service\": \"radiation_monitor\",\n"
    //                        "  \"timestamp\": \"" + getCurrentTime() + "\"\n"
    //                                             "}";
    // sendResponse(conn, response, "application/json");

    std::string response = "{\n"
                           "  \"status\": \"running\",\n"
                           "  \"service\": \"radiation_monitor\",\n"
                           "  \"timestamp\": \"" + getCurrentTime() + "\"\n"
                                                "}";
    sendResponse(conn, response, "application/json");
}



void ServerCore::handlePostTest(mg_connection *conn)
{
    // std::string response = "{\n"
    //                        "  \"message\": \"Test successful\",\n"
    //                        "  \"code\": 200\n"
    //                        "}";
    // sendResponse(conn, response, "application/json");

    std::string response = "{\n"
                           "  \"message\": \"Test successful\",\n"
                           "  \"code\": 200\n"
                           "}";
    sendResponse(conn, response, "application/json");
}



// void ServerCore::handlePostAuthLogin(mg_connection* conn)
// {
//     // === ПРОВЕРКА 1: currentInstance ===
//     if (!currentInstance) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Server instance not available";
//         sendJsonResponse(conn, errorResp, 500);
//         return;
//     }

//     // === ПРОВЕРКА 2: База данных подключена ===
//     if (!currentInstance->dbManager.isConnected()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Database not connected";
//         sendJsonResponse(conn, errorResp, 500);
//         return;
//     }

//     // 1. Получить IP и User-Agent
//     const struct mg_request_info* req_info = mg_get_request_info(conn);
//     std::string client_ip = req_info->remote_addr ? req_info->remote_addr : "";
//     std::string user_agent = "";

//     // Если IP пустой - используем заглушку
//     if (client_ip.empty()) {
//         client_ip = "unknown";
//     }

//     // Rate limiting проверка
//     auto rateLimitResult = g_rateLimiter.checkRequest(client_ip, false);
//     if (!rateLimitResult.first) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = rateLimitResult.second;
//         sendJsonResponse(conn, errorResp, 429); // 429 Too Many Requests
//         logMessage("Rate limit exceeded for IP: " + client_ip);
//         return;
//     }

//     // Получить User-Agent из заголовков
//     for (int i = 0; i < req_info->num_headers; i++) {
//         if (strcmp(req_info->http_headers[i].name, "User-Agent") == 0) {
//             user_agent = req_info->http_headers[i].value;
//             break;
//         }
//     }

//     // 2. Читаем тело запроса
//     std::string requestBody = readRequestBody(conn);
//     if (requestBody.empty()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Empty request body";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 3. Парсим JSON
//     Json::Value jsonRequest;
//     std::string parseError;
//     if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = parseError;
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 4. Проверяем поля
//     if (!jsonRequest.isMember("login") || !jsonRequest.isMember("password")) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Missing login or password field";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     std::string login = jsonRequest["login"].asString();
//     std::string password = jsonRequest["password"].asString();

//     // 5. Аутентификация через DatabaseManager
//     AuthResult authResult = currentInstance->dbManager.authenticateUser(login, password);

//     if (!authResult.success) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = authResult.error_msg;
//         sendJsonResponse(conn, errorResp, 401);
//         logMessage("Failed login attempt for user: " + login);
//         return;
//     }

//     // Успешный вход - отмечаем в rate limiter
//     g_rateLimiter.checkRequest(client_ip, true);

//     // 6. Создание токена
//     std::string token = currentInstance->dbManager.createAuthToken(
//         authResult.user_id,
//         client_ip,
//         user_agent
//         );

//     if (token.empty()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Failed to create authentication token";
//         sendJsonResponse(conn, errorResp, 500);
//         return;
//     }

//     // 7. Успешный ответ
//     Json::Value successResp;
//     successResp["status"] = "success";
//     successResp["message"] = "Authentication successful";

//     Json::Value data;
//     data["token"] = token;
//     data["user_id"] = authResult.user_id;
//     data["name"] = escapeHtmlForJson(authResult.name);
//     data["role"] = authResult.role;

//     successResp["data"] = data;

//     sendJsonResponse(conn, successResp, 200);
//     logMessage("Successful login for user: " + login + " (role: " + authResult.role + ")");
// }


void ServerCore::handlePostAuthLogin(mg_connection* conn)
{
    // === ПРОВЕРКА 1: currentInstance ===
    if (!currentInstance) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Server instance not available";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // === ПРОВЕРКА 2: База данных подключена ===
    if (!currentInstance->dbManager.isConnected()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Database not connected";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // 1. Получить IP и User-Agent
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    std::string client_ip = req_info->remote_addr ? req_info->remote_addr : "";
    std::string user_agent = "";

    // Если IP пустой - используем заглушку
    if (client_ip.empty()) {
        client_ip = "unknown";
    }

    // Rate limiting проверка
    auto rateLimitResult = g_rateLimiter.checkRequest(client_ip, false);
    if (!rateLimitResult.first) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = rateLimitResult.second;
        sendJsonResponse(conn, errorResp, 429); // 429 Too Many Requests
        logMessage("Rate limit exceeded for IP: " + client_ip);
        return;
    }

    // Получить User-Agent из заголовков
    for (int i = 0; i < req_info->num_headers; i++) {
        if (strcmp(req_info->http_headers[i].name, "User-Agent") == 0) {
            user_agent = req_info->http_headers[i].value;
            break;
        }
    }

    // 2. Читаем тело запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсим JSON
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Проверяем поля
    if (!jsonRequest.isMember("login") || !jsonRequest.isMember("password")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing login or password field";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    std::string login = jsonRequest["login"].asString();
    std::string password = jsonRequest["password"].asString();

    // 5. Аутентификация через DatabaseManager
    AuthResult authResult = currentInstance->dbManager.authenticateUser(login, password);

    if (!authResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = authResult.error_msg;
        sendJsonResponse(conn, errorResp, 401);
        logMessage("Failed login attempt for user: " + login);
        return;
    }

    // Успешный вход - отмечаем в rate limiter
    g_rateLimiter.checkRequest(client_ip, true);

    // 6. Создание токена
    std::string token = currentInstance->dbManager.createAuthToken(
        authResult.user_id,
        client_ip,
        user_agent
        );

    if (token.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Failed to create authentication token";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // 7. Успешный ответ (БЕЗ user_id)
    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "Authentication successful";

    Json::Value data;
    data["token"] = token;
    // user_id убран из ответа - внутренний идентификатор БД не раскрывается клиенту
    data["name"] = escapeHtmlForJson(authResult.name);
    data["role"] = authResult.role;

    successResp["data"] = data;

    sendJsonResponse(conn, successResp, 200);
    logMessage("Successful login for user: " + login + " (role: " + authResult.role + ")");
}



// void ServerCore::handlePostAuthValidate(mg_connection* conn)
// {
//     // 1. Проверка currentInstance
//     if (!currentInstance) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Server instance not available";
//         sendJsonResponse(conn, errorResp, 500);
//         return;
//     }

//     // 2. Проверка подключения к БД
//     if (!currentInstance->dbManager.isConnected()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Database not connected";
//         sendJsonResponse(conn, errorResp, 500);
//         return;
//     }

//     // 3. Чтение тела запроса
//     std::string requestBody = readRequestBody(conn);
//     if (requestBody.empty()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Empty request body";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 4. Парсинг JSON
//     Json::Value jsonRequest;
//     std::string parseError;
//     if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = parseError;
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 5. Проверка поля token
//     if (!jsonRequest.isMember("token")) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Missing token field";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     std::string token = jsonRequest["token"].asString();


//     // 6. Валидация токена
//     TokenValidationResult validationResult = currentInstance->dbManager.validateToken(token, "", "");

//     // 7. Формирование ответа
//     if (!validationResult.valid) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = validationResult.error_msg;
//         sendJsonResponse(conn, errorResp, 401);
//         return;
//     }

//     // 8. Успешный ответ
//     Json::Value successResp;
//     successResp["status"] = "success";
//     successResp["message"] = "Token is valid";

//     Json::Value data;
//     data["user_id"] = validationResult.user_id;
//     data["login"] = validationResult.login;
//     data["name"] = escapeHtmlForJson(validationResult.name);
//     data["role"] = validationResult.role;

//     successResp["data"] = data;
//     sendJsonResponse(conn, successResp, 200);
// }






void ServerCore::sendResponse(mg_connection *conn, const std::string &content, const std::string &contentType)
{
    // mg_printf(conn, "HTTP/1.1 200 OK\r\n"
    //                 "Content-Type: %s\r\n"
    //                 "Content-Length: %zu\r\n"
    //                 "Connection: close\r\n\r\n",
    //           contentType.c_str(), content.length());

    // mg_write(conn, content.c_str(), content.length());

    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %zu\r\n"
              "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
              "X-Content-Type-Options: nosniff\r\n"
              "X-Frame-Options: DENY\r\n"
              "X-XSS-Protection: 1; mode=block\r\n"
              "Connection: close\r\n\r\n",
              contentType.c_str(),
              content.length());

    mg_write(conn, content.c_str(), content.length());
}

std::string ServerCore::getCurrentTime()
{
    std::time_t now = std::time(nullptr);
    std::string time_str = std::ctime(&now);
    if (!time_str.empty() && time_str.back() == '\n') {
        time_str.pop_back();
    }
    return time_str;
}

void ServerCore::logMessage(const std::string &message)
{
    // if (logCallback_) logCallback_(message);

    if (currentInstance && currentInstance->logCallback_) {
        currentInstance->logCallback_(message);
    }
}


std::string ServerCore::readRequestBody(mg_connection* conn)
{
    // Получаем информацию о запросе
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    if (!req_info) {
        return "";
    }

    // Получаем длину контента из заголовка Content-Length
    long content_length = 0;
    if (req_info->content_length > 0) {
        content_length = req_info->content_length;
    }

    // Проверяем максимальный размер
    if (content_length <= 0) {
        // Нет тела запроса или нулевая длина
        return "";
    }

    if (content_length > MAX_REQUEST_BODY_SIZE) {
        // logMessage("Request body too large: " + std::to_string(content_length) + " bytes");
        return "";
    }

    // Выделяем буфер для чтения
    std::vector<char> buffer(content_length + 1); // +1 для нуль-терминатора
    size_t total_read = 0;

    // Читаем данные порциями
    while (total_read < static_cast<size_t>(content_length)) {
        int bytes_read = mg_read(conn, &buffer[total_read], content_length - total_read);

        if (bytes_read <= 0) {
            // Ошибка чтения или соединение закрыто
            // logMessage("Error reading request body, read " + std::to_string(total_read) + " of " +
            // std::to_string(content_length) + " bytes");
            return "";
        }

        total_read += bytes_read;
    }

    // Добавляем нуль-терминатор для безопасности
    buffer[total_read] = '\0';

    // Возвращаем как строку
    return std::string(buffer.data(), total_read);
}



bool ServerCore::parseJsonRequest(const std::string& jsonStr, Json::Value& jsonValue, std::string& errorMsg)
{
    if (jsonStr.empty()) {
        errorMsg = "Empty JSON request";
        return false;
    }

    Json::CharReaderBuilder readerBuilder;
    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());

    // Парсим JSON
    bool parsingSuccessful = reader->parse(
        jsonStr.c_str(),
        jsonStr.c_str() + jsonStr.length(),
        &jsonValue,
        &errorMsg
        );

    if (!parsingSuccessful) {
        errorMsg = "JSON parse error: " + errorMsg;
        return false;
    }

    return true;
}


// void ServerCore::sendJsonResponse(mg_connection* conn, const Json::Value& jsonData, int statusCode)
// {
//     // Преобразуем JSON в строку
//     Json::StreamWriterBuilder writerBuilder;
//     writerBuilder["indentation"] = ""; // Без форматирования для экономии трафика
//     std::string jsonResponse = Json::writeString(writerBuilder, jsonData);

//     // Формируем статусную строку HTTP
//     const char* statusText = "OK";
//     if (statusCode == 400) statusText = "Bad Request";
//     else if (statusCode == 401) statusText = "Unauthorized";
//     else if (statusCode == 403) statusText = "Forbidden";
//     else if (statusCode == 404) statusText = "Not Found";
//     else if (statusCode == 500) statusText = "Internal Server Error";

//     // Отправляем HTTP заголовки
//     mg_printf(conn,
//               "HTTP/1.1 %d %s\r\n"
//               "Content-Type: application/json\r\n"
//               "Content-Length: %zu\r\n"
//               "Connection: close\r\n"
//               "\r\n",
//               statusCode, statusText,
//               jsonResponse.length());

//     // Отправляем тело ответа
//     mg_write(conn, jsonResponse.c_str(), jsonResponse.length());
// }


// void ServerCore::sendJsonResponse(mg_connection* conn, const Json::Value& jsonData, int statusCode)
// {
//     // Преобразуем JSON в строку
//     Json::StreamWriterBuilder writerBuilder;
//     writerBuilder["indentation"] = ""; // Без форматирования для экономии трафика
//     std::string jsonResponse = Json::writeString(writerBuilder, jsonData);

//     // Формируем статусную строку HTTP
//     const char* statusText = "OK";
//     if (statusCode == 400) statusText = "Bad Request";
//     else if (statusCode == 401) statusText = "Unauthorized";
//     else if (statusCode == 403) statusText = "Forbidden";
//     else if (statusCode == 404) statusText = "Not Found";
//     else if (statusCode == 500) statusText = "Internal Server Error";

//     // Отправляем HTTP заголовки с HSTS
//     mg_printf(conn,
//               "HTTP/1.1 %d %s\r\n"
//               "Content-Type: application/json\r\n"
//               "Content-Length: %zu\r\n"
//               "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" // HSTS заголовок
//               "Connection: close\r\n"
//               "\r\n",
//               statusCode, statusText,
//               jsonResponse.length());

//     // Отправляем тело ответа
//     mg_write(conn, jsonResponse.c_str(), jsonResponse.length());
// }

void ServerCore::sendJsonResponse(mg_connection* conn, const Json::Value& jsonData, int statusCode)
{
    // Преобразуем JSON в строку
    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";
    std::string jsonResponse = Json::writeString(writerBuilder, jsonData);

    const char* statusText = "OK";
    if (statusCode == 400) statusText = "Bad Request";
    else if (statusCode == 401) statusText = "Unauthorized";
    else if (statusCode == 403) statusText = "Forbidden";
    else if (statusCode == 404) statusText = "Not Found";
    else if (statusCode == 500) statusText = "Internal Server Error";

    // Отправляем HTTP заголовки с security-заголовками
    mg_printf(conn,
              "HTTP/1.1 %d %s\r\n"
              "Content-Type: application/json\r\n"
              "Content-Length: %zu\r\n"
              "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
              "X-Content-Type-Options: nosniff\r\n"
              "X-Frame-Options: DENY\r\n"
              "X-XSS-Protection: 1; mode=block\r\n"
              "Connection: close\r\n"
              "\r\n",
              statusCode, statusText,
              jsonResponse.length());

    mg_write(conn, jsonResponse.c_str(), jsonResponse.length());
}



/**
 * @brief Middleware для аутентификации запроса
 *
 * Извлекает токен из запроса, проверяет его валидность,
 * заполняет tokenData информацией о пользователе.
 *
 * @param conn HTTP соединение
 * @param tokenData[out] Результат проверки токена
 * @return true если токен валиден, false если нет (уже отправили ошибку)
 */
bool ServerCore::authenticateRequest(mg_connection* conn,
                                     TokenValidationResult& tokenData,
                                     const std::string& requiredRole)
{
    // 1. Проверяем доступность экземпляра сервера
    if (!currentInstance) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Server instance not available";
        sendJsonResponse(conn, errorResp, 500);
        return false;
    }

    // 2. Проверяем подключение к БД
    if (!currentInstance->dbManager.isConnected()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Database not connected";
        sendJsonResponse(conn, errorResp, 500);
        return false;
    }

    // 3. Извлекаем токен из заголовка Authorization
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    std::string authHeader = "";

    // Ищем заголовок Authorization
    for (int i = 0; i < req_info->num_headers; i++) {
        if (strcmp(req_info->http_headers[i].name, "Authorization") == 0) {
            authHeader = req_info->http_headers[i].value;
            break;
        }
    }

    // 4. Проверяем формат: "Bearer <token>"
    if (authHeader.empty() ||
        authHeader.find("Bearer ") != 0) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Authorization header missing or invalid";
        sendJsonResponse(conn, errorResp, 401);
        return false;
    }

    // 5. Извлекаем токен (убираем "Bearer ")
    std::string token = authHeader.substr(7); // "Bearer ".length() = 7



    // 6. Валидируем токен через DatabaseManager с текущим IP
    // Получаем IP клиента из запроса
    std::string client_ip = req_info->remote_addr ? req_info->remote_addr : "";
    if (client_ip.empty()) {
        client_ip = "unknown";
    }

    // Получаем User-Agent
    std::string user_agent = "";
    for (int i = 0; i < req_info->num_headers; i++) {
        if (strcmp(req_info->http_headers[i].name, "User-Agent") == 0) {
            user_agent = req_info->http_headers[i].value;
            break;
        }
    }

    tokenData = currentInstance->dbManager.validateToken(token, client_ip, user_agent);

    if (!tokenData.valid) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = tokenData.error_msg;

        // Если это подозрительная активность, логируем детали
        if (tokenData.is_suspicious || tokenData.ip_changed) {
            logMessage("SUSPICIOUS ACTIVITY DETECTED: " + tokenData.error_msg +
                       " User: " + tokenData.login + " IP: " + client_ip);
        }

        sendJsonResponse(conn, errorResp, 401);
        return false;
    }

    // 7. Токен валиден, возвращаем данные пользователя

    // Проверка прав доступа
    if (!checkPermissions(tokenData, requiredRole)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Insufficient permissions. Required role: " + requiredRole;
        sendJsonResponse(conn, errorResp, 403); // 403 Forbidden
        return false;
    }

    return true;
}

/**
 * @brief Проверка прав доступа по роли пользователя
 *
 * @param tokenData Данные пользователя из токена
 * @param requiredRole Требуемая роль ("admin", "operator", "executor")
 * @return true если доступ разрешён, false если нет
 */
bool ServerCore::checkPermissions(const TokenValidationResult& tokenData,
                                  const std::string& requiredRole)
{

    // 1. "any" эндпоинты доступны всем ролям
    if (requiredRole == "any") {
        return true;
    }

    // 2. ADMIN: доступ ко всему (кроме "any" уже обработано)
    if (tokenData.role == "admin") {
        return true;
    }

    // 3. OPERATOR: доступ только к "operator" эндпоинтам
    if (tokenData.role == "operator") {
        return requiredRole == "operator";
    }

    // 4. EXECUTOR: доступ только к "executor" эндпоинтам
    if (tokenData.role == "executor") {
        return requiredRole == "executor";
    }

    return false;
}



// void ServerCore::handlePostAuthLogout(mg_connection* conn)
// {
//     // 1. Аутентификация через middleware
//     TokenValidationResult userData;
//     if (!authenticateRequest(conn, userData)) {
//         return; // Ошибка уже отправлена
//     }

//     // 2. Получить токен из заголовка Authorization
//     const struct mg_request_info* req_info = mg_get_request_info(conn);
//     std::string token = "";

//     for (int i = 0; i < req_info->num_headers; i++) {
//         if (strcmp(req_info->http_headers[i].name, "Authorization") == 0) {
//             std::string authHeader = req_info->http_headers[i].value;
//             if (authHeader.find("Bearer ") == 0) {
//                 token = authHeader.substr(7);
//             }
//             break;
//         }
//     }

//     // 3. Инвалидировать токен
//     bool success = currentInstance->dbManager.invalidateToken(token);

//     // 4. Формирование ответа
//     Json::Value response;

//     if (success) {
//         response["status"] = "success";
//         response["message"] = "Successfully logged out";
//         logMessage("User logged out: " + userData.login);
//     } else {
//         response["status"] = "error";
//         response["message"] = "Failed to invalidate token";
//     }

//     sendJsonResponse(conn, response, success ? 200 : 500);
// }



void ServerCore::handlePostAuthLogout(mg_connection* conn)
{
    // 1. Аутентификация через middleware
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData)) {
        return; // Ошибка уже отправлена
    }

    // 2. Получить токен из заголовка Authorization (тело запроса не читаем)
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    std::string token = "";

    for (int i = 0; i < req_info->num_headers; i++) {
        if (strcmp(req_info->http_headers[i].name, "Authorization") == 0) {
            std::string authHeader = req_info->http_headers[i].value;
            if (authHeader.find("Bearer ") == 0) {
                token = authHeader.substr(7);
            }
            break;
        }
    }

    // 3. Инвалидировать токен
    bool success = currentInstance->dbManager.invalidateToken(token);

    // 4. Формирование ответа
    Json::Value response;

    if (success) {
        response["status"] = "success";
        response["message"] = "Successfully logged out";
        logMessage("User logged out: " + userData.login);
    } else {
        response["status"] = "error";
        response["message"] = "Failed to invalidate token";
    }

    sendJsonResponse(conn, response, success ? 200 : 500);
}





// void ServerCore::handlePostUsersList(mg_connection* conn)
// {
//     // 1. Аутентификация и проверка прав (только admin)
//     TokenValidationResult userData;
//     if (!authenticateRequest(conn, userData, "admin")) {
//         return; // Ошибка уже отправлена
//     }

//     // 2. Получение списка пользователей
//     std::vector<DatabaseManager::UserInfo> users = currentInstance->dbManager.getUsersList();

//     // 3. Формирование JSON ответа
//     Json::Value response;
//     response["status"] = "success";
//     response["message"] = "Users list retrieved successfully";

//     Json::Value usersArray(Json::arrayValue);
//     for (const auto& user : users) {
//         Json::Value userJson;
//         userJson["id"] = user.id;
//         userJson["login"] = user.login;
//         userJson["name"] = escapeHtmlForJson(user.name);      // <-- ЭКРАНИРОВАНО
//         userJson["role"] = user.role;
//         userJson["phone"] = escapeHtmlForJson(user.phone);    // <-- ЭКРАНИРОВАНО
//         userJson["email"] = escapeHtmlForJson(user.email);    // <-- ЭКРАНИРОВАНО
//         userJson["is_active"] = user.is_active;
//         userJson["created_at"] = user.created_at;

//         usersArray.append(userJson);
//     }

//     response["data"]["users"] = usersArray;
//     response["data"]["count"] = static_cast<int>(users.size());

//     sendJsonResponse(conn, response, 200);
//     logMessage("Users list accessed by admin: " + userData.login);
// }


void ServerCore::handlePostUsersList(mg_connection* conn)
{
    // 1. Аутентификация и проверка прав (только admin)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "admin")) {
        return; // Ошибка уже отправлена
    }

    // 2. Получение списка пользователей (тело запроса не читаем)
    std::vector<DatabaseManager::UserInfo> users = currentInstance->dbManager.getUsersList();

    // 3. Формирование JSON ответа
    Json::Value response;
    response["status"] = "success";
    response["message"] = "Users list retrieved successfully";

    Json::Value usersArray(Json::arrayValue);
    for (const auto& user : users) {
        Json::Value userJson;
        userJson["id"] = user.id;                    // ID только для админа
        userJson["login"] = user.login;
        userJson["name"] = escapeHtmlForJson(user.name);
        userJson["role"] = user.role;
        userJson["phone"] = escapeHtmlForJson(user.phone);
        userJson["email"] = escapeHtmlForJson(user.email);
        userJson["is_active"] = user.is_active;
        userJson["created_at"] = user.created_at;

        usersArray.append(userJson);
    }

    response["data"]["users"] = usersArray;
    // Поле "count" убрано - клиент может использовать users.length

    sendJsonResponse(conn, response, 200);
    logMessage("Users list accessed by admin: " + userData.login);
}



void ServerCore::handlePostUsersCreate(mg_connection* conn)
{
    // 1. Аутентификация и проверка прав (только admin)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "admin")) {
        return;
    }

    // 2. Чтение тела запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсинг JSON
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Проверка обязательных полей
    if (!jsonRequest.isMember("login") || !jsonRequest.isMember("password") ||
        !jsonRequest.isMember("name") || !jsonRequest.isMember("role")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing required fields: login, password, name, role";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 5. Извлечение данных
    std::string login = jsonRequest["login"].asString();
    std::string password = jsonRequest["password"].asString();
    std::string name = jsonRequest["name"].asString();
    std::string role = jsonRequest["role"].asString();

    std::string phone = jsonRequest.isMember("phone") ? jsonRequest["phone"].asString() : "";
    std::string email = jsonRequest.isMember("email") ? jsonRequest["email"].asString() : "";

    // 6. Создание пользователя
    DatabaseManager::CreateUserResult createResult =
        currentInstance->dbManager.createUser(login, password, name, role, phone, email);

    // 7. Формирование ответа
    if (!createResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = createResult.error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "User created successfully";

    Json::Value data;
    data["user_id"] = createResult.user_id;
    data["login"] = login;
    data["name"] = escapeHtmlForJson(name);
    data["role"] = role;

    successResp["data"] = data;

    sendJsonResponse(conn, successResp, 201); // 201 Created
    logMessage("User created by admin " + userData.login + ": " + login + " (" + role + ")");
}



void ServerCore::handlePostUsersUpdate(mg_connection* conn)
{
    // 1. Аутентификация и проверка прав (только admin)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "admin")) {
        return;
    }

    // 2. Чтение тела запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсинг JSON
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Проверка обязательного поля user_id
    if (!jsonRequest.isMember("user_id")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing required field: user_id";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 5. БЕЗОПАСНОЕ извлечение user_id (защита от SQLi и неверных типов)
    int user_id = 0;
    std::string error_msg = "";
    bool valid_user_id = false;

    if (jsonRequest["user_id"].isInt()) {
        // user_id как число
        user_id = jsonRequest["user_id"].asInt();
        valid_user_id = true;
    }
    else if (jsonRequest["user_id"].isString()) {
        // user_id как строка - пытаемся преобразовать
        std::string user_id_str = jsonRequest["user_id"].asString();
        try {
            size_t pos = 0;
            user_id = std::stoi(user_id_str, &pos);

            // Проверяем что вся строка была преобразована
            if (pos != user_id_str.length()) {
                error_msg = "user_id contains non-numeric characters";
            } else {
                valid_user_id = true;
            }
        }
        catch (const std::invalid_argument& e) {
            error_msg = "user_id must be a valid integer";
        }
        catch (const std::out_of_range& e) {
            error_msg = "user_id value is out of range";
        }
    }
    else {
        // user_id не число и не строка
        error_msg = "user_id must be an integer or numeric string";
    }

    if (!valid_user_id) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 6. Дополнительная валидация user_id
    if (user_id <= 0) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Invalid user ID. Must be positive integer";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 7. Извлечение опциональных полей
    std::string name = jsonRequest.isMember("name") ? jsonRequest["name"].asString() : "";
    std::string role = jsonRequest.isMember("role") ? jsonRequest["role"].asString() : "";
    std::string phone = jsonRequest.isMember("phone") ? jsonRequest["phone"].asString() : "";
    std::string email = jsonRequest.isMember("email") ? jsonRequest["email"].asString() : "";

    bool is_active = true;
    if (jsonRequest.isMember("is_active")) {
        if (jsonRequest["is_active"].isBool()) {
            is_active = jsonRequest["is_active"].asBool();
        } else {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "is_active must be a boolean (true/false)";
            sendJsonResponse(conn, errorResp, 400);
            return;
        }
    }

    // 8. Валидация роли (если указана)
    if (!role.empty() && role != "admin" && role != "operator" && role != "executor") {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Invalid role. Must be: admin, operator, executor";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 9. Обновление пользователя
    DatabaseManager::UpdateUserResult updateResult =
        currentInstance->dbManager.updateUser(user_id, name, role, phone, email, is_active);

    // 10. Формирование ответа
    if (!updateResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = updateResult.error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "User updated successfully";

    Json::Value data;
    data["user_id"] = user_id;
    if (!name.empty()) data["name_updated"] = true;
    if (!role.empty()) data["role_updated"] = true;
    if (!phone.empty()) data["phone_updated"] = true;
    if (!email.empty()) data["email_updated"] = true;
    data["is_active"] = is_active;

    successResp["data"] = data;

    sendJsonResponse(conn, successResp, 200);
    logMessage("User updated by admin " + userData.login + ": user_id=" + std::to_string(user_id));
}






void ServerCore::handlePostUsersDelete(mg_connection* conn)
{
    // 1. Аутентификация и проверка прав (только admin)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "admin")) {
        return;
    }

    // 2. Чтение тела запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсинг JSON
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Проверка обязательного поля user_id
    if (!jsonRequest.isMember("user_id")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing required field: user_id";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 5. БЕЗОПАСНОЕ извлечение user_id (защита от SQLi и неверных типов)
    int user_id = 0;
    std::string error_msg = "";
    bool valid_user_id = false;

    if (jsonRequest["user_id"].isInt()) {
        // user_id как число
        user_id = jsonRequest["user_id"].asInt();
        valid_user_id = true;
    }
    else if (jsonRequest["user_id"].isString()) {
        // user_id как строка - пытаемся преобразовать
        std::string user_id_str = jsonRequest["user_id"].asString();
        try {
            size_t pos = 0;
            user_id = std::stoi(user_id_str, &pos);

            // Проверяем что вся строка была преобразована
            if (pos != user_id_str.length()) {
                error_msg = "user_id contains non-numeric characters";
            } else {
                valid_user_id = true;
            }
        }
        catch (const std::invalid_argument& e) {
            error_msg = "user_id must be a valid integer";
        }
        catch (const std::out_of_range& e) {
            error_msg = "user_id value is out of range";
        }
    }
    else {
        // user_id не число и не строка
        error_msg = "user_id must be an integer or numeric string";
    }

    if (!valid_user_id) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 6. Дополнительная валидация
    if (user_id <= 0) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Invalid user ID. Must be positive integer";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 7. Запрет на деактивацию самого себя (опционально)
    if (user_id == userData.user_id) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Cannot deactivate your own account";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 8. Деактивация пользователя
    DatabaseManager::DeleteUserResult deleteResult =
        currentInstance->dbManager.deleteUser(user_id);

    // 9. Формирование ответа
    if (!deleteResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = deleteResult.error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "User deactivated successfully";
    successResp["data"]["user_id"] = user_id;
    successResp["data"]["action"] = "deactivated";

    sendJsonResponse(conn, successResp, 200);
    logMessage("User deactivated by admin " + userData.login + ": user_id=" + std::to_string(user_id));
}






// void ServerCore::handlePostAuthChangePassword(mg_connection* conn)
// {
//     // 1. Аутентификация (любая роль)
//     TokenValidationResult userData;
//     if (!authenticateRequest(conn, userData, "executor")) { // executor - минимальная роль
//         return;
//     }

//     // 2. Чтение тела запроса
//     std::string requestBody = readRequestBody(conn);
//     if (requestBody.empty()) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Empty request body";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 3. Парсинг JSON
//     Json::Value jsonRequest;
//     std::string parseError;
//     if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = parseError;
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     // 4. Проверка обязательных полей
//     if (!jsonRequest.isMember("old_password") || !jsonRequest.isMember("new_password")) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = "Missing old_password or new_password field";
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     std::string old_password = jsonRequest["old_password"].asString();
//     std::string new_password = jsonRequest["new_password"].asString();

//     // 5. Определяем user_id для смены пароля
//     int target_user_id = userData.user_id; // по умолчанию меняем свой пароль

//     // Если admin хочет сменить пароль другому пользователю
//     if (jsonRequest.isMember("user_id") && userData.role == "admin") {
//         // БЕЗОПАСНОЕ извлечение user_id
//         std::string error_msg = "";
//         bool valid_user_id = false;
//         int extracted_user_id = 0;

//         if (jsonRequest["user_id"].isInt()) {
//             extracted_user_id = jsonRequest["user_id"].asInt();
//             valid_user_id = true;
//         }
//         else if (jsonRequest["user_id"].isString()) {
//             std::string user_id_str = jsonRequest["user_id"].asString();
//             try {
//                 size_t pos = 0;
//                 extracted_user_id = std::stoi(user_id_str, &pos);

//                 if (pos != user_id_str.length()) {
//                     error_msg = "user_id contains non-numeric characters";
//                 } else {
//                     valid_user_id = true;
//                 }
//             }
//             catch (const std::invalid_argument& e) {
//                 error_msg = "user_id must be a valid integer";
//             }
//             catch (const std::out_of_range& e) {
//                 error_msg = "user_id value is out of range";
//             }
//         }
//         else {
//             error_msg = "user_id must be an integer or numeric string";
//         }

//         if (!valid_user_id) {
//             Json::Value errorResp;
//             errorResp["status"] = "error";
//             errorResp["message"] = error_msg;
//             sendJsonResponse(conn, errorResp, 400);
//             return;
//         }

//         if (extracted_user_id <= 0) {
//             Json::Value errorResp;
//             errorResp["status"] = "error";
//             errorResp["message"] = "Invalid user ID. Must be positive integer";
//             sendJsonResponse(conn, errorResp, 400);
//             return;
//         }

//         target_user_id = extracted_user_id;
//     }

//     // 6. Смена пароля
//     DatabaseManager::ChangePasswordResult changeResult =
//         currentInstance->dbManager.changePassword(target_user_id, old_password, new_password);

//     // 7. Формирование ответа
//     if (!changeResult.success) {
//         Json::Value errorResp;
//         errorResp["status"] = "error";
//         errorResp["message"] = changeResult.error_msg;
//         sendJsonResponse(conn, errorResp, 400);
//         return;
//     }

//     Json::Value successResp;
//     successResp["status"] = "success";
//     successResp["message"] = "Password changed successfully";

//     if (target_user_id != userData.user_id) {
//         successResp["data"]["user_id"] = target_user_id;
//         successResp["data"]["changed_by_admin"] = true;
//         logMessage("Password changed by admin " + userData.login + " for user_id=" + std::to_string(target_user_id));
//     } else {
//         successResp["data"]["changed_by_admin"] = false;
//         logMessage("Password changed by user: " + userData.login);
//     }

//     sendJsonResponse(conn, successResp, 200);
// }


void ServerCore::handlePostAuthChangePassword(mg_connection* conn)
{
    // 1. Аутентификация (любая роль)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "executor")) { // executor - минимальная роль
        return;
    }

    // 2. Чтение тела запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсинг JSON
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Определение сценария
    bool isAdminChangingForOther = false;
    int target_user_id = userData.user_id; // по умолчанию меняем свой пароль
    std::string old_password = "";
    std::string new_password = "";

    // Сценарий 1: Админ меняет пароль другому пользователю
    if (jsonRequest.isMember("user_id") && userData.role == "admin") {
        // Безопасное извлечение user_id
        std::string error_msg = "";
        bool valid_user_id = false;
        int extracted_user_id = 0;

        if (jsonRequest["user_id"].isInt()) {
            extracted_user_id = jsonRequest["user_id"].asInt();
            valid_user_id = true;
        }
        else if (jsonRequest["user_id"].isString()) {
            std::string user_id_str = jsonRequest["user_id"].asString();
            try {
                size_t pos = 0;
                extracted_user_id = std::stoi(user_id_str, &pos);

                if (pos != user_id_str.length()) {
                    error_msg = "user_id contains non-numeric characters";
                } else {
                    valid_user_id = true;
                }
            }
            catch (const std::invalid_argument& e) {
                error_msg = "user_id must be a valid integer";
            }
            catch (const std::out_of_range& e) {
                error_msg = "user_id value is out of range";
            }
        }
        else {
            error_msg = "user_id must be an integer or numeric string";
        }

        if (!valid_user_id) {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = error_msg;
            sendJsonResponse(conn, errorResp, 400);
            return;
        }

        if (extracted_user_id <= 0) {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "Invalid user ID. Must be positive integer";
            sendJsonResponse(conn, errorResp, 400);
            return;
        }

        // Проверяем, что админ не меняет пароль самому себе (опционально)
        if (extracted_user_id == userData.user_id) {
            // Админ меняет свой пароль - переходим в сценарий 2
            // Требуем old_password
            isAdminChangingForOther = false;
            target_user_id = userData.user_id;
        } else {
            // Админ меняет пароль другому пользователю
            isAdminChangingForOther = true;
            target_user_id = extracted_user_id;
        }
    }

    // 5. Проверка наличия new_password
    if (!jsonRequest.isMember("new_password")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing new_password field";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    new_password = jsonRequest["new_password"].asString();

    // 6. Проверка сложности нового пароля
    std::string complexity_error;
    if (!PasswordHasher::validatePasswordComplexity(new_password, complexity_error)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = complexity_error;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 7. Обработка в зависимости от сценария
    DatabaseManager::ChangePasswordResult changeResult;

    if (isAdminChangingForOther) {
        // Сценарий 1: Админ меняет пароль другому пользователю
        // Используем новый метод resetUserPassword
        changeResult = currentInstance->dbManager.resetUserPassword(target_user_id, new_password);
    }
    else {
        // Сценарий 2: Пользователь меняет свой пароль (или админ свой)
        if (!jsonRequest.isMember("old_password")) {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "Missing old_password field";
            sendJsonResponse(conn, errorResp, 400);
            return;
        }

        old_password = jsonRequest["old_password"].asString();

        // Старый и новый пароль не должны совпадать
        if (old_password == new_password) {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "New password must be different from current password";
            sendJsonResponse(conn, errorResp, 400);
            return;
        }

        // Проверка что пароль не содержит логин
        std::string user_login = userData.login;
        std::string lower_password = new_password;
        std::string lower_login = user_login;

        for (char& c : lower_password) c = std::tolower(c);
        for (char& c : lower_login) c = std::tolower(c);

        if (lower_password.find(lower_login) != std::string::npos) {
            Json::Value errorResp;
            errorResp["status"] = "error";
            errorResp["message"] = "Password should not contain your login";
            sendJsonResponse(conn, errorResp, 400);
            return;
        }

        changeResult = currentInstance->dbManager.changePassword(
            target_user_id, old_password, new_password);
    }

    // 8. Формирование ответа
    if (!changeResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = changeResult.error_msg;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "Password changed successfully";

    if (isAdminChangingForOther) {
        successResp["data"]["user_id"] = target_user_id;
        successResp["data"]["changed_by_admin"] = true;
        logMessage("Password changed by admin " + userData.login + " for user_id=" + std::to_string(target_user_id));
    } else {
        successResp["data"]["changed_by_admin"] = false;
        logMessage("Password changed by user: " + userData.login);
    }

    sendJsonResponse(conn, successResp, 200);
}







void ServerCore::handlePostAuthRefresh(mg_connection* conn)
{
    // 1. Проверка currentInstance
    if (!currentInstance) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Server instance not available";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // 2. Проверка подключения к БД
    if (!currentInstance->dbManager.isConnected()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Database not connected";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // 3. Извлекаем старый токен из заголовка Authorization
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    std::string authHeader = "";

    for (int i = 0; i < req_info->num_headers; i++) {
        if (strcmp(req_info->http_headers[i].name, "Authorization") == 0) {
            authHeader = req_info->http_headers[i].value;
            break;
        }
    }

    // 4. Проверяем формат: "Bearer <token>"
    if (authHeader.empty() || authHeader.find("Bearer ") != 0) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Authorization header missing or invalid format. Use: Bearer <token>";
        sendJsonResponse(conn, errorResp, 401);
        return;
    }

    // 5. Извлекаем старый токен
    std::string old_token = authHeader.substr(7); // "Bearer ".length() = 7

    // 6. Вызываем метод обновления токена
    DatabaseManager::RefreshTokenResult refreshResult =
        currentInstance->dbManager.refreshAuthToken(old_token);

    // 7. Формирование ответа
    if (!refreshResult.success) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = refreshResult.error_msg;

        // Определяем код ошибки
        int statusCode = 400;
        if (refreshResult.error_msg.find("Token not found") != std::string::npos ||
            refreshResult.error_msg.find("suspicious") != std::string::npos) {
            statusCode = 401;
        }

        sendJsonResponse(conn, errorResp, statusCode);
        logMessage("Token refresh failed: " + refreshResult.error_msg);
        return;
    }

    // 8. Успешный ответ
    Json::Value successResp;
    successResp["status"] = "success";
    successResp["message"] = "Token refreshed successfully";

    Json::Value data;
    data["token"] = refreshResult.new_token;
    data["user_id"] = refreshResult.user_id;
    data["login"] = refreshResult.login;
    data["name"] = escapeHtmlForJson(refreshResult.name);
    data["role"] = refreshResult.role;

    successResp["data"] = data;

    sendJsonResponse(conn, successResp, 200);
    logMessage("Token refreshed for user: " + refreshResult.login +
               " (old_token: " + old_token.substr(0, 8) + "...)");
}

void ServerCore::handleDeviceDataWrite(mg_connection *conn)
{
    // === ПРОВЕРКА 1: currentInstance ===
    if (!currentInstance) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Server instance not available";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // === ПРОВЕРКА 2: База данных подключена ===
    if (!currentInstance->dbManager.isConnected()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Database not connected";
        sendJsonResponse(conn, errorResp, 500);
        return;
    }

    // 1. Аутентификация (любая роль)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "executor")) {
        return;
    }

    // 2. Чтение тела запроса
    std::string requestBody = readRequestBody(conn);
    if (requestBody.empty()) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Empty request body";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 3. Парсинг JSON для базовой валидации
    Json::Value jsonRequest;
    std::string parseError;
    if (!parseJsonRequest(requestBody, jsonRequest, parseError)) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = parseError;
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 4. Проверяем наличие обязательных полей
    if (!jsonRequest.isMember("dev_id") || !jsonRequest.isMember("keys")) {
        Json::Value errorResp;
        errorResp["status"] = "error";
        errorResp["message"] = "Missing required fields: dev_id or keys";
        sendJsonResponse(conn, errorResp, 400);
        return;
    }

    // 5. Вызываем метод DatabaseManager для записи данных
    DeviceWriteResult result = currentInstance->dbManager.saveDeviceMeasures(requestBody);

    // 6. Формируем ответ
    Json::Value response;

    if (result.success) {
        response["status"] = result.status;
        if (!result.message.empty()) {
            response["message"] = result.message;
        }
        sendJsonResponse(conn, response, 200);
    } else {
        response["status"] = result.status;
        response["message"] = result.message.empty() ? "Operation failed" : result.message;

        // Определяем HTTP статус код в зависимости от типа ошибки
        int httpStatus = 500;
        if (result.status == 1) {
            httpStatus = 400; // Ошибка в данных
        } else if (result.status == 2) {
            httpStatus = 404; // Устройство не найдено
        }

        sendJsonResponse(conn, response, httpStatus);
    }
}

void ServerCore::handleDeviceDataRead(mg_connection* conn)
{
    // === ПРОВЕРКА 1: currentInstance ===
    if (!currentInstance) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = "Server instance not available";
        sendJsonResponse(conn, err, 500);
        return;
    }

    // === ПРОВЕРКА 2: База данных подключена ===
    if (!currentInstance->dbManager.isConnected()) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = "Database not connected";
        sendJsonResponse(conn, err, 500);
        return;
    }

    // 1. Аутентификация (любая роль)
    TokenValidationResult userData;
    if (!authenticateRequest(conn, userData, "executor")) {
        return;
    }

    // 2. Чтение тела запроса
    std::string body = readRequestBody(conn);
    if (body.empty()) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = "Empty request body";
        sendJsonResponse(conn, err, 400);
        return;
    }

    // 3. Парсинг JSON для базовой валидации
    Json::Value req;
    std::string parseError;
    if (!parseJsonRequest(body, req, parseError)) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = parseError;
        sendJsonResponse(conn, err, 400);
        return;
    }

    // 4. Проверяем наличие обязательных полей
    if (!req.isMember("dev_id") || !req.isMember("filters")) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = "Missing dev_id or filters";
        sendJsonResponse(conn, err, 400);
        return;
    }

    const Json::Value& filters = req["filters"];

    //check data
    if (!filters.isMember("date_from") || !filters.isMember("date_to")) {
        Json::Value err;
        err["status"] = "error";
        err["message"] = "Missing date_from or date_to";
        sendJsonResponse(conn, err, 400);
        return;
    }

    int devId = req["dev_id"].asInt();
    std::string dateFrom = filters["date_from"].asString();
    std::string dateTo   = filters["date_to"].asString();
    int limit  = filters.get("limit", 100).asInt();
    int offset = filters.get("offset", 0).asInt();
    int totalCount = currentInstance->dbManager.getMeasuresTotalCount();

    // === 7. Call DB ===
    auto rows = currentInstance->dbManager.readDeviceMeasures(
        devId, dateFrom, dateTo, limit, offset
        );

    if (rows.empty()) {
        Json::Value response;
        response["status"] = "success";
        response["total_count"] = 0;
        response["data"] = Json::arrayValue;
        sendJsonResponse(conn, response, 200);
        return;
    }

    std::map<std::string, Json::Value> grouped;

    //pivot rows into record
    for (const auto& r : rows) {
        if (!grouped.count(r.timestamp)) {
            Json::Value obj;
            obj["timestamp"] = r.timestamp;
            grouped[r.timestamp] = obj;
        }
        double rounded = std::round(r.value * 100.0) / 100.0;
        grouped[r.timestamp][r.key] = rounded;
    }

    Json::Value data(Json::arrayValue);
    for (auto& [_, obj] : grouped) {
        data.append(obj);
    }

    Json::Value columns(Json::arrayValue);

    //build columns array
    if (req.isMember("filters") && req["filters"].isMember("keys")) {
        const Json::Value& keys = req["filters"]["keys"];
        for (Json::ValueConstIterator it = keys.begin(); it != keys.end(); ++it) {
            columns.append(it->asString());
        }
    } else {
        // fallback: include default columns
        columns.append("temp");
        columns.append("hum");
        columns.append("pressure");
        columns.append("rad");
    }

    //build response
    Json::Value response;
    response["status"] = "success";
    response["total_count"] = totalCount;
    response["records_returned"] = (int)data.size();
    response["columns"] = columns;
    response["data"] = data;

    sendJsonResponse(conn, response, 200);
}


std::string ServerCore::escapeHtmlForJson(const std::string& input)
{
    if (input.empty()) {
        return input;
    }

    std::string output;
    output.reserve(input.length() * 2); // Меньше резерва, т.к. кириллицу не экранируем

    for (size_t i = 0; i < input.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);

        // Экранируем только опасные для HTML/XML символы и управляющие символы
        switch (c) {
        case '<':  output += "\\u003c"; break;  // < - опасен для HTML
        case '>':  output += "\\u003e"; break;  // > - опасен для HTML
        case '&':  output += "\\u0026"; break;  // & - опасен для HTML
        case '\"': output += "\\\""; break;     // " - опасен для JSON
        case '\'': output += "\\'"; break;      // ' - опционально
        case '\\': output += "\\\\"; break;     // \ - опасен для JSON
        case '/':  output += "\\/"; break;      // / - опционально
        case '\b': output += "\\b"; break;      // управляющие символы
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            // Экранируем ТОЛЬКО управляющие символы (0x00-0x1F)
            // Кириллицу и другие UTF-8 символы оставляем как есть
            if (c < 0x20) {
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                output += buf;
            } else {
                output += c; // Все остальные символы (включая кириллицу) как есть
            }
            break;
        }
    }

    return output;
}
