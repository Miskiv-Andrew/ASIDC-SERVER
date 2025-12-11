#ifndef SERVERCORE_H
#define SERVERCORE_H

#include <string>
#include <functional>

#include ".//nanodbc/nanodbc.h"  // Подключить в классе баз данных

#include ".//databasemanager.h"

#include <json/json.h>

class ServerCore
{
public:

    // Тип для callback-функции (принимает строку, возвращает void)
    using LogCallback = std::function<void(const std::string&)>;

    ServerCore();
    ~ServerCore();

    bool startServer(int port = 8080);
    void stopServer();
    bool isRunning() const;
    std::string getLastError() const;
    int getServerPort() const;

    void setLogCallback(LogCallback callback);

    DatabaseManager dbManager;

private:

    // методы для обработки запросов
    static int handleRequest(struct mg_connection* conn);

    static void handlePostRoot(struct mg_connection* conn);

    static void handlePostStatus(struct mg_connection* conn);

    static void handlePostTest(struct mg_connection* conn);

    // Новые обработчики для аутентификации
    static void handlePostAuthLogin(mg_connection* conn);

    static void handlePostAuthValidate(mg_connection* conn);

    static void sendResponse(struct mg_connection* conn, const std::string& content, const std::string& contentType = "text/plain");

    static std::string getCurrentTime();

    // Новые вспомогательные методы для работы с HTTP и JSON
    static std::string readRequestBody(mg_connection* conn);

    static bool parseJsonRequest(const std::string& jsonStr, Json::Value& jsonValue, std::string& errorMsg);

    static void sendJsonResponse(mg_connection* conn, const Json::Value& jsonData, int statusCode = 200);


    // Middleware для проверки аутентификации
    static bool authenticateRequest(mg_connection* conn,
                                    TokenValidationResult& tokenData,
                                    const std::string& requiredRole = "executor");

    // Проверка прав доступа по роли
    static bool checkPermissions(const TokenValidationResult& tokenData,
                                 const std::string& requiredRole);


    static void handlePostAuthLogout(mg_connection* conn);

    static void handlePostUsersList(mg_connection* conn);

    static void handlePostUsersCreate(mg_connection* conn);

    static void handlePostUsersUpdate(mg_connection* conn);

    static void handlePostUsersDelete(mg_connection* conn);

    static void handlePostAuthChangePassword(mg_connection* conn);


    void* serverContext;  // Указатель на mg_context (void* для независимости от Qt)
    bool serverRunning;
    std::string lastError;
    int currentPort;

    LogCallback logCallback_;
    static void logMessage(const std::string& message);
    static ServerCore* currentInstance;
};

#endif // SERVERCORE_H
