#ifndef SERVERCORE_H
#define SERVERCORE_H

#include <string>
#include <functional>

#include ".//nanodbc/nanodbc.h"  // Подключить в классе баз данных

#include ".//databasemanager.h"

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
    static void handleRootRequest(struct mg_connection* conn);
    static void handleApiStatus(struct mg_connection* conn);
    static void handleApiTest(struct mg_connection* conn);
    static void sendResponse(struct mg_connection* conn, const std::string& content, const std::string& contentType = "text/plain");

    static std::string getCurrentTime();


    void* serverContext;  // Указатель на mg_context (void* для независимости от Qt)
    bool serverRunning;
    std::string lastError;
    int currentPort;

    LogCallback logCallback_;
    void logMessage(const std::string& message);
    static ServerCore* currentInstance;
};

#endif // SERVERCORE_H
