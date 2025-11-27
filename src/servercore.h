#ifndef SERVERCORE_H
#define SERVERCORE_H

#include <string>


class ServerCore
{
public:
    ServerCore();
    ~ServerCore();

    bool startServer(int port = 8080);
    void stopServer();
    bool isRunning() const;
    std::string getLastError() const;
    int getServerPort() const;

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
};

#endif // SERVERCORE_H
