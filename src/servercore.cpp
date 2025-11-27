#include "servercore.h"
#include "../cv_web/civetweb.h"
#include <iostream>
#include <chrono>
#include <ctime>

ServerCore::ServerCore() : serverContext(nullptr), serverRunning(false), currentPort(0)
{
}

ServerCore::~ServerCore()
{
    stopServer();
}

bool ServerCore::startServer(int port)
{

    if (serverRunning) {
        stopServer();
    }

    std::string port_str = std::to_string(port);
    const char *options[] = {
        "listening_ports", port_str.c_str(),
        "num_threads", "5",
        NULL
    };

    // Создаем структуру callback-функций
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks)); // Обнуляем структуру
    callbacks.begin_request = handleRequest;  // Регистрируем наш обработчик

    serverContext = mg_start(&callbacks, NULL, options); // Передаем callbacks

    if (!serverContext) {
        lastError = "mg_start returned NULL";
        serverRunning = false;
        return false;
    }

    serverRunning = true;
    currentPort = port;
    lastError.clear();

    std::cout << "HTTP server with request handler started on port " << port << std::endl;
    return true;

}

void ServerCore::stopServer()
{
    if (serverContext) {
        mg_stop((mg_context*)serverContext);
        serverContext = nullptr;
    }
    serverRunning = false;
    std::cout << "HTTP server stopped" << std::endl;
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


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


int ServerCore::handleRequest(mg_connection *conn)
{
    // Теперь правильный тип
    const struct mg_request_info* req_info = mg_get_request_info(conn);

    if (!req_info) {
        return 0;
    }

    std::cout << "Received request: " << req_info->request_method
              << " " << req_info->request_uri << std::endl;

    std::string uri = req_info->request_uri;

    if (uri == "/") {
        handleRootRequest(conn);
    }
    else if (uri == "/api/status") {
        handleApiStatus(conn);
    }
    else if (uri == "/api/test") {
        handleApiTest(conn);
    }
    else {
        mg_send_http_error(conn, 404, "Not Found");
    }

    return 1;
}

void ServerCore::handleRootRequest(mg_connection *conn)
{
    std::string response = "Radiation Monitoring Server\n"
                           "HTTP Server is running\n"
                           "Use /api/status for server status";
    sendResponse(conn, response, "text/plain");
}

void ServerCore::handleApiStatus(mg_connection *conn)
{
    std::string response = "{\n"
                           "  \"status\": \"running\",\n"
                           "  \"service\": \"radiation_monitor\",\n"
                           "  \"timestamp\": \"" + getCurrentTime() + "\"\n"
                                                "}";
    sendResponse(conn, response, "application/json");
}

void ServerCore::handleApiTest(mg_connection *conn)
{
    std::string response = "{\n"
                           "  \"message\": \"Test successful\",\n"
                           "  \"code\": 200\n"
                           "}";
    sendResponse(conn, response, "application/json");
}

void ServerCore::sendResponse(mg_connection *conn, const std::string &content, const std::string &contentType)
{
    mg_printf(conn, "HTTP/1.1 200 OK\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n\r\n",
              contentType.c_str(), content.length());

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


