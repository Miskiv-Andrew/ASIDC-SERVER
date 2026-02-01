#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

#include "servercore.h"

static std::atomic<bool> g_running(true);
static ServerCore* g_server = nullptr;

void signalHandler(int signal)
{
    std::cout << "\n[INFO] Signal received (" << signal << "), stopping server...\n";
    g_running = false;

    if (g_server) {
        g_server->stopServer();
    }
}

// Простое чтение SQL файла
std::string readSQLFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Упрощенное выполнение SQL скрипта
bool executeSQLScript(ServerCore& server, const std::string& sqlScript)
{
    if (sqlScript.empty()) {
        return false;
    }

    // Разбиваем по точке с запятой и выполняем команды
    std::istringstream stream(sqlScript);
    std::string line, command;

    while (std::getline(stream, line)) {
        // Пропускаем комментарии
        if (line.empty() || line.substr(0, 2) == "--" || line.substr(0, 2) == "/*") {
            continue;
        }

        command += line + "\n";

        // Если команда завершена, выполняем
        if (line.find(';') != std::string::npos) {
            if (!server.dbManager.executeQuery(command)) {
                // Игнорируем ошибки типа "already exists"
                std::string error = server.dbManager.getLastError();
                if (error.find("already exists") == std::string::npos) {
                    std::cerr << "[WARNING] SQL error: " << error << std::endl;
                }
            }
            command.clear();
        }
    }

    return true;
}

// Читай строку подключения из переменной окружения (правильный подход для Docker)
std::string getConnectionString()
{
    // Берём из переменной окружения, если есть
    const char* envDsn = std::getenv("ODBC_DSN");
    if (envDsn && envDsn[0] != '\0') {
        return std::string(envDsn);
    }
    // Fallback для локального запуска
    return "DSN=GuarderDB";
}

// Инициализация БД
bool initializeDatabase(ServerCore& server)
{
    std::cout << "[INFO] Initializing database...\n";

    std::string connStr = getConnectionString();
    std::cout << "[INFO] Using connection string: " << connStr << "\n";

    // Подключаемся к БД
    if (!server.dbManager.initialize(connStr)) {
        std::cerr << "[ERROR] Database connection failed: "
                  << server.dbManager.getLastError() << std::endl;
        return false;
    }

    std::cout << "[OK] Database connected\n";

    // CMake скопировал SQL файл в db/init/ - используем этот путь
    std::string sqlScript = readSQLFile("db/init/001_init.sql");

    if (sqlScript.empty()) {
        std::cerr << "[WARNING] SQL script not found or empty\n";
        std::cout << "[INFO] Database might already be initialized\n";
        return true; // Не критично, БД может быть уже создана
    }

    std::cout << "[INFO] Executing SQL initialization script...\n";
    executeSQLScript(server, sqlScript);

    std::cout << "[OK] Database initialization completed\n";
    return true;
}

int main(int argc, char** argv)
{
    int httpsPort = 8443;

    if (argc > 1) {
        httpsPort = std::atoi(argv[1]);
        if (httpsPort <= 0 || httpsPort > 65535) {
            std::cerr << "[ERROR] Invalid port, using default 8443\n";
            httpsPort = 8443;
        }
    }

    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::cout << "============================================\n";
    std::cout << "        Guarder Server (CLI mode)           \n";
    std::cout << "============================================\n";
    std::cout << "[INFO] HTTPS port: " << httpsPort << "\n";

    ServerCore server;
    g_server = &server;

    server.setLogCallback([](const std::string& msg) {
        std::cout << "[LOG] " << msg << std::endl;
    });

    // Инициализация БД
    if (!initializeDatabase(server)) {
        std::cerr << "[ERROR] Database initialization failed!\n";
        std::cerr << "[WARNING] Server will start but database operations may fail\n";
    }

    std::cout << "[INFO] Starting server...\n";
    if (!server.startServer(httpsPort)) {
        std::cerr << "[ERROR] Server start failed: "
                  << server.getLastError() << std::endl;
        return 1;
    }

    std::cout << "[OK] Server is running. Press Ctrl+C to stop.\n";

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[INFO] Server stopped. Exiting.\n";
    return 0;
}
