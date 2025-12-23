#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

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
