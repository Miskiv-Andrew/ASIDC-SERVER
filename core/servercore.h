#ifndef SERVERCORE_H
#define SERVERCORE_H

#include <string>
#include <functional>

#include "databasemanager.h"

#include <json/json.h>

/**
 * @class ServerCore
 * @brief Основной класс HTTP/HTTPS сервера на основе библиотеки civetweb.
 *
 * Обеспечивает:
 * - Запуск и остановку сервера
 * - Обработку HTTP/HTTPS запросов
 * - Аутентификацию и авторизацию пользователей
 * - Управление пользователями (для администраторов)
 * - Логирование операций
 * - Защиту от атак (rate limiting, XSS, SQL-инъекции)
 */
class ServerCore
{
public:
    /**
     * @brief Тип callback-функции для логирования.
     *
     * Принимает строку сообщения для логирования.
     */
    using LogCallback = std::function<void(const std::string&)>;

    /**
     * @brief Конструктор по умолчанию.
     */
    ServerCore();

    /**
     * @brief Деструктор.
     *
     * Останавливает сервер при уничтожении объекта.
     */
    ~ServerCore();

    /**
     * @brief Запускает HTTP/HTTPS сервер.
     *
     * @param port Порт для HTTP-соединений (по умолчанию 8080).
     *            HTTPS всегда работает на порту 8443.
     * @return true если сервер успешно запущен, false в случае ошибки.
     */
    bool startServer(int https_port = 8443);

    /**
     * @brief Останавливает сервер.
     *
     * Освобождает все ресурсы и закрывает соединения.
     */
    void stopServer();

    /**
     * @brief Проверяет, запущен ли сервер.
     *
     * @return true если сервер активен, false если остановлен.
     */
    bool isRunning() const;

    /**
     * @brief Возвращает текст последней ошибки.
     *
     * @return Строка с описанием последней ошибки или пустая строка.
     */
    std::string getLastError() const;

    /**
     * @brief Возвращает текущий порт сервера.
     *
     * @return Номер порта или 0 если сервер не запущен.
     */
    int getServerPort() const;

    /**
     * @brief Устанавливает callback-функцию для логирования.
     *
     * @param callback Функция, которая будет вызываться для логирования сообщений.
     */
    void setLogCallback(LogCallback callback);

    /// @brief Менеджер базы данных для работы с пользователями и токенами.
    DatabaseManager dbManager;

private:
    // === Обработчики HTTP-запросов ===

    /**
     * @brief Основной обработчик входящих HTTP-запросов.
     *
     * @param conn Соединение civetweb.
     * @return 1 если запрос обработан, 0 для передачи управления дальше.
     */
    static int handleRequest(struct mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к корневому эндпоинту (/).
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostRoot(struct mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/status.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostStatus(struct mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/test.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostTest(struct mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/auth/login.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostAuthLogin(mg_connection* conn);

    // static void handlePostAuthValidate(mg_connection* conn); // Удален

    /**
     * @brief Отправляет простой текстовый ответ.
     *
     * @param conn Соединение civetweb.
     * @param content Содержимое ответа.
     * @param contentType MIME-тип контента (по умолчанию text/plain).
     */
    static void sendResponse(struct mg_connection* conn,
                             const std::string& content,
                             const std::string& contentType = "text/plain");

    /**
     * @brief Возвращает текущее время в формате строки.
     *
     * @return Строка с текущей датой и временем.
     */
    static std::string getCurrentTime();

    // === Вспомогательные методы для работы с HTTP ===

    /**
     * @brief Читает тело HTTP-запроса.
     *
     * @param conn Соединение civetweb.
     * @return Содержимое тела запроса или пустая строка при ошибке.
     */
    static std::string readRequestBody(mg_connection* conn);

    /**
     * @brief Парсит JSON строку.
     *
     * @param jsonStr Строка в формате JSON.
     * @param jsonValue[out] Распарсенное значение JSON.
     * @param errorMsg[out] Сообщение об ошибке парсинга.
     * @return true если парсинг успешен, false в случае ошибки.
     */
    static bool parseJsonRequest(const std::string& jsonStr,
                                 Json::Value& jsonValue,
                                 std::string& errorMsg);

    /**
     * @brief Отправляет JSON ответ.
     *
     * @param conn Соединение civetweb.
     * @param jsonData Данные для отправки в формате JSON.
     * @param statusCode HTTP статус код ответа.
     */
    static void sendJsonResponse(mg_connection* conn,
                                 const Json::Value& jsonData,
                                 int statusCode = 200);

    // === Middleware и проверки безопасности ===

    /**
     * @brief Middleware для проверки аутентификации и авторизации.
     *
     * Извлекает токен из заголовка Authorization, проверяет его валидность
     * и проверяет права доступа по роли.
     *
     * @param conn Соединение civetweb.
     * @param tokenData[out] Результат проверки токена.
     * @param requiredRole Требуемая роль пользователя.
     * @return true если аутентификация успешна и права доступа есть.
     */
    static bool authenticateRequest(mg_connection* conn,
                                    TokenValidationResult& tokenData,
                                    const std::string& requiredRole = "executor");

    /**
     * @brief Проверяет права доступа пользователя по роли.
     *
     * @param tokenData Данные пользователя из токена.
     * @param requiredRole Требуемая роль.
     * @return true если доступ разрешен.
     */
    static bool checkPermissions(const TokenValidationResult& tokenData,
                                 const std::string& requiredRole);

    // === Обработчики API эндпоинтов ===

    /**
     * @brief Обрабатывает POST запрос к /api/auth/logout.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostAuthLogout(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/users/list.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostUsersList(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/users/create.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostUsersCreate(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/users/update.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostUsersUpdate(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/users/delete.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostUsersDelete(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/auth/change-password.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostAuthChangePassword(mg_connection* conn);

    /**
     * @brief Обрабатывает POST запрос к /api/auth/refresh.
     *
     * @param conn Соединение civetweb.
     */
    static void handlePostAuthRefresh(mg_connection* conn);

    /**
     * @brief Экранирует HTML-символы для безопасной вставки в JSON.
     *
     * Преобразует:
     * < → \u003c
     * > → \u003e
     * & → \u0026
     * " → \"
     * ' → \'
     * / → \/
     *
     * @param input Входная строка.
     * @return Экранированная строка.
     */
    static std::string escapeHtmlForJson(const std::string& input);

    /// @brief Указатель на контекст сервера civetweb.
    void* serverContext;

    /// @brief Флаг состояния сервера (true - запущен, false - остановлен).
    bool serverRunning;

    /// @brief Текст последней ошибки сервера.
    std::string lastError;

    /// @brief Текущий порт сервера.
    int currentPort;

    /// @brief Callback-функция для логирования.
    LogCallback logCallback_;

    /**
     * @brief Записывает сообщение в лог.
     *
     * @param message Сообщение для логирования.
     */
    static void logMessage(const std::string& message);

    /// @brief Указатель на текущий экземпляр ServerCore (для статических методов).
    static ServerCore* currentInstance;
};

#endif // SERVERCORE_H
