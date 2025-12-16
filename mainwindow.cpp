#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>


#include "passwordhasher.h"
#include <QMessageBox>

#include "databasemanager.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , networkManager(new QNetworkAccessManager(this))
{
    ui->setupUi(this);

    // Устанавливаем начальные значения
    ui->txtLog->append("Server test");
    ui->txtPortHTTP->setText("8080");
    ui->txtPortHTTPS->setText("8443");
    ui->lblStatus->setText("Server not started");
    ui->lblSSLStatus->setText("SSL not configured");
    ui->txtLog->append("Application initialized - ready to start server");
    ui->txtLog->append("\n--------------------------------------------\n");
    ui->txtLog->append("jsonCpp test");
    Json::Value obj;
    obj["name"] = "test";
    obj["value"] = 123;
    std::string s = obj.toStyledString();
    ui->txtLog->append(QString::fromStdString(s));


    serverCore.setLogCallback([this](const std::string& message) {
        QString qMessage = QString::fromStdString(message);
        ui->txtLog->append(qMessage);
    });


    const char* version = OpenSSL_version(OPENSSL_VERSION);


    // Вывод в GUI (если есть текстовое поле txtLog)

    ui->txtLog->append(QString("OpenSSL loaded: %1").arg(version));


    // ТЕСТ PasswordHasher
    //testPasswordHasher();

    //qDebug() << "JsonCpp version: " << JSONCPP_VERSION_STRING ;


}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btnStartServer_clicked() // Server start
{
    int port = ui->txtPortHTTP->text().toInt();
    if (port <= 0) port = 8080;

    if (serverCore.startServer(port)) {
        // ui->lblStatus->setText("HTTP Server running on port " + QString::number(port));
        // ui->txtLog->append("Server started on port " + QString::number(port));
    } else {
        ui->lblStatus->setText("Server failed: " + QString::fromStdString(serverCore.getLastError()));
        ui->txtLog->append("Server start failed: " + QString::fromStdString(serverCore.getLastError()));
    }
}


void MainWindow::on_btnStopServer_clicked() // Server stop
{
    serverCore.stopServer();
    ui->lblStatus->setText("Server stopped");
    ui->txtLog->append("Server stopped");
    qDebug() << "Server stopped by user";
}


void MainWindow::on_btnRestartServer_clicked() // Server restart
{
    // Сначала останавливаем
    serverCore.stopServer();
    ui->txtLog->append("Server stopping...");

    // Ждем немного (можно добавить QTimer для надежности)
    QThread::msleep(100);

    // Запускаем снова с текущим портом
    int port = ui->txtPortHTTP->text().toInt();
    if (port <= 0) port = 8080;

    if (serverCore.startServer(port)) {
        ui->lblStatus->setText("Server restarted on port " + QString::number(port));
        ui->txtLog->append("Server restarted on port " + QString::number(port));
    } else {
        ui->lblStatus->setText("Restart failed: " + QString::fromStdString(serverCore.getLastError()));
        ui->txtLog->append("Restart failed: " + QString::fromStdString(serverCore.getLastError()));
    }
}


void MainWindow::on_btnTestHTTP_clicked()
{
    int port = ui->txtPortHTTP->text().toInt();
    if (port <= 0) port = 8080;

    QUrl url("http://localhost:" + QString::number(port) + "/api/status");
    QNetworkRequest request(url);

    ui->txtLog->append("Testing HTTP connection to " + url.toString());

    QNetworkReply* reply = networkManager->get(request);

    // Таймаут 5 секунд
    QTimer::singleShot(5000, reply, &QNetworkReply::abort);

    connect(reply, &QNetworkReply::finished, [this, reply, port]() {
        if (reply->error() == QNetworkReply::NoError) {
            ui->txtLog->append("✓ HTTP server is working on port " + QString::number(port));
        } else {
            ui->txtLog->append("✗ HTTP server error: " + reply->errorString());
        }
        reply->deleteLater();
    });
}


void MainWindow::on_btnTestDbConnect_clicked()  // Test DB connection
{
    bool connected = serverCore.dbManager.initialize("DSN=GuarderDB");

    // bool connected = serverCore.dbManager.initialize("DRIVER={MySQL ODBC 9.5 Unicode Driver};SERVER=localhost;DATABASE=guarder_base;USER=root;PASSWORD=Qt26091968Qt");
    QString message = connected ?
                          "База данных подключена успешно" :
                          "Ошибка подключения: " + QString::fromStdString(serverCore.dbManager.getLastError());

    ui->txtLog->append(message);
}


void MainWindow::on_btnClearLogs_clicked() // Clear logs
{
    ui->txtLog->clear();
}

// void MainWindow::testPasswordHasher() {
//     try {
//         qDebug() << "=== Testing PasswordHasher ===";

//         // Тест 1: Хеширование пароля
//         std::string password = "MySecretPassword123";
//         std::string hash = PasswordHasher::hashPassword(password);

//         qDebug() << "Original password:" << password.c_str();
//         qDebug() << "Generated hash:" << hash.c_str();

//         // Тест 2: Проверка правильного пароля
//         bool verify1 = PasswordHasher::verifyPassword(password, hash);
//         qDebug() << "Verify correct password:" << (verify1 ? "SUCCESS" : "FAIL");

//         // Тест 3: Проверка неправильного пароля
//         bool verify2 = PasswordHasher::verifyPassword("WrongPassword", hash);
//         qDebug() << "Verify wrong password:" << (verify2 ? "FAIL (should be false)" : "SUCCESS");

//         // Тест 4: Генерация соли
//         std::string salt = PasswordHasher::generateSalt();
//         qDebug() << "Generated salt:" << salt.c_str();
//         qDebug() << "Salt length:" << salt.length();

//         // Вывод в GUI
//         if (ui->txtLog) {
//             ui->txtLog->append("=== PasswordHasher Test ===");
//             ui->txtLog->append("Hash test: " + QString(verify1 ? "PASSED" : "FAILED"));
//             ui->txtLog->append("Verification test: " + QString(!verify2 ? "PASSED" : "FAILED"));
//             ui->txtLog->append("All tests completed.");
//         }

//         // Проверка формата хеша
//         if (hash.find("pbkdf2_sha256:10000:") == 0) {
//             qDebug() << "Hash format: CORRECT";
//         } else {
//             qDebug() << "Hash format: INCORRECT";
//         }

//     } catch (const std::exception& e) {
//         qDebug() << "PasswordHasher test FAILED:" << e.what();
//         if (ui->txtLog) {
//             ui->txtLog->append("ERROR: " + QString(e.what()));
//         }
//         QMessageBox::critical(this, "Test Failed",
//                               QString("PasswordHasher test failed: %1").arg(e.what()));
//     }
// }


void MainWindow::on_pushButton_clicked()  // Log Test
{
    AuthResult result = serverCore.dbManager.authenticateUser("admin", "admin123");
    if (result.success) {
        ui->txtLog->append("Auth SUCCESS: User " + QString::fromStdString(result.name) +
                           ", Role: " + QString::fromStdString(result.role));
    } else {
        ui->txtLog->append("Auth FAILED: " + QString::fromStdString(result.error_msg));
    }
}


void MainWindow::on_pushButton_2_clicked()  // Test Hash
{
    std::string test_hash = PasswordHasher::hashPassword("Admin@123456");
    qDebug() << "New hash for Admin@123456:" << test_hash.c_str();
}


void MainWindow::on_pushButton_13_clicked()  // Token test
{
    // 1. Сначала аутентифицируемся
    AuthResult auth = serverCore.dbManager.authenticateUser("admin", "admin123");

    // 2. Если успешно, создаем токен
    if (auth.success) {
        std::string token = serverCore.dbManager.createAuthToken(
            auth.user_id,
            "127.0.0.1",  // тестовый IP
            "QtTestClient/1.0"  // тестовый User-Agent
            );

        ui->txtToken->setText(QString::fromStdString(token));

        if (!token.empty()) {
            ui->txtLog->append("Token created: " + QString::fromStdString(token));
        } else {
            ui->txtLog->append("Failed to create token");
        }
    }
}


void MainWindow::on_btnTestAPI_clicked()  // Validate token
{
    // Получаем токен из текстового поля (предположим, что он в ui->txtToken)
    QString tokenText = ui->txtToken->text().trimmed();

    if (tokenText.isEmpty()) {
        ui->txtLog->append("Ошибка: Введите токен для проверки");
        return;
    }

    // Вызываем метод validateToken
    TokenValidationResult result = serverCore.dbManager.validateToken(tokenText.toStdString());

    // Выводим результат
    if (result.valid) {
        QString message = QString("Токен валиден: "
                                  "User ID=%1, "
                                  "Логин=%2, "
                                  "Имя=%3, "
                                  "Роль=%4")
                              .arg(result.user_id)
                              .arg(QString::fromStdString(result.login))
                              .arg(QString::fromStdString(result.name))
                              .arg(QString::fromStdString(result.role));

        ui->txtLog->append(message);
    } else {
        QString message = QString("Токен невалиден: %1")
                              .arg(QString::fromStdString(result.error_msg));

        ui->txtLog->append(message);
    }
}

