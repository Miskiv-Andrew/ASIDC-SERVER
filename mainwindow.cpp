#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>


#include "passwordhasher.h"
#include <QMessageBox>

#include "databasemanager.h"

const QString st_serv("server status ");
const QString st_db("DB status ");


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , networkManager(new QNetworkAccessManager(this))
{
    ui->setupUi(this);
    ui->txtPortHTTP->setText("HTTP not used");
    ui->txtPortHTTPS->setText("8443");


    // Тестовая лямбда для вывода информации, потом убрать
    serverCore.setLogCallback([this](const std::string& message) {
        QString qMessage = QString::fromStdString(message);
        ui->txtLog->append(qMessage);
    });


    // ui->lblStatus->setText("Server not started");
    // ui->lblSSLStatus->setText("SSL not configured");
    // ui->txtLog->append("Application initialized - ready to start server");
    // ui->txtLog->append("\n--------------------------------------------\n");
    // ui->txtLog->append("jsonCpp test");
    // Json::Value obj;
    // obj["name"] = "test";
    // obj["value"] = 123;
    // std::string s = obj.toStyledString();
    // ui->txtLog->append(QString::fromStdString(s));
    //const char* version = OpenSSL_version(OPENSSL_VERSION);
    // Вывод в GUI (если есть текстовое поле txtLog)
    //ui->txtLog->append(QString("OpenSSL loaded: %1").arg(version));
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

    bool flag;
    // Берем порт из поля HTTPS (ранее было HTTP)
    int https_port = ui->txtPortHTTPS->text().toInt(&flag);

    // Валидация порта
    if (!flag || https_port <= 0 || https_port > 65535) {
        https_port = 8443; // Значение по умолчанию при ошибке
        ui->txtPortHTTPS->setText("8443"); // Корректируем в UI
    }

    // Запускаем сервер с указанным HTTPS портом
    if (serverCore.startServer(https_port)) {
        ui->lblServerStatus->setText(st_serv + "HTTPS Server running on port " + QString::number(https_port) );
        ui->txtLog->append("HTTPS server started on port " + QString::number(https_port)+ " (HTTPS only)");
    } else {
        ui->lblServerStatus->setText(st_serv + "Server failed: " + QString::fromStdString(serverCore.getLastError()));
        ui->txtLog->append("Server start failed: " + QString::fromStdString(serverCore.getLastError()));
    }
}

void MainWindow::on_btnStopServer_clicked() // Server stop
{
    serverCore.stopServer();
    ui->lblServerStatus->setText(st_serv + "Server stopped");
    ui->txtLog->append("Server stopped");   
}

void MainWindow::on_btnRestartServer_clicked() // Server restart
{
    // Оостанавливаем сервер
    serverCore.stopServer();
    ui->txtLog->append("HTTPS server stopping...");
    ui->lblServerStatus->setText(st_serv + "Server stopping...");

    // Пауза для завершения операций
    QThread::msleep(100);

    // Запускаем снова с текущим HTTPS портом
    bool flag;
    int https_port = ui->txtPortHTTPS->text().toInt(&flag);

    // Валидация порта
    if (!flag || https_port <= 0 || https_port > 65535) {
        https_port = 8443; // Значение по умолчанию
        ui->txtPortHTTPS->setText("8443"); // Корректируем в UI
    }

    if (serverCore.startServer(https_port)) {
        ui->lblServerStatus->setText(st_serv + "HTTPS Server restarted on port " + QString::number(https_port) + " (HTTPS only)");
        ui->txtLog->append("HTTPS server restarted on port " + QString::number(https_port));
    } else {
        ui->lblServerStatus->setText(st_serv + "Restart failed: " + QString::fromStdString(serverCore.getLastError()));
        ui->txtLog->append("Restart failed: " + QString::fromStdString(serverCore.getLastError()));
    }
}


void MainWindow::on_btnTestDbConnect_clicked()  // DB connection
{
    // Параметры подключения (можно вынести в настройки)
    std::string connectionString = "DSN=GuarderDB";

    // std::string connectionString = "DRIVER={MySQL ODBC 9.5 Unicode Driver};SERVER=localhost;DATABASE=guarder_base;USER=root;PASSWORD=Qt26091968Qt";

    if (serverCore.dbManager.initialize(connectionString)) {
        ui->txtLog->append("Database connected successfully");
        ui->labelDBstatus->setText(st_db + "Database connected");
    }
    else {
        ui->txtLog->append("Database connection failed: " +
                           QString::fromStdString(serverCore.dbManager.getLastError()));
        ui->labelDBstatus->setText(st_db + "Database connection failed");
    }
}

void MainWindow::on_btnDBdisconnect_clicked()  // DB disconnect
{
    // Отключаемся от базы данных
    serverCore.dbManager.disconnect();

    ui->txtLog->append("Database connection closed");
    ui->labelDBstatus->setText(st_db + "Database disconnected");
}

void MainWindow::on_btnClearLogs_clicked() // Clear logs
{
    ui->txtLog->clear();
}



void MainWindow::on_pushButton_2_clicked()  // Get Hash from Pass
{
    // Если нужно получить ХЭШ по паролю
    std::string test_hash = PasswordHasher::hashPassword("Admin@Secure12345!");
    ui->txtLog->clear();
    ui->txtLog->append("Hash   " + QString::fromStdString(test_hash.c_str()));
}







