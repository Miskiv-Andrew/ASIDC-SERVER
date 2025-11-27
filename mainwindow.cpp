#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>


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
        ui->lblStatus->setText("HTTP Server running on port " + QString::number(port));
        ui->txtLog->append("Server started on port " + QString::number(port));
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

