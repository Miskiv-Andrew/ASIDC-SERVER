#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QDebug>
#include "cv_web/civetweb.h"
#include "src/servercore.h"

#include <json/json.h>


QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_btnStartServer_clicked();

    void on_btnStopServer_clicked();

    void on_btnRestartServer_clicked();


    void on_btnTestHTTP_clicked();

private:
    Ui::MainWindow *ui;
    ServerCore serverCore;  // Добавляем сервер
    QNetworkAccessManager* networkManager;  // Для HTTP запросов
};
#endif // MAINWINDOW_H
