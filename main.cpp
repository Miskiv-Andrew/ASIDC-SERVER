#include "mainwindow.h"

#include <QApplication>
// #include "passwordhasher.h"
// #include <iostream>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();


    // std::string hash1 = PasswordHasher::hashPassword("operator123");
    // std::string hash2 = PasswordHasher::hashPassword("executor123");

    // std::cout << "operator123 hash: " << hash1 << std::endl;
    // std::cout << "executor123 hash: " << hash2 << std::endl;

    return a.exec();
}
