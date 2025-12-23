QT       += core gui core network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17


# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0   nanodbc

LIBS += -lodbc32

INCLUDEPATH +=  $$PWD/jsoncpp/include \
                $$PWD/third_party/nanodbc \
                $$PWD/third_party/civetweb \
                $$PWD/core

SOURCES += \
    third_party/jsoncpp/json_reader.cpp \
    third_party/jsoncpp/json_value.cpp  \
    third_party/jsoncpp/json_writer.cpp \
    core/databasemanager.cpp \
    third_party/nanodbc/nanodbc.cpp \
    core/passwordhasher.cpp


SOURCES += \
    third_party/civetweb/civetweb.c \
    gui/mainwindow.cpp \
    apps/main_gui.cpp \
    core/servercore.cpp

HEADERS += \
    third_party/civetweb//civetweb.h \
    third_party/civetweb//handle_form.inl \
    third_party/civetweb//match.inl \
    third_party/civetweb//md5.inl \
    third_party/civetweb//openssl_dl.inl \
    third_party/civetweb//response.inl \
    third_party/civetweb//sort.inl \
    core/databasemanager.h \
    gui/mainwindow.h \
    third_party/nanodbc/nanodbc.h \
    core/passwordhasher.h \
    core/servercore.h

FORMS += \
    gui/mainwindow.ui


win32 {
    OPENSSL_PATH = $$(OPENSSL_PATH)
    INCLUDEPATH += "$$OPENSSL_PATH/include"
    LIBS += -L"$$OPENSSL_PATH/lib/VC/x64/MD"
    LIBS += -llibssl -llibcrypto
}

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
