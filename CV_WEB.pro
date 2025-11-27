QT       += core gui core network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

INCLUDEPATH += $$PWD/jsoncpp/include

SOURCES += \
    $$PWD/jsoncpp/src/lib_json/json_reader.cpp \
    $$PWD/jsoncpp/src/lib_json/json_value.cpp  \
    $$PWD/jsoncpp/src/lib_json/json_writer.cpp


SOURCES += \
    cv_web/civetweb.c \
    main.cpp \
    mainwindow.cpp \
    src/servercore.cpp

HEADERS += \
    cv_web/civetweb.h \
    cv_web/handle_form.inl \
    cv_web/match.inl \
    cv_web/md5.inl \
    cv_web/openssl_dl.inl \
    cv_web/response.inl \
    cv_web/sort.inl \
    mainwindow.h \
    src/servercore.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
