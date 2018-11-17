#-------------------------------------------------
#
# Project created by QtCreator 2018-11-04T19:47:11
#
#-------------------------------------------------

QT       += core gui network sql xml

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = STIGQter
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++17

SOURCES += \
        main.cpp \
        stigqter.cpp \
    dbmanager.cpp \
    ccithread.cpp \
    common.cpp

HEADERS += \
        stigqter.h \
    dbmanager.h \
    ccithread.h \
    common.h

FORMS += \
        stigqter.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32{
    LIBS += -LE:/projects/openssl -llibssl -llibcrypto
    INCLUDEPATH += -LE:/projects/openssl/include
}
