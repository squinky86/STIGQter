TEMPLATE = app
TARGET = tst_stigqter
CONFIG += testcase
include(../stigqter-common.pri)
QT += testlib
SOURCES += $$PWD/tst_stigqter.cpp
SOURCES += $$PWD/overhaul.cpp
HEADERS += $$PWD/tst_stigqter.h

SOURCES += $$PWD/uiscenarios.cpp
HEADERS += $$PWD/uiscenarios.h
