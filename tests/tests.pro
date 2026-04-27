QT += core gui network sql xml widgets testlib

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += testcase c++1z
TEMPLATE = app
TARGET = tst_stigqter

VERSION = $$cat($$PWD/../VERSION)
DEFINES += APP_VERSION=\\\"$$VERSION\\\"
DEFINES += QT_DEPRECATED_WARNINGS

INCLUDEPATH += ../src

SOURCES += \
    tst_stigqter.cpp \
    ../src/asset.cpp \
    ../src/assetview.cpp \
    ../src/cci.cpp \
    ../src/cklcheck.cpp \
    ../src/common.cpp \
    ../src/control.cpp \
    ../src/dbmanager.cpp \
    ../src/family.cpp \
    ../src/help.cpp \
    ../src/stig.cpp \
    ../src/stigcheck.cpp \
    ../src/stigedit.cpp \
    ../src/stigqter.cpp \
    ../src/supplement.cpp \
    ../src/tabviewwidget.cpp \
    ../src/worker.cpp \
    ../src/workerassetadd.cpp \
    ../src/workerassetdelete.cpp \
    ../src/workercciadd.cpp \
    ../src/workerccidelete.cpp \
    ../src/workercheckversion.cpp \
    ../src/workerckl.cpp \
    ../src/workercklb.cpp \
    ../src/workercklexport.cpp \
    ../src/workercklimport.cpp \
    ../src/workercklupgrade.cpp \
    ../src/workercmrsexport.cpp \
    ../src/workeremassreport.cpp \
    ../src/workerfindingsreport.cpp \
    ../src/workerhtml.cpp \
    ../src/workerimportemass.cpp \
    ../src/workerimportemasscontrol.cpp \
    ../src/workermapunmapped.cpp \
    ../src/workerpoamreport.cpp \
    ../src/workerstigadd.cpp \
    ../src/workerstigdelete.cpp \
    ../src/workerstigdownload.cpp

HEADERS += \
    tst_stigqter.h \
    ../src/asset.h \
    ../src/assetview.h \
    ../src/cci.h \
    ../src/cklcheck.h \
    ../src/common.h \
    ../src/control.h \
    ../src/dbmanager.h \
    ../src/family.h \
    ../src/help.h \
    ../src/stig.h \
    ../src/stigcheck.h \
    ../src/stigedit.h \
    ../src/stigqter.h \
    ../src/supplement.h \
    ../src/tabviewwidget.h \
    ../src/worker.h \
    ../src/workerassetadd.h \
    ../src/workerassetdelete.h \
    ../src/workercciadd.h \
    ../src/workerccidelete.h \
    ../src/workercheckversion.h \
    ../src/workerckl.h \
    ../src/workercklb.h \
    ../src/workercklexport.h \
    ../src/workercklimport.h \
    ../src/workercklupgrade.h \
    ../src/workercmrsexport.h \
    ../src/workeremassreport.h \
    ../src/workerfindingsreport.h \
    ../src/workerhtml.h \
    ../src/workerimportemass.h \
    ../src/workerimportemasscontrol.h \
    ../src/workermapunmapped.h \
    ../src/workerpoamreport.h \
    ../src/workerstigadd.h \
    ../src/workerstigdelete.h \
    ../src/workerstigdownload.h

FORMS += \
    ../src/assetview.ui \
    ../src/help.ui \
    ../src/stigedit.ui \
    ../src/stigqter.ui

LIBS += -lzip -lxlsxwriter -lz

resources.files = \
    ../src/U_CCI_List.xml \
    ../src/800-53-rev4-controls.xml
resources.prefix = /dod
RESOURCES = resources
