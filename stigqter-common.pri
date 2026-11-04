# Common application/library configuration; included by STIGQter.pro and tests.
STIGQTER_ROOT = $$PWD
QT += core gui network sql xml widgets
CONFIG += c++17
VERSION = $$cat($$STIGQTER_ROOT/VERSION)
DEFINES += APP_VERSION=\\\"$$VERSION\\\" QT_DEPRECATED_WARNINGS
INCLUDEPATH += $$STIGQTER_ROOT/src

SOURCES += \
    $$STIGQTER_ROOT/src/asset.cpp \
    $$STIGQTER_ROOT/src/assetview.cpp \
    $$STIGQTER_ROOT/src/cci.cpp \
    $$STIGQTER_ROOT/src/cklcheck.cpp \
    $$STIGQTER_ROOT/src/common.cpp \
    $$STIGQTER_ROOT/src/control.cpp \
    $$STIGQTER_ROOT/src/dbmanager.cpp \
    $$STIGQTER_ROOT/src/family.cpp \
    $$STIGQTER_ROOT/src/help.cpp \
    $$STIGQTER_ROOT/src/stig.cpp \
    $$STIGQTER_ROOT/src/stigcheck.cpp \
    $$STIGQTER_ROOT/src/stigedit.cpp \
    $$STIGQTER_ROOT/src/stigqter.cpp \
    $$STIGQTER_ROOT/src/supplement.cpp \
    $$STIGQTER_ROOT/src/tabviewwidget.cpp \
    $$STIGQTER_ROOT/src/worker.cpp \
    $$STIGQTER_ROOT/src/workerassetadd.cpp \
    $$STIGQTER_ROOT/src/workerassetdelete.cpp \
    $$STIGQTER_ROOT/src/workercciadd.cpp \
    $$STIGQTER_ROOT/src/workerccidelete.cpp \
    $$STIGQTER_ROOT/src/workercheckversion.cpp \
    $$STIGQTER_ROOT/src/workerckl.cpp \
    $$STIGQTER_ROOT/src/workercklb.cpp \
    $$STIGQTER_ROOT/src/workercklexport.cpp \
    $$STIGQTER_ROOT/src/workercklimport.cpp \
    $$STIGQTER_ROOT/src/workercklupgrade.cpp \
    $$STIGQTER_ROOT/src/workercmrsexport.cpp \
    $$STIGQTER_ROOT/src/workeremassreport.cpp \
    $$STIGQTER_ROOT/src/workerfindingsreport.cpp \
    $$STIGQTER_ROOT/src/workerhtml.cpp \
    $$STIGQTER_ROOT/src/workerimportemass.cpp \
    $$STIGQTER_ROOT/src/workerimportemasscontrol.cpp \
    $$STIGQTER_ROOT/src/workermapunmapped.cpp \
    $$STIGQTER_ROOT/src/workerpoamreport.cpp \
    $$STIGQTER_ROOT/src/workerstigadd.cpp \
    $$STIGQTER_ROOT/src/workerstigdelete.cpp \
    $$STIGQTER_ROOT/src/workerstigdownload.cpp \
    $$STIGQTER_ROOT/src/workerstigexport.cpp

HEADERS += \
    $$STIGQTER_ROOT/src/asset.h \
    $$STIGQTER_ROOT/src/assetview.h \
    $$STIGQTER_ROOT/src/cci.h \
    $$STIGQTER_ROOT/src/cklcheck.h \
    $$STIGQTER_ROOT/src/common.h \
    $$STIGQTER_ROOT/src/control.h \
    $$STIGQTER_ROOT/src/dbmanager.h \
    $$STIGQTER_ROOT/src/family.h \
    $$STIGQTER_ROOT/src/help.h \
    $$STIGQTER_ROOT/src/stig.h \
    $$STIGQTER_ROOT/src/stigcheck.h \
    $$STIGQTER_ROOT/src/stigedit.h \
    $$STIGQTER_ROOT/src/stigqter.h \
    $$STIGQTER_ROOT/src/supplement.h \
    $$STIGQTER_ROOT/src/tabviewwidget.h \
    $$STIGQTER_ROOT/src/worker.h \
    $$STIGQTER_ROOT/src/workerassetadd.h \
    $$STIGQTER_ROOT/src/workerassetdelete.h \
    $$STIGQTER_ROOT/src/workercciadd.h \
    $$STIGQTER_ROOT/src/workerccidelete.h \
    $$STIGQTER_ROOT/src/workercheckversion.h \
    $$STIGQTER_ROOT/src/workerckl.h \
    $$STIGQTER_ROOT/src/workercklb.h \
    $$STIGQTER_ROOT/src/workercklexport.h \
    $$STIGQTER_ROOT/src/workercklimport.h \
    $$STIGQTER_ROOT/src/workercklupgrade.h \
    $$STIGQTER_ROOT/src/workercmrsexport.h \
    $$STIGQTER_ROOT/src/workeremassreport.h \
    $$STIGQTER_ROOT/src/workerfindingsreport.h \
    $$STIGQTER_ROOT/src/workerhtml.h \
    $$STIGQTER_ROOT/src/workerimportemass.h \
    $$STIGQTER_ROOT/src/workerimportemasscontrol.h \
    $$STIGQTER_ROOT/src/workermapunmapped.h \
    $$STIGQTER_ROOT/src/workerpoamreport.h \
    $$STIGQTER_ROOT/src/workerstigadd.h \
    $$STIGQTER_ROOT/src/workerstigdelete.h \
    $$STIGQTER_ROOT/src/workerstigdownload.h \
    $$STIGQTER_ROOT/src/workerstigexport.h

FORMS += \
    $$STIGQTER_ROOT/src/assetview.ui \
    $$STIGQTER_ROOT/src/help.ui \
    $$STIGQTER_ROOT/src/stigedit.ui \
    $$STIGQTER_ROOT/src/stigqter.ui

SOURCES += $$STIGQTER_ROOT/src/download.cpp $$STIGQTER_ROOT/src/releasemetadata.cpp
HEADERS += $$STIGQTER_ROOT/src/download.h $$STIGQTER_ROOT/src/releasemetadata.h

isEmpty(STIGQTER_STATIC_DEPS) {
    LIBS += -lzip -lxlsxwriter -lz
} else {
    INCLUDEPATH += $$STIGQTER_STATIC_DEPS/include
    LIBS += $$STIGQTER_STATIC_DEPS/lib/libxlsxwriter.a $$STIGQTER_STATIC_DEPS/lib/libzip.a \
            $$STIGQTER_STATIC_DEPS/lib/libz.a $$STIGQTER_STATIC_DEPS/lib/libssl.a \
            $$STIGQTER_STATIC_DEPS/lib/libcrypto.a -lws2_32 -lcrypt32 -lbcrypt
}

resources.files = $$STIGQTER_ROOT/src/U_CCI_List.xml $$STIGQTER_ROOT/src/800-53-rev5-controls.xml $$STIGQTER_ROOT/src/STIGQter.svg
resources.base = $$STIGQTER_ROOT
resources.prefix = /dod
RESOURCES += resources

contains(CONFIG, coverage) {
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS += -O0 --coverage -fno-inline
    QMAKE_LFLAGS += --coverage
}

SOURCES += $$STIGQTER_ROOT/src/contentcatalog.cpp
HEADERS += $$STIGQTER_ROOT/src/contentcatalog.h

# Internal boundaries behind the existing public interfaces.
HEADERS += $$STIGQTER_ROOT/src/workerxccdf.h $$STIGQTER_ROOT/src/xccdfresults.h
SOURCES += $$STIGQTER_ROOT/src/workerxccdf.cpp $$STIGQTER_ROOT/src/xccdfresults.cpp $$STIGQTER_ROOT/src/dbmanager-assessment.cpp
SOURCES += $$STIGQTER_ROOT/src/archive.cpp \
    $$STIGQTER_ROOT/src/classification.cpp \
    $$STIGQTER_ROOT/src/dbmanager-project.cpp \
    $$STIGQTER_ROOT/src/dbmanager-schema.cpp \
    $$STIGQTER_ROOT/src/dbmanager-queries.cpp \
    $$STIGQTER_ROOT/src/dbmanager-mutations.cpp \
    $$STIGQTER_ROOT/src/cklparser.cpp \
    $$STIGQTER_ROOT/src/cklbparser.cpp

HEADERS += $$STIGQTER_ROOT/src/checklistwriter.h
SOURCES += $$STIGQTER_ROOT/src/cklwriter.cpp $$STIGQTER_ROOT/src/cklbwriter.cpp
