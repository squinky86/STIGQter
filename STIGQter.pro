#-------------------------------------------------
#
# Project created by QtCreator 2018-11-04T19:47:11
#
# STIGQter - STIG fun with Qt
#
# Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

CONFIG += c++1z

SOURCES += \
    src/asset.cpp \
    src/assetview.cpp \
    src/cci.cpp \
    src/cklcheck.cpp \
    src/common.cpp \
    src/control.cpp \
    src/dbmanager.cpp \
    src/family.cpp \
    src/help.cpp \
    src/main.cpp \
    src/stig.cpp \
    src/stigcheck.cpp \
    src/stigedit.cpp \
    src/stigqter.cpp \
    src/supplement.cpp \
    src/tabviewwidget.cpp \
    src/worker.cpp \
    src/workerassetadd.cpp \
    src/workerassetdelete.cpp \
    src/workercciadd.cpp \
    src/workerccidelete.cpp \
    src/workercheckversion.cpp \
    src/workerckl.cpp \
    src/workercklexport.cpp \
    src/workercklimport.cpp \
    src/workercmrsexport.cpp \
    src/workeremassreport.cpp \
    src/workerfindingsreport.cpp \
    src/workerhtml.cpp \
    src/workerimportemass.cpp \
    src/workerimportemasscontrol.cpp \
    src/workermapunmapped.cpp \
    src/workerpoamreport.cpp \
    src/workerstigadd.cpp \
    src/workerstigdelete.cpp \
    src/workerstigdownload.cpp

HEADERS += \
    src/asset.h \
    src/assetview.h \
    src/cci.h \
    src/cklcheck.h \
    src/common.h \
    src/control.h \
    src/dbmanager.h \
    src/family.h \
    src/help.h \
    src/stig.h \
    src/stigcheck.h \
    src/stigedit.h \
    src/stigqter.h \
    src/supplement.h \
    src/tabviewwidget.h \
    src/worker.h \
    src/workerassetadd.h \
    src/workerassetdelete.h \
    src/workercciadd.h \
    src/workerccidelete.h \
    src/workercheckversion.h \
    src/workerckl.h \
    src/workercklexport.h \
    src/workercklimport.h \
    src/workercmrsexport.h \
    src/workeremassreport.h \
    src/workerfindingsreport.h \
    src/workerhtml.h \
    src/workerimportemass.h \
    src/workerimportemasscontrol.h \
    src/workermapunmapped.h \
    src/workerpoamreport.h \
    src/workerstigadd.h \
    src/workerstigdelete.h \
    src/workerstigdownload.h

FORMS += \
    src/assetview.ui \
    src/help.ui \
    src/stigedit.ui \
    src/stigqter.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = $${PREFIX}/bin
!isEmpty(target.path): INSTALLS += target

LIBS += -lzip -lxlsxwriter -lz

INCLUDEPATH = src

RC_FILE = STIGQter.rc

DISTFILES += \
    tests/emassTRImport.xlsx
