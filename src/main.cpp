/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "stigqter.h"

#include <QApplication>
#include <QIcon>
#include <QPalette>
#include <QStyleFactory>

/**
 * @brief ApplyTheme
 * @param a
 *
 * Give STIGQter a consistent, modern look across every platform. The
 * Fusion style plus a curated light palette means the application looks
 * the same whether it runs on Windows, Linux, or elsewhere, and it
 * complements the DoD classification banners (which set their own inline
 * colors and therefore override anything here). A light-touch stylesheet
 * adds padding, rounded controls, group-box framing, and an accent color
 * for the primary workflow buttons. No technical information is hidden or
 * removed by any of this — it is purely presentational.
 */
static void ApplyTheme(QApplication &a)
{
    if (QStyleFactory::keys().contains(QStringLiteral("Fusion")))
        a.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    //curated, neutral light palette (blue accent) for a predictable look
    QPalette p;
    p.setColor(QPalette::Window,          QColor(0xF5, 0xF6, 0xF8));
    p.setColor(QPalette::WindowText,      QColor(0x1C, 0x1E, 0x21));
    p.setColor(QPalette::Base,            QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::AlternateBase,   QColor(0xEF, 0xF1, 0xF4));
    p.setColor(QPalette::Text,            QColor(0x1C, 0x1E, 0x21));
    p.setColor(QPalette::Button,          QColor(0xF2, 0xF4, 0xF6));
    p.setColor(QPalette::ButtonText,      QColor(0x1C, 0x1E, 0x21));
    p.setColor(QPalette::ToolTipBase,     QColor(0x2B, 0x2F, 0x36));
    p.setColor(QPalette::ToolTipText,     QColor(0xF5, 0xF6, 0xF8));
    p.setColor(QPalette::Highlight,       QColor(0x2D, 0x6C, 0xDF));
    p.setColor(QPalette::HighlightedText, QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Link,            QColor(0x2D, 0x6C, 0xDF));
    p.setColor(QPalette::Disabled, QPalette::Text,       QColor(0x9A, 0xA0, 0xA6));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(0x9A, 0xA0, 0xA6));
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(0x9A, 0xA0, 0xA6));
    a.setPalette(p);

    a.setStyleSheet(QStringLiteral(
        "QGroupBox {"
        "  font-weight: bold;"
        "  border: 1px solid #C7CCD1;"
        "  border-radius: 6px;"
        "  margin-top: 14px;"
        "  padding: 10px 8px 8px 8px;"
        "  background-color: #FBFCFD;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  subcontrol-position: top left;"
        "  left: 10px;"
        "  padding: 0 4px;"
        "  color: #2D5FA4;"
        "}"
        "QPushButton {"
        "  padding: 5px 12px;"
        "  border: 1px solid #B7BEC5;"
        "  border-radius: 5px;"
        "  background-color: #F2F4F6;"
        "}"
        "QPushButton:hover { background-color: #E6EEFB; border-color: #6F9BE0; }"
        "QPushButton:pressed { background-color: #D4E2F7; }"
        "QPushButton:disabled { color: #9AA0A6; background-color: #ECEEF0; border-color: #D7DBDF; }"
        //primary workflow actions get an accent so the next step is obvious
        "QPushButton#btnCreateCKL, QPushButton#btnOpenCKL {"
        "  background-color: #2D6CDF; color: white; border-color: #245BC0; font-weight: bold;"
        "}"
        "QPushButton#btnCreateCKL:hover, QPushButton#btnOpenCKL:hover { background-color: #3F7CEF; }"
        "QPushButton#btnCreateCKL:pressed, QPushButton#btnOpenCKL:pressed { background-color: #245BC0; }"
        "QPushButton#btnCreateCKL:disabled, QPushButton#btnOpenCKL:disabled {"
        "  background-color: #C9D3E6; color: #EEF2FA; border-color: #B9C4DA;"
        "}"
        "QListWidget, QTreeWidget, QTableWidget {"
        "  border: 1px solid #C7CCD1; border-radius: 5px; background-color: #FFFFFF;"
        "}"
        "QListWidget::item { padding: 3px 4px; }"
        "QListWidget::item:selected { background-color: #2D6CDF; color: white; }"
        "QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QDateEdit {"
        "  border: 1px solid #B7BEC5; border-radius: 5px; padding: 3px 5px; background-color: #FFFFFF;"
        "}"
        "QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus, QDateEdit:focus {"
        "  border-color: #2D6CDF;"
        "}"
        "QComboBox::drop-down { border: 0; width: 18px; }"
        "QProgressBar {"
        "  border: 1px solid #C7CCD1; border-radius: 5px; text-align: center;"
        "  background-color: #EEF0F2; min-height: 16px;"
        "}"
        "QProgressBar::chunk { background-color: #2D6CDF; border-radius: 4px; }"
        "QTabBar::tab { padding: 6px 14px; }"
        "QTabWidget::pane { border: 1px solid #C7CCD1; border-radius: 5px; top: -1px; }"
        "QToolBox::tab { background-color: #EDEFF2; border: 1px solid #C7CCD1; border-radius: 4px; padding: 4px; }"
        "QToolBox::tab:selected { background-color: #E6EEFB; color: #2D5FA4; font-weight: bold; }"
        "QToolTip { color: #F5F6F8; background-color: #2B2F36; border: 1px solid #1C1E21; padding: 4px; }"
    ));
}

int main(int argc, char *argv[])
{
    qInstallMessageHandler(MessageHandler);
    QApplication a(argc, argv);

    //application metadata (nicer native dialog titles, taskbar grouping).
    //NOTE: deliberately do NOT set an organization name — doing so changes
    //QStandardPaths::AppDataLocation (the STIGQter.db location) and would
    //orphan users' existing local databases.
    QApplication::setApplicationName(QStringLiteral("STIGQter"));
    QApplication::setApplicationDisplayName(QStringLiteral("STIGQter"));
    QApplication::setApplicationVersion(VERSION);
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/dod/STIGQter.svg")));

    ApplyTheme(a);

    STIGQter w;
    w.show();

    return a.exec();
}
