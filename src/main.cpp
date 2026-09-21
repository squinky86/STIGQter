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

    //curated, modern light palette (indigo-blue accent, cool neutrals)
    QPalette p;
    p.setColor(QPalette::Window,          QColor(0xF3, 0xF5, 0xF9));
    p.setColor(QPalette::WindowText,      QColor(0x1F, 0x23, 0x28));
    p.setColor(QPalette::Base,            QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::AlternateBase,   QColor(0xF6, 0xF8, 0xFB));
    p.setColor(QPalette::Text,            QColor(0x1F, 0x23, 0x28));
    p.setColor(QPalette::Button,          QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::ButtonText,      QColor(0x24, 0x29, 0x2F));
    p.setColor(QPalette::ToolTipBase,     QColor(0x1F, 0x23, 0x28));
    p.setColor(QPalette::ToolTipText,     QColor(0xF3, 0xF5, 0xF9));
    p.setColor(QPalette::Highlight,       QColor(0x25, 0x63, 0xEB));
    p.setColor(QPalette::HighlightedText, QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Link,            QColor(0x25, 0x63, 0xEB));
    p.setColor(QPalette::Disabled, QPalette::Text,       QColor(0xAE, 0xB6, 0xC2));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(0xAE, 0xB6, 0xC2));
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(0xAE, 0xB6, 0xC2));
    a.setPalette(p);

    // Cohesive modern stylesheet. Cards on a cool-grey canvas, one indigo
    // accent, soft borders, slim rounded scrollbars, and a pill progress bar.
    // Layout dimensions are unchanged (nothing here grows spacing); slim
    // scrollbars actually reclaim a little horizontal room. Classification
    // banners set their own inline style and override this.
    a.setStyleSheet(QStringLiteral(
        "QGroupBox {"
        "  font-weight: 600;"
        "  border: 1px solid #E3E8EF;"
        "  border-radius: 8px;"
        "  margin-top: 13px;"
        "  padding: 2px 6px 3px 6px;"
        "  background-color: #FFFFFF;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  subcontrol-position: top left;"
        "  left: 10px;"
        "  padding: 1px 6px;"
        "  color: #1D4ED8;"
        "}"
        "QPushButton {"
        "  padding: 5px 12px;"
        "  border: 1px solid #D0D7DE;"
        "  border-radius: 6px;"
        "  background-color: #FFFFFF;"
        "  color: #24292F;"
        "}"
        "QPushButton:hover { background-color: #F0F5FF; border-color: #6B9BF0; }"
        "QPushButton:pressed { background-color: #E3EDFD; }"
        "QPushButton:disabled { color: #AEB6C2; background-color: #F4F6F9; border-color: #E7EBF1; }"
        //primary workflow actions get the accent so the next step is obvious
        "QPushButton#btnCreateCKL, QPushButton#btnOpenCKL {"
        "  background-color: #2563EB; color: white; border: 1px solid #1D4ED8; font-weight: 600;"
        "}"
        "QPushButton#btnCreateCKL:hover, QPushButton#btnOpenCKL:hover { background-color: #3B76F0; }"
        "QPushButton#btnCreateCKL:pressed, QPushButton#btnOpenCKL:pressed { background-color: #1D4ED8; }"
        "QPushButton#btnCreateCKL:disabled, QPushButton#btnOpenCKL:disabled {"
        "  background-color: #BCD0F5; color: #EAF1FD; border-color: #BCD0F5;"
        "}"
        "QListWidget, QTreeWidget, QTableWidget {"
        "  border: 1px solid #E3E8EF; border-radius: 8px; background-color: #FFFFFF;"
        "  alternate-background-color: #F6F8FB; outline: 0;"
        "}"
        "QListWidget::item { padding: 2px 4px; border-radius: 4px; }"
        "QListWidget::item:hover { background-color: #EEF3FC; }"
        "QListWidget::item:selected { background-color: #2563EB; color: white; }"
        "QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QDateEdit {"
        "  border: 1px solid #D0D7DE; border-radius: 6px; padding: 4px 7px; background-color: #FFFFFF;"
        "  selection-background-color: #2563EB; selection-color: #FFFFFF;"
        "}"
        "QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus, QDateEdit:focus {"
        "  border: 1px solid #2563EB;"
        "}"
        "QComboBox::drop-down { border: 0; width: 18px; }"
        "QProgressBar {"
        "  border: 0; border-radius: 5px; text-align: center;"
        "  background-color: #E6EAF0; min-height: 14px; max-height: 14px; color: #1F2328;"
        "}"
        "QProgressBar::chunk { background-color: #2563EB; border-radius: 5px; }"
        "QTabWidget::pane { border: 1px solid #E3E8EF; border-radius: 8px; top: -1px; background: #FFFFFF; }"
        "QTabBar::tab {"
        "  padding: 6px 16px; margin-right: 2px; color: #4B5563; background: #EAEEF4;"
        "  border: 1px solid #E3E8EF; border-bottom: none;"
        "  border-top-left-radius: 6px; border-top-right-radius: 6px;"
        "}"
        "QTabBar::tab:hover { background: #F2F6FC; }"
        "QTabBar::tab:selected { background: #FFFFFF; color: #1D4ED8; font-weight: 600; }"
        "QToolBox::tab { background-color: #EAEEF4; border: 1px solid #E3E8EF; border-radius: 6px; padding: 5px; color: #4B5563; }"
        "QToolBox::tab:selected { background-color: #EEF3FC; color: #1D4ED8; font-weight: 600; }"
        "QMenuBar { background-color: #FFFFFF; border-bottom: 1px solid #E3E8EF; }"
        "QMenuBar::item { padding: 5px 10px; background: transparent; border-radius: 4px; }"
        "QMenuBar::item:selected { background: #EEF3FC; color: #1D4ED8; }"
        "QMenu { background-color: #FFFFFF; border: 1px solid #D0D7DE; border-radius: 6px; padding: 4px; }"
        "QMenu::item { padding: 5px 24px 5px 20px; border-radius: 4px; }"
        "QMenu::item:selected { background-color: #2563EB; color: white; }"
        "QMenu::separator { height: 1px; background: #E3E8EF; margin: 4px 8px; }"
        "QScrollBar:vertical { background: transparent; width: 11px; margin: 2px; }"
        "QScrollBar::handle:vertical { background: #C3CBD6; border-radius: 5px; min-height: 26px; }"
        "QScrollBar::handle:vertical:hover { background: #A7B2C2; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }"
        "QScrollBar:horizontal { background: transparent; height: 11px; margin: 2px; }"
        "QScrollBar::handle:horizontal { background: #C3CBD6; border-radius: 5px; min-width: 26px; }"
        "QScrollBar::handle:horizontal:hover { background: #A7B2C2; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }"
        "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }"
        "QToolTip { color: #F3F5F9; background-color: #1F2328; border: 1px solid #1F2328; border-radius: 4px; padding: 4px 6px; }"
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
