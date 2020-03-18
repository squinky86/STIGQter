/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020 Jon Hood, http://www.hoodsecurity.com/
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

#include "tabviewwidget.h"

#include <QApplication>

/**
 * @brief TabViewWidget::TabViewWidget
 * @param parent
 *
 * Main Constructor
 */
TabViewWidget::TabViewWidget(QWidget *parent) : QWidget(parent),
    _tabIndex(-1),
    _parent(dynamic_cast<STIGQter *>(parent))
{
    connect(this, SIGNAL(CloseTab(int)), _parent, SLOT(CloseTab(int)));
    connect(this, SIGNAL(RenameTab(int, QString)), _parent, SLOT(RenameTab(int, QString)));
}

/**
 * @brief TabViewWidget::SetTabIndex
 * @param index
 *
 * Keep up with which index this tab is in the interface.
 */
void TabViewWidget::SetTabIndex(int index)
{
    _tabIndex = index;
}

/**
 * @brief TabViewWidget::GetTabType
 * @return What type of tab this is (main, Asset, or STIG)
 */
TabType TabViewWidget::GetTabType()
{
    return TabType::root;
}

/**
 * @brief TabViewWidget::DisableInput
 *
 * Override this function to disable user input
 */
void TabViewWidget::DisableInput()
{
}

/**
 * @brief TabViewWidget::DisableInput
 *
 * Override this function to enable user input
 */
void TabViewWidget::EnableInput()
{
}

#ifdef USE_TESTS
/**
 * @brief TabViewWidget::ProcEvents
 *
 * Override to execute run-time tests.
 */
void TabViewWidget::ProcEvents()
{
    while (!_parent->isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }
    QApplication::processEvents();
}

/**
 * @brief TabViewWidget::RunTests
 *
 * Override to execute run-time tests.
 */
void TabViewWidget::RunTests()
{
}
#endif
