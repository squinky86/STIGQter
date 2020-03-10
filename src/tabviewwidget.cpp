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

/**
 * @brief TabViewWidget::TabViewWidget
 * @param parent
 *
 * Main Constructor
 */
TabViewWidget::TabViewWidget(QWidget *parent) : QWidget(parent), _tabIndex(-1)
{

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
