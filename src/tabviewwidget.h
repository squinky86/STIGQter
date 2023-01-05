/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2023 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef TABVIEWWIDGET_H
#define TABVIEWWIDGET_H

#include <QWidget>

#include "stigqter.h"

enum TabType
{
    stig = 2,
    asset = 1,
    root = 0
};

class TabViewWidget : public QWidget
{
    Q_OBJECT
public:
    explicit TabViewWidget(QWidget *parent = nullptr);
    void SetTabIndex(int index);
    virtual TabType GetTabType();
    virtual void DisableInput();
    virtual void EnableInput();
#ifdef USE_TESTS
    void ProcEvents();
    virtual void RunTests();
#endif

protected:
    int _tabIndex;
    STIGQter *_parent;

Q_SIGNALS:
    void CloseTab(int);
    void RenameTab(int, QString);
};

#endif // TABVIEWWIDGET_H
