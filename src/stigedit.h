/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef STIGEDIT_H
#define STIGEDIT_H

#include <QWidget>

#include "stig.h"
#include "tabviewwidget.h"

namespace Ui {
class STIGEdit;
}

class STIGEdit : public TabViewWidget
{
    Q_OBJECT

public:
    STIGEdit() = delete;
    STIGEdit(const STIGEdit &se) = delete;
    explicit STIGEdit(STIG &stig, QWidget *parent = nullptr);
    void DisableInput() override;
    void EnableInput() override;
    TabType GetTabType() override;
#ifdef USE_TESTS
    virtual void RunTests() override;
#endif

private:
    Ui::STIGEdit *ui;
    STIG _s;
    void UpdateChecks();
    void UpdateSupplements();

private Q_SLOTS:
    void AddCCI();
    void SelectCheck();
    void UpdateSTIG();
    void UpdateCheck();
};

#endif // STIGEDIT_H
