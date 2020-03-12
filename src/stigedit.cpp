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

#include "stigedit.h"

#include "ui_stigedit.h"

/**
 * @brief STIGEdit::STIGEdit
 * @param stig
 * @param parent
 *
 * Main Constructor
 */
STIGEdit::STIGEdit(STIG &stig, QWidget *parent) : TabViewWidget (parent),
    ui(new Ui::STIGEdit)
{
    ui->setupUi(this);

    ui->txtTitle->setText(stig.title);
    ui->txtDescription->setText(stig.description);
    ui->txtVersion->setText(QString::number(stig.version));
    QString tmpRelease = stig.release;
    if (tmpRelease.contains(QStringLiteral("Release: ")))
    {
        tmpRelease = tmpRelease.right(tmpRelease.size() - 9);
        if (tmpRelease.contains(QStringLiteral(" ")))
        {
            ui->txtRelease->setText(tmpRelease.left(tmpRelease.indexOf(QStringLiteral(" "))));
        }
    }
    if (tmpRelease.contains(QStringLiteral("Date: ")))
    {
        tmpRelease = tmpRelease.right(tmpRelease.size() - tmpRelease.indexOf(QStringLiteral("Date: ")) - 6);

        QDate d = QDate::fromString(tmpRelease, QStringLiteral("dd MMM yyyy"));
        ui->date->setDate(d);
    }
}

/**
 * @brief STIGEdit::DisableInput
 *
 * Disable all button input
 */
void STIGEdit::DisableInput()
{
    ui->btnSave->setEnabled(false);
    ui->txtTitle->setEnabled(false);
    ui->txtRelease->setEnabled(false);
    ui->txtVersion->setEnabled(false);
    ui->txtDescription->setEnabled(false);
    ui->txtFindingDetails->setEnabled(false);
}

/**
 * @brief STIGEdit::EnableInput
 *
 * Enable all button input
 */
void STIGEdit::EnableInput()
{
    ui->btnSave->setEnabled(true);
    ui->txtTitle->setEnabled(true);
    ui->txtRelease->setEnabled(true);
    ui->txtVersion->setEnabled(true);
    ui->txtDescription->setEnabled(true);
    ui->txtFindingDetails->setEnabled(true);
}

/**
 * @brief STIGEdit::GetTabType
 * @return Indication that this is a STIG editing tab
 */
TabType STIGEdit::GetTabType()
{
    return TabType::stig;
}
