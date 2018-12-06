/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018 Jon Hood, http://www.hoodsecurity.com/
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

#include "control.h"
#include "dbmanager.h"

QString PrintControl(Control c)
{
    QString ret = c.Family().acronym + "-" + QString::number(c.number);
    if (c.enhancement > 0)
        ret.append("(" + QString::number(c.enhancement) + ")");
    return ret;
}

Control::Control(QObject *parent) : QObject(parent)
{

}

Family Control::Family()
{
    DbManager db;
    return db.GetFamily(familyId);
}

Control::Control(const Control &right) : Control(right.parent())
{
    *this = right;
}

Control& Control::operator=(const Control &right)
{
    if (this != &right)
    {
        id = right.id;
        familyId = right.familyId;
        number = right.number;
        enhancement = right.enhancement;
        title = right.title;
    }
    return *this;
}
