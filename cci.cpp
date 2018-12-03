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

#include "cci.h"

#include <QDebug>

QString PrintCCI(CCI c)
{
    return "CCI-" + QString::number(c.cci).rightJustified(6, '0');
}

CCI::CCI() : QObject()
{

}

CCI::CCI(const CCI &right) : CCI()
{
    *this = right;
}

CCI& CCI::operator=(const CCI &right)
{
    if (this != &right)
    {
        id = right.id;
        control = right.control;
        cci = right.cci;
        definition = right.definition;
    }
    return *this;
}
