/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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

#include "family.h"

Family::Family(QObject *parent) : QObject(parent),
    id(-1),
    acronym(QStringLiteral("ZZ")),
    description(QStringLiteral("Default Family"))
{
}

Family::Family(const Family &right) : Family(right.parent())
{
    *this = right;
}

Family& Family::operator=(const Family &right)
{
    if (this != &right)
    {
        id = right.id;
        acronym = right.acronym;
        description = right.description;
    }
    return *this;
}

QString PrintFamily(const Family &c)
{
    return c.acronym;
}
