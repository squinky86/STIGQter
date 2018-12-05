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

#include "stig.h"
#include "stigcheck.h"

QString PrintSTIG(STIG s)
{
    return s.title + " Version: " + QString::number(s.version) + " " + s.release;
}

STIG::STIG(QObject *parent) : QObject(parent)
{
}

STIG::STIG(const STIG &right) : STIG(right.parent())
{
    *this = right;
}

STIG::~STIG()
{
    //clean up the STIGChecks
    foreach(STIGCheck *c, checks)
        delete c;
}

void STIG::SetValues(const STIG &right, bool deepCopy)
{
    id = right.id;
    title = right.title;
    description = right.description;
    release = right.release;
    version = right.version;

    if (deepCopy)
    {
        //delete old checks
        foreach(STIGCheck* c, checks)
        {
            delete c;
        }

        //copy new checks
        foreach(STIGCheck* c, right.checks)
        {
            STIGCheck *tmpCheck = new STIGCheck(*c);
            checks.append(tmpCheck);
        }
    }

    QList<STIGCheck*> checks;
    void SetValues(const STIG &right);
}

STIG &STIG::operator=(const STIG &right)
{
    if (this != &right)
    {
        SetValues(right, false);
    }
    return *this;
}
