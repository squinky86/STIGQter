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

#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"

STIG::STIG(QObject *parent) : QObject(parent),
    id(-1),
    title(),
    description(),
    release(),
    version(0),
    benchmarkId(),
    fileName()
{
}

QList<STIGCheck> STIG::STIGChecks() const
{
    DbManager db;
    return db.GetSTIGChecks(*this);
}

QList<Asset> STIG::Assets() const
{
    DbManager db;
    return db.GetAssets(*this);
}

STIG::STIG(const STIG &right) : STIG(right.parent())
{
    *this = right;
}

STIG &STIG::operator=(const STIG &right)
{
    if (this != &right)
    {
        id = right.id;
        title = right.title;
        description = right.description;
        release = right.release;
        version = right.version;
        benchmarkId = right.benchmarkId;
        fileName = right.fileName;
    }
    return *this;
}

bool STIG::operator==(const STIG &right)
{
    if ((id <= 0) || (right.id <= 0))
    {
        return ((title == right.title) &&
                // (description == right.description) && // description is irrelevant to a STIG being the same; the version numbers are what matter!
                (release == right.release) &&
                (version == right.version));
    }
    return id == right.id;
}

QString PrintSTIG(const STIG &stig)
{
    return stig.title + " Version: " + QString::number(stig.version) + " " + stig.release;
}
