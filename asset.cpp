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

#include "asset.h"
#include "dbmanager.h"

Asset::Asset(const Asset &a) : Asset(a.parent())
{
    *this = a;
}

Asset::Asset(QObject *parent) : QObject(parent)
{
    id = -1;
}

Asset &Asset::operator=(const Asset &right)
{
    if (this != &right)
    {
        id = right.id;
        assetType = right.assetType;
        hostName = right.hostName;
        hostIP = right.hostIP;
        hostMAC = right.hostMAC;
        hostFQDN = right.hostFQDN;
        techArea = right.techArea;
        targetKey = right.targetKey;
        webOrDB = right.webOrDB;
        webDbSite = right.webDbSite;
        webDbInstance = right.webDbInstance;
    }
    return *this;
}

QList<STIG> Asset::STIGs()
{
    DbManager db;
    return db.GetSTIGs(*this);
}

QString PrintAsset(Asset a)
{
    return a.hostName;
}
