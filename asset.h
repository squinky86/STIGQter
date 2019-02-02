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

#ifndef ASSET_H
#define ASSET_H

#include <QList>
#include <QObject>
#include <QString>

#include "stig.h"

class CKLCheck;

class Asset : public QObject
{
    Q_OBJECT
public:
    Asset(const Asset &asset);
    explicit Asset(QObject *parent = nullptr);
    Asset& operator=(const Asset &right);
    QList<STIG> STIGs() const;
    QList<CKLCheck> CKLChecks(const STIG *stig = nullptr) const;
    int id;
    QString assetType;
    QString hostName;
    QString hostIP;
    QString hostMAC;
    QString hostFQDN;
    QString techArea;
    QString targetKey;
    bool webOrDB;
    QString webDbSite;
    QString webDbInstance;
};

Q_DECLARE_METATYPE(Asset);

QString PrintAsset(const Asset &asset);

#endif // ASSET_H
