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
    Asset(Asset const&& orig) noexcept;
    ~Asset() override = default;
    explicit Asset(QObject *parent = nullptr);
    Asset& operator=(const Asset &right);
    Asset& operator=(Asset &&orig) noexcept;
    QList<STIG> GetSTIGs() const;
    QList<CKLCheck> GetCKLChecks(const STIG *stig = nullptr) const;
    int id{-1}; /**< Database ID */
    QString assetType{QStringLiteral("Computing")}; /**< Specifies if asset is "Computing" or "Non-Computing" */
    QString hostName; /**< Unique asset identifier */
    QString hostIP; /**< IP address of the asset */
    QString hostMAC; /**< MAC address of the asset */
    QString hostFQDN; /**< FQDN of the asset */
    QString techArea; /**< Tech Area may be any of:
                           "" (not set)
                           "Application Review"
                           "Boundary Security"
                           "CDS Admin Review"
                           "CDS Technical Review"
                           "Database Review"
                           "Domain Name System (DNS)"
                           "Exchange Server"
                           "Host Based System Security (HBSS)"
                           "Internal Network"
                           "Mobility"
                           "Releasable Networks (REL)"
                           "Traditional Security"
                           "UNIX OS"
                           "VVOIP Review"
                           "Web Review"
                           "Windows OS"
                           "Other Review"
                       */
    QString targetKey; /**< Target identifier specified in STIG */
    bool webOrDB{false}; /**< whether the asset is a web or database asset */
    QString webDbSite; /**< If webOrDatabase is true, specify the site identifier (usually node name) */
    QString webDbInstance; /**< If webOrDatabase is true, specify the instance (usually the DB's name) */
};

Q_DECLARE_METATYPE(Asset);

QString PrintAsset(const Asset &asset);

#endif // ASSET_H
