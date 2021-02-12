/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
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
#include "cklcheck.h"
#include "dbmanager.h"

/**
 * @class Asset
 * @brief An Asset is a single node, database, or element that would
 * usually be represented by an entry in a system's hardware/software
 * list.
 *
 * An Asset is a way to group checklist files in a logical way.
 * Projects may have many assets, and an asset may contain many
 * checklists.
 *
 * Once an asset has been created, the individual checklists for that
 * asset are selected. An asset may contain only unique checklists.
 * For example, the asset "Computer 1" containing Windows 10 would
 * only contain one checklist for Windows 10. When the example asset
 * contains multiple installations of Windows 10 (such as may be the
 * case for a multi-boot system), the differing installations should
 * be given unique asset names (and be seen as separate assets).
 */

/**
 * @brief Asset::Asset
 * @param parent
 *
 * The default constructor sets up an empty Asset.
 */
Asset::Asset(QObject *parent) : QObject(parent)
{
}

/**
 * @brief Asset::Asset
 * @param asset
 *
 * Copy constructor.
 */
Asset::Asset(const Asset &asset) : Asset(asset.parent())
{
    *this = asset;
}

/**
 * @brief Asset::Asset
 * @param asset
 *
 * Move constructor.
 */
Asset::Asset(Asset &&orig) noexcept :
    id(orig.id),
    assetType(std::move(orig.assetType)),
    hostName(std::move(orig.hostName)),
    hostIP(std::move(orig.hostIP)),
    hostMAC(std::move(orig.hostMAC)),
    hostFQDN(std::move(orig.hostFQDN)),
    techArea(std::move(orig.techArea)),
    targetKey(std::move(orig.targetKey)),
    webOrDB(orig.webOrDB),
    webDbSite(std::move(orig.webDbSite)),
    webDbInstance(std::move(orig.webDbInstance))
{
}

/**
 * @brief Asset::operator=
 * @param right
 * @return copied Asset
 */
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

Asset &Asset::operator=(Asset &&orig) noexcept
{
    if (this != &orig)
    {
        id = orig.id;
        assetType = std::move(orig.assetType);
        hostName = std::move(orig.hostName);
        hostIP = std::move(orig.hostIP);
        hostMAC = std::move(orig.hostMAC);
        hostFQDN = std::move(orig.hostFQDN);
        techArea = std::move(orig.techArea);
        targetKey = std::move(orig.targetKey);
        webOrDB = orig.webOrDB;
        webDbSite = std::move(orig.webDbSite);
        webDbInstance = std::move(orig.webDbInstance);
    }
    return *this;
}

/**
 * @brief Asset::GetSTIGs
 * @return list of STIGs associated with this Asset
 */
QVector<STIG> Asset::GetSTIGs() const
{
    DbManager db;
    return db.GetSTIGs(*this);
}

/**
 * @brief Asset::GetCKLChecks
 * @param stig
 * @return list of CKLChecks associated with this Asset
 *
 * When @a stig is a nullptr, all CKL checks associated with all
 * STIGs mapped to this Asset are returned.
 */
QVector<CKLCheck> Asset::GetCKLChecks(const STIG *stig) const
{
    DbManager db;
    return db.GetCKLChecks(*this, stig);
}

/**
 * @brief PrintAsset
 * @param asset
 * @return human-readable Asset description
 */
QString PrintAsset(const Asset &asset)
{
    return asset.hostName;
}
