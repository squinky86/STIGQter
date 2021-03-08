/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021 Jon Hood, http://www.hoodsecurity.com/
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
#include "workerassetdelete.h"

#include <QMap>

/**
 * @class WorkerAssetDelete
 * @brief Remove @a Assets from the internal database.
 *
 * Assets are removed from the internal database.
 */

/**
 * @brief WorkerAssetDelete::WorkerAssetDelete
 * @param parent
 *
 * Default constructor.
 */
WorkerAssetDelete::WorkerAssetDelete(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerSTIGDelete::AddAssets
 * @param assets
 *
 * Provide the Assets to delete.
 */
void WorkerAssetDelete::AddAssets(const QVector<Asset> &assets)
{
    _assets.append(assets);
}

/**
 * @brief WorkerSTIGDelete::AddAsset
 * @param asset
 *
 * Provide the Assets to delete.
 */
void WorkerAssetDelete::AddAsset(const Asset &asset)
{
    _assets.append(asset);
}

/**
 * @brief WorkerSTIGDelete::process
 *
 * Loop through the provided IDs and remove them from the database.
 */
void WorkerAssetDelete::process()
{
    Worker::process();

    //open database in this thread
    Q_EMIT initialize(2 + _assets.count(), 1);
    DbManager db;

    Q_EMIT updateStatus(QStringLiteral("Deleting Assets…"));
    db.DelayCommit(true);
    int numChecks = 0;

    QMap<Asset, QVector<STIG>> toDelete;

    Q_FOREACH (Asset a, _assets)
    {
        //don't double-delete assets that were double-added
        if (toDelete.keys().contains(a))
            continue;

        toDelete.insert(a, a.GetSTIGs());
        numChecks += toDelete.value(a).count();
    }

    Q_EMIT initialize(2 + _assets.count() + numChecks, 1);
    Q_EMIT progress(-1);

    Q_FOREACH (Asset a, toDelete.keys())
    {
        Q_EMIT updateStatus(QStringLiteral("Deleting Asset ") + PrintAsset(a) + QStringLiteral("…"));
        //remove all associated STIGs from this asset.
        Q_FOREACH (const STIG &s, toDelete.value(a))
        {
            db.DeleteSTIGFromAsset(s, a);
            Q_EMIT progress(-1);
        }
        db.DeleteAsset(a);
        Q_EMIT progress(-1);
    }
    db.DelayCommit(false);
    Q_EMIT progress(-1);

    //complete
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
