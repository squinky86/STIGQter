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

#include "dbmanager.h"
#include "workerassetadd.h"

WorkerAssetAdd::WorkerAssetAdd(QObject *parent) : QObject(parent)
{
}

void WorkerAssetAdd::AddAsset(QString asset)
{
    _todoAsset = asset;
}

void WorkerAssetAdd::AddSTIG(STIG s)
{
    _todoSTIGs.append(s);
}

void WorkerAssetAdd::process()
{
    DbManager db;
    //get the list of STIGs to add to this asset
    emit initialize(_todoSTIGs.count() + 1, 0);

    //add asset to DB
    Asset a;
    a.hostName = _todoAsset;
    if (db.AddAsset(a))
    {
        updateStatus("Adding asset " + PrintAsset(a));
        emit progress(-1);
        //loop through STIGs and add to new asset
        foreach(STIG s, _todoSTIGs)
        {
            updateStatus("Adding " + PrintSTIG(s) + " to " + PrintAsset(a) + "…");
            db.AddSTIGToAsset(s, a);
            emit progress(-1);
        }
    }
    emit updateStatus("Done!");
    emit finished();
}
