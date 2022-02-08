/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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

/**
 * @class WorkerAssetAdd
 * @brief When adding an @a Asset, several database consistency
 * operations must be performed. This worker process adds the new
 * @a Asset, maps any selected @a STIG to the new @a Asset, and maps
 * each @a CKLCheck to its respective @a STIGCheck in that @a STIG.
 *
 * Due to the potentially large number of operations and mappings,
 * this process is set up as a background thread that reports its
 * progress and completion.
 */

/**
 * @brief WorkerAssetAdd::WorkerAssetAdd
 * @param parent
 *
 * Default constructor.
 */
WorkerAssetAdd::WorkerAssetAdd(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerAssetAdd::AddAsset
 * @param asset
 *
 * Add an @a Asset to the database once the worker process is
 * initialized.
 */
void WorkerAssetAdd::AddAsset(const Asset &asset)
{
    _toAdd = asset;
}

/**
 * @brief WorkerAssetAdd::AddSTIG
 * @param stig
 *
 * Add a @a STIG to be mapped once the @a Asset is added to the
 * database when the worker process is initialized.
 */
void WorkerAssetAdd::AddSTIG(const STIG &stig)
{
    _toMapSTIGs.append(stig);
}

/**
 * @brief WorkerAssetAdd::process
 *
 * Perform the operations of this worker process.
 *
 * @example process
 * @title process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerAssetAdd *addAsset = new WorkerAssetAdd();
 * addAsset->moveToThread(thread); // move the asset to the new thread
 * addAsset->AddAsset(asset); // "asset" is an instance of an Asset that will be added to the DB
 * addAsset->AddSTIG(stig); // "stig" is an instance of a STIG that will be mapped to the new "asset" once it's inserted into the database.
 * connect(thread, SIGNAL(started()), addAsset, SLOT(process())); // Start the worker when the new thread emits its started() signal.
 * connect(addAsset, SIGNAL(finished()), thread, SLOT(quit())); // Kill the thread once the worker emits its finished() signal.
 * connect(thread, SIGNAL(finished()), this, SLOT(EndFunction()));  // execute some EndFunction() (custom code) when the thread is cleaned up.
 * connect(addAsset, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int))); // If progress status is needed, connect a custom Initialize(int, int) function to the initialize slot.
 * connect(addAsset, SIGNAL(progress(int)), this, SLOT(Progress(int))); // If progress status is needed, connect the progress slot to a custom Progress(int) function.
 * connect(addAsset, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString))); // If progress status is needed, connect a human-readable display of the status to the updateStatus(QString) slot.
 * t->start(); // Start the thread
 *
 * //Don't forget to handle the *thread and *addAsset cleanup!
 * @endcode
 */
void WorkerAssetAdd::process()
{
    Worker::process();

    DbManager db;
    //get the list of STIGs to add to this asset
    Q_EMIT initialize(_toMapSTIGs.count() + 1, 0);

    //add asset to DB
    Asset a;
    a.hostName = _toAdd.hostName;
    if (db.AddAsset(a))
    {
        Q_EMIT updateStatus("Adding asset " + PrintAsset(a));
        Q_EMIT progress(-1);
        //loop through STIGs and add to new asset
        Q_FOREACH(STIG s, _toMapSTIGs)
        {
            Q_EMIT updateStatus("Adding " + PrintSTIG(s) + " to " + PrintAsset(a) + "…");
            db.AddSTIGToAsset(s, a);
            Q_EMIT progress(-1);
        }
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
