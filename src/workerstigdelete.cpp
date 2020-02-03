/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2020 Jon Hood, http://www.hoodsecurity.com/
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
#include "workerstigdelete.h"

/**
 * @class WorkerSTIGDelete
 * @brief Remove STIGs and SRGs from the internal database.
 *
 * STIG and SRG IDs are provided and removed from the database.
 */

/**
 * @brief WorkerSTIGDelete::WorkerSTIGDelete
 * @param parent
 *
 * Default constructor.
 */
WorkerSTIGDelete::WorkerSTIGDelete(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerSTIGDelete::AddId
 * @param id
 *
 * Provide the IDs to delete.
 */
void WorkerSTIGDelete::AddId(int id)
{
    _ids.append(id);
}

/**
 * @brief WorkerSTIGDelete::process
 *
 * Loop through the provided IDs and remove them from the database.
 */
void WorkerSTIGDelete::process()
{
    //open database in this thread
    Q_EMIT initialize(2 + _ids.count(), 1);
    DbManager db;

    Q_EMIT updateStatus(QStringLiteral("Clearing DB of selected STIG information…"));
    db.DelayCommit(true);
    Q_FOREACH (int i, _ids)
    {
        db.DeleteSTIG(i);
        Q_EMIT progress(-1);
    }
    db.DelayCommit(false);
    Q_EMIT progress(-1);

    //complete
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
