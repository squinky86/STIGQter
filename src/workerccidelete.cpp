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

#include "workerccidelete.h"
#include "common.h"
#include "dbmanager.h"

/**
 * @class WorkerCCIDelete
 * @brief Deleting the data indexed by the @a WorkerCCIAdd task is
 * performed by this background worker.
 *
 * This class resets the database to a state before a @a CCI is
 * indexed.
 */

/**
 * @brief WorkerCCIDelete::WorkerCCIDelete
 * @param parent
 *
 * Default constructor.
 */
WorkerCCIDelete::WorkerCCIDelete(QObject *parent) : QObject(parent)
{
}

/**
 * @brief WorkerCCIDelete::process
 *
 * Delete the @a CCI and @a Control information from the database.
 */
void WorkerCCIDelete::process()
{
    //open database in this thread
    Q_EMIT initialize(2, 1);
    DbManager db;

    Q_EMIT updateStatus(QStringLiteral("Clearing DB of CCI/RMF information…"));
    db.DeleteCCIs();
    Q_EMIT progress(-1);

    //complete
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
