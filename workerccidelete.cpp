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

#include "workerccidelete.h"
#include "common.h"
#include "dbmanager.h"

WorkerCCIDelete::WorkerCCIDelete(QObject *parent) : QObject(parent)
{
}

void WorkerCCIDelete::process()
{
    //open database in this thread
    emit initialize(2, 1);
    DbManager db;

    emit updateStatus("Clearing DB of CCI/RMF information…");
    db.DeleteCCIs();
    emit progress(-1);

    //complete
    emit updateStatus("Done!");
    emit finished();
}
