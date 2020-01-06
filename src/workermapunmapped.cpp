/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019-2020 Jon Hood, http://www.hoodsecurity.com/
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
#include "common.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "workermapunmapped.h"

#include <QDateTime>
#include <QFile>
#include <QXmlStreamWriter>

/**
 * @class WorkerMapUnmapped
 * @brief Map STIGChecks that are not part of the eMASS TRExport report to
 * CM-6, CCI-366.
 *
 * Many systems have STIGs that map against controls not included in their
 * categorization baseline or tailoring. These findings can be remapped to
 * CM-6.
 */

/**
 * @brief WorkerMapUnmapped::WorkerMapUnmapped
 * @param parent
 *
 * Default constructor.
 */
WorkerMapUnmapped::WorkerMapUnmapped(QObject *parent) : QObject(parent)
{
}

/**
 * @brief WorkerMapUnmapped::process
 *
 * Cycle through every STIGCheck and make sure each is mapped against an
 * RMF control that's in use in eMASS.
 */
void WorkerMapUnmapped::process()
{
    Q_EMIT updateStatus(QStringLiteral("Enumerating STIG Checks…"));
    DbManager db;
    QList<STIGCheck> stigchecks = db.GetSTIGChecks();
    Q_EMIT initialize(stigchecks.count(), 0);

    CCI cci366 = db.GetCCIByCCI(366);

    Q_FOREACH (STIGCheck check, stigchecks)
    {
        Q_EMIT updateStatus(QStringLiteral("Checking ") + PrintSTIGCheck(check) + QStringLiteral("…"));
        bool updateCheck = false;
        //if the associated CCI was not imported in the eMASS import, remap to CM-6, CCI-366.
        Q_FOREACH (CCI c, check.GetCCIs())
        {
            if (!c.isImport)
            {
                check.cciIds.removeOne(c.id);
                updateCheck = true;
            }
        }
        if (check.cciIds.count() <= 0)
        {
            check.cciIds.append(cci366.id);
            updateCheck = true;
        }
        if (updateCheck)
        {
            Q_EMIT updateStatus(QStringLiteral("Updating mapping for ") + PrintSTIGCheck(check) + QStringLiteral("…"));
            db.UpdateSTIGCheck(check);
        }
        Q_EMIT progress(-1);
    }

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
