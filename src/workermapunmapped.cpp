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
WorkerMapUnmapped::WorkerMapUnmapped(QObject *parent) : Worker(parent)
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
    QVector<STIGCheck> stigchecks = db.GetSTIGChecks();
    Q_EMIT initialize(stigchecks.count(), 0);

    QVector<CCI> remapCCIs = db.GetRemapCCIs();
    QVector<int> remapCCIIds;
    Q_FOREACH (CCI c, remapCCIs)
    {
        remapCCIIds.append(c.id);
    }

    Q_FOREACH (STIGCheck check, stigchecks)
    {
        //Q_EMIT updateStatus(QStringLiteral("Checking ") + PrintSTIGCheck(check) + QStringLiteral("…"));
        bool updateCheck = false;

        //step one - see if this STIG Check is already an imported one
        if (check.isRemap)
        {
            check.cciIds.clear();
        }
        else
        {

            //step two - make sure that each of the CCIs are in the import
            Q_FOREACH (CCI c, check.GetCCIs())
            {
                if (!c.isImport)
                {
                    check.cciIds.removeAll(c.id);
                    updateCheck = true;
                }
            }
        }

        //step three - remap to CM-6
        if (check.cciIds.count() <= 0)
        {
            Q_FOREACH (CCI c, remapCCIs)
            {
                check.cciIds.append(c.id);
            }
            check.isRemap = true;
            updateCheck = true;
        }

        //step four - write the changes
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
