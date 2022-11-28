/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2022 Jon Hood, http://www.hoodsecurity.com/
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
#include "common.h"
#include "dbmanager.h"
#include "workercklupgrade.h"
#include "workerstigadd.h"

#include <QFile>
#include <QTemporaryFile>
#include <QUrlQuery>
#include <QXmlStreamReader>

/**
 * @class WorkerCKLUpgrade
 * @brief Upgrade a CKL file to a newer version
 */

/**
 * @brief WorkerCKLUpgrade::WorkerCKLUpgrade
 * @param parent
 *
 * Default constructor.
 */
WorkerCKLUpgrade::WorkerCKLUpgrade(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCKLUpgrade::AddCKLs
 * @param ckls
 *
 * Add the provided CKLs to the queue for processing.
 */
void WorkerCKLUpgrade::AddSTIG(const Asset &asset, const STIG &stig)
{
    _asset = asset;
    _stig = stig;
}

/**
 * @brief WorkerCKLUpgrade::process
 *
 * Begin cycling through the queue of CKL files to process.
 */
void WorkerCKLUpgrade::process()
{
    Worker::process();

    Q_EMIT initialize(_stig.GetSTIGChecks().count() + 1, 0);
    DbManager db;
    db.DelayCommit(true);

    Q_FOREACH (STIG s, db.GetSTIGs())
    {
        if (s != _stig)
        {
            if (
                    (s.title == _stig.title) &&
                    (
                        (s.version > _stig.version) ||
                        ((s.version == _stig.version) && (s.release.compare(_stig.release) > 0))
                    ) &&
                    (!_asset.GetSTIGs().contains(s))
                )
            {
                //found STIG to upgrade to
                db.AddSTIGToAsset(s, _asset);
                db.DelayCommit(true);
                QVector<CKLCheck> oldChecks = _asset.GetCKLChecks(&_stig);
                Q_FOREACH (CKLCheck ckl, _asset.GetCKLChecks(&s))
                {
                    Q_EMIT updateStatus("Updating " + PrintCKLCheck(ckl) + "...");
                    bool updated = false;
                    Q_FOREACH(CKLCheck cklOld, oldChecks)
                    {
                        if (cklOld.GetSTIGCheck().vulnNum == ckl.GetSTIGCheck().vulnNum)
                        {
                            ckl.status = cklOld.status;
                            ckl.findingDetails = cklOld.findingDetails;
                            ckl.comments = cklOld.comments;
                            ckl.severityOverride = cklOld.severityOverride;
                            ckl.severityJustification = cklOld.severityJustification;
                            db.UpdateCKLCheck(ckl);
                            updated = true;
                            Q_EMIT progress(-1);
                            break;
                        }
                    }
                    if (updated)
                        continue;
                }
                db.DelayCommit(false);
                break;
            }
        }
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
