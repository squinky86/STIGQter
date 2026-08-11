/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2022–2023 Jon Hood, http://www.hoodsecurity.com/
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

    STIG replacement;
    for (const STIG &s : db.GetSTIGs())
    {
        if (s != _stig && s.title == _stig.title && s.IsNewerThan(_stig) &&
            !_asset.GetSTIGs().contains(s) &&
            (replacement.id < 0 || s.IsNewerThan(replacement)))
        {
            replacement = s;
        }
    }

    if (replacement.id >= 0)
    {
        db.AddSTIGToAsset(replacement, _asset);
        db.DelayCommit(true);
        QVector<CKLCheck> oldChecks = _asset.GetCKLChecks(&_stig);
        for (CKLCheck ckl : _asset.GetCKLChecks(&replacement))
        {
            Q_EMIT updateStatus("Updating " + PrintCKLCheck(ckl) + "...");
            for (const CKLCheck &cklOld : oldChecks)
            {
                if (cklOld.GetSTIGCheck().vulnNum == ckl.GetSTIGCheck().vulnNum)
                {
                    ckl.status = cklOld.status;
                    ckl.findingDetails = cklOld.findingDetails;
                    ckl.comments = cklOld.comments;
                    ckl.severityOverride = cklOld.severityOverride;
                    ckl.severityJustification = cklOld.severityJustification;
                    db.UpdateCKLCheck(ckl);
                    Q_EMIT progress(-1);
                    break;
                }
            }
        }
        db.DelayCommit(false);
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
