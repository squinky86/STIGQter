/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2022 Jon Hood, http://www.hoodsecurity.com/
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

#include "common.h"
#include "dbmanager.h"
#include "workerckl.h"
#include "workercklexport.h"

#include <QDir>
#include <QThread>
#include <QXmlStreamWriter>

/**
 * @class WorkerCKLExport
 * @brief Export a STIG Viewer-compatible version of the results in a
 * CKL file.
 *
 * Many systems and tools require data in a CKL file containing
 * @a STIG @a CKLCheck data. This background worker takes a directory
 * as input and generates individual CKL files for each @a Asset ↔
 * @a STIG relationship.
 *
 * To comply with eMASS' Asset Manager, only unique mappings between
 * @a Asset and @a STIG are allowed.
 */

/**
 * @brief WorkerCKLExport::WorkerCKLExport
 * @param parent
 *
 * Default constructor.
 */
WorkerCKLExport::WorkerCKLExport(QObject *parent) : Worker(parent),
    _assetName(),
    _monolithic(false)
{
}

/**
 * @brief WorkerCKLExport::SetAssetName
 * @param assetName
 *
 * Set the asset name for the CKLs that will be exported.
 */
void WorkerCKLExport::SetAssetName(const QString &assetName)
{
    _assetName = assetName;
}

/**
 * @brief WorkerCKLExport::SetExportDir
 * @param dir
 *
 * Set the output directory. This is the directory where all of the
 * individual CKL files will be exported to.
 */
void WorkerCKLExport::SetExportDir(const QString &dir)
{
    _dirName = dir;
}

/**
 * @brief WorkerCKLExport::SetMonolithic
 * @param monolithic
 *
 * Sets whether the CKL files will be monolithic (per Asset) or
 * not (per-STIG).
 */
void WorkerCKLExport::SetMonolithic(const bool monolithic)
{
    _monolithic = monolithic;
}

/**
 * @brief WorkerCKLExport::process
 *
 * Using the provided output directory of SetExportDir(), generate
 * a STIG CKL file for every @a Asset when set to monolithic mode,
 * or generate every combination of @a Asset ↔ @a STIG mapping
 * stored in the database and build individual CKL files for each
 * mapping.
 */
void WorkerCKLExport::process()
{
    Worker::process();
    Q_EMIT updateStatus(QStringLiteral("Building CKL Files…"));

    //append all assets (or a single-provided asset) to the list to generate
    DbManager db;
    QVector<Asset> assets;
    if (_assetName.isEmpty())
    {
        assets.append(db.GetAssets());
    }
    else
    {
        assets.append(db.GetAsset(_assetName));
    }

    //build a new thread for each CKL file to generate
    Q_EMIT initialize(assets.count(), 0);

    Q_FOREACH (Asset a, assets)
    {
        Q_EMIT updateStatus("Building CKL Files for " + PrintAsset(a) + "…");
        //monolithic - one CKL file per asset
        if (_monolithic)
        {
            WorkerCKL wc;
            wc.AddFilename(QDir(_dirName).filePath(PrintAsset(a) + "-monolithic.ckl"));
            wc.AddAsset(a);
            wc.process();
        }
        //not monolithic - one CKL file per asset/stig combo
        else
        {
            Q_FOREACH (STIG s, a.GetSTIGs())
            {
                WorkerCKL wc;
                wc.AddFilename(QDir(_dirName).filePath(PrintAsset(a) + "_" + SanitizeFile(s.title) + "_V" + QString::number(s.version) + "R" + QString::number(GetReleaseNumber(s.release)) + ".ckl"));
                wc.AddAsset(a, {s});
                wc.process();
            }
        }
        Q_EMIT progress(-1);
    }

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
