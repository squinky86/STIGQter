/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "contentcatalog.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "workerstigdownload.h"

#include "workerstigadd.h"
#include <QTemporaryFile>
#include <QMap>

/**
 * @class WorkerSTIGDownload
 * @brief Download the latest quarterly STIG release from DISA and
 * add the checklists to the internal database.
 *
 * The main source of STIG and SRG information is from DISA. They
 * publish a quarterly STIG release that is downloaded and processed
 * in this worker.
 */

/**
 * @brief WorkerSTIGDownload::WorkerSTIGDownload
 * @param parent
 *
 * Default constructor.
 */
WorkerSTIGDownload::WorkerSTIGDownload(QObject *parent) : Worker(parent),
    _enableSupplements(false)
{
}

/**
 * @brief WorkerSTIGDownload::SetEnableSupplements
 * @param enableSupplements
 *
 * Sets whether to enable or disable importing the STIG supplementary
 * material into the DB
 */
void WorkerSTIGDownload::SetEnableSupplements(bool enableSupplements)
{
    _enableSupplements = enableSupplements;
}

/**
 * @brief WorkerSTIGDownload::process
 *
 * Download the STIG library and process it as a .zip file of .zip
 * files. Assume that each .zip file within the main archive is a
 * STIG and attempt to parse it.
 */
void WorkerSTIGDownload::process()
{
    Worker::process();

    //get the list of STIG .zip files selected
    Q_EMIT initialize(2, 1);
    Q_EMIT updateStatus(QStringLiteral("Downloading quarterly…"));

    QTemporaryFile tmpFile;
    QString error;
    DbManager db;
    const QUrl configured(db.GetVariable(QStringLiteral("quarterly")));
    bool downloaded = false;
    if (tmpFile.open())
    {
        if (ContentCatalog::isDefaultQuarterly(configured))
        {
            ContentCatalog catalog;
            if (catalog.load(error))
            {
                Q_EMIT updateStatus(catalog.sourceDescription());
                downloaded = catalog.download(catalog.quarterly(), &tmpFile, error);
            }
        }
        else
        {
            downloaded = DownloadFile(configured, &tmpFile);
            if (!downloaded) error = QStringLiteral("Unable to download the configured STIG library.");
        }
    }
    else error = QStringLiteral("Unable to create a temporary download file.");
    if (!downloaded)
    {
        Q_EMIT ThrowWarning(QStringLiteral("STIG download failed"), error);
        Q_EMIT finished();
        return;
    }
    const auto stigFiles = GetFilesFromZip(tmpFile.fileName(), QStringLiteral(".zip"));
    if (stigFiles.isEmpty())
    {
        Q_EMIT ThrowWarning(QStringLiteral("Invalid STIG library"), QStringLiteral("The download contains no STIG ZIP archives. Import a STIG ZIP manually or check the configured URL."));
        Q_EMIT finished();
        return;
    }
    Q_EMIT initialize(stigFiles.count() + 2, 2);
    for (auto i = stigFiles.constBegin(); i != stigFiles.constEnd(); ++i)
    {
        if (QThread::currentThread()->isInterruptionRequested()) break;
        Q_EMIT updateStatus(QStringLiteral("Parsing %1…").arg(i.key()));
        QTemporaryFile source;
        if (!source.open() || source.write(i.value()) != i.value().size() || !source.flush())
        {
            Q_EMIT ThrowWarning(QStringLiteral("STIG import failed"), QStringLiteral("Unable to stage %1.").arg(i.key()));
            continue;
        }
        WorkerSTIGAdd importer;
        connect(&importer, &Worker::ThrowWarning, this, &Worker::ThrowWarning, Qt::DirectConnection);
        importer.SetEnableSupplements(_enableSupplements);
        importer.AddSTIGs({source.fileName()});
        importer.process();
        Q_EMIT progress(-1);
    }
    Q_EMIT finished();
}
