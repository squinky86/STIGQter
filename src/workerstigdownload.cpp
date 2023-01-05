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
    if (tmpFile.open())
    {
        DbManager db;
        QUrl stigs(db.GetVariable(QStringLiteral("quarterly")));
        DownloadFile(stigs, &tmpFile);
        //get all zip files within the master zip file
        Q_EMIT updateStatus(QStringLiteral("Extracting and adding STIGs…"));
        auto stigFiles = GetFilesFromZip(tmpFile.fileName(), QStringLiteral(".zip"));
        Q_EMIT initialize(stigFiles.count() + 2, 2);
        //assume that each zip file within the archive is its own STIG and try to process it
        QMap<QString, QByteArray>::iterator i;
        for (i = stigFiles.begin(); i != stigFiles.end(); ++i)
        {
            Q_EMIT updateStatus("Parsing " + i.key() + "…");
            WorkerSTIGAdd tmpWorker;
            tmpWorker.SetEnableSupplements(_enableSupplements);
            QTemporaryFile tmpFile2;
            if (tmpFile2.open())
            {
                tmpFile2.write(i.value());
            }
            tmpFile2.close();
            QStringList tmpList;
            tmpList.push_back(tmpFile2.fileName());
            tmpWorker.AddSTIGs(tmpList);
            tmpWorker.process();
            Q_EMIT progress(-1);
        }
        tmpFile.close();
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
