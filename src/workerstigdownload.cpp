/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019 Jon Hood, http://www.hoodsecurity.com/
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

WorkerSTIGDownload::WorkerSTIGDownload(QObject *parent) : QObject(parent)
{
}

void WorkerSTIGDownload::process()
{
    //get the list of STIG .zip files selected
    Q_EMIT initialize(2, 1);
    Q_EMIT updateStatus(QStringLiteral("Downloading quarterly…"));

    QTemporaryFile tmpFile;
    if (tmpFile.open())
    {
        QUrl stigs(QStringLiteral("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_2019_10v2.zip"));
        DownloadFile(stigs, &tmpFile);
        //get all zip files within the master zip file
        auto stigFiles = GetFilesFromZip(tmpFile.fileName().toStdString().c_str(), QStringLiteral(".zip")).values();
        Q_EMIT initialize(stigFiles.count() + 2, 2);
        Q_EMIT updateStatus(QStringLiteral("Extracting and adding STIGs…"));
        //assume that each zip file within the archive is its own STIG and try to process it
        Q_FOREACH (auto stigFile, stigFiles)
        {
            WorkerSTIGAdd tmpWorker;
            QTemporaryFile tmpFile2;
            if (tmpFile2.open())
            {
                tmpFile2.write((stigFile));
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
