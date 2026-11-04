/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "contentcatalog.h"
#include "dbmanager.h"
#include "workercklimport.h"
#include "workerstigadd.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryFile>
#include <QUrlQuery>
#include <QXmlStreamReader>

/**
 * @class WorkerCKLImport
 * @brief Import a STIG Viewer-compatible version of the results from
 * a CKL file.
 *
 * Many systems and tools require data in a CKL file containing
 * @a STIG @a CKLCheck data. This background worker parses a CKL file
 * that has been created by one of these external tools.
 *
 * To comply with eMASS' Asset Manager, only unique mappings between
 * @a Asset and @a STIG are allowed.
 */

/**
 * @brief WorkerCKLImport::CheckAsset
 * @param a
 * @return The Asset from the database
 *
 * Make sure that the Asset object you have is the one from the
 * database.
 */
Asset WorkerCKLImport::CheckAsset(Asset &a)
{
    DbManager db;

    //warn (but continue) if the imported marking is classified higher than the system marking
    Classification assetClass = GetClassification(a.marking);
    Classification systemClass = GetClassification(db.GetVariable(QStringLiteral("systemMarking")));
    if (assetClass > systemClass)
    {
        Q_EMIT ThrowWarning(QStringLiteral("Classification Mismatch"),
            "The imported asset " + PrintAsset(a) + " is marked \"" + a.marking +
            "\", which is classified higher than the system marking (" +
            GetClassificationString(systemClass) + "). The import will continue; verify the system classification marking.");
    }

    Asset tmpAsset = db.GetAsset(a.hostName);
    if (tmpAsset.id > 0)
        a = tmpAsset;
    else
        db.AddAsset(a);
    return a;
}

/**
 * @brief WorkerCKLImport::WorkerCKLImport
 * @param parent
 *
 * Default constructor.
 */
WorkerCKLImport::WorkerCKLImport(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCKLImport::AddCKLs
 * @param ckls
 *
 * Add the provided CKLs to the queue for processing.
 */
void WorkerCKLImport::AddCKLs(const QStringList &ckls)
{
    _fileNames = ckls;
}

/**
 * @brief WorkerCKLImport::process
 *
 * Begin cycling through the queue of CKL files to process.
 */
void WorkerCKLImport::process()
{
    Worker::process();

    ContentCatalog catalog;
    Q_EMIT initialize(_fileNames.count(), 0);
    for (const QString &fileName : _fileNames)
    {
        Q_EMIT updateStatus("Parsing " + fileName);
        if (fileName.endsWith(QStringLiteral(".cklb"), Qt::CaseInsensitive))
            ParseCKLB(fileName);
        else
            ParseCKL(fileName, catalog);
        Q_EMIT progress(-1);
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
