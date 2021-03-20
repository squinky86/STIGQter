/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
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
#include "workercklimport.h"
#include "workerstigadd.h"

#include <QFile>
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
 * @brief WorkerCKLImport::ParseCKL
 * @param fileName
 *
 * Given a CKL file, parse it and put its data into the database.
 */
void WorkerCKLImport::ParseCKL(const QString &fileName)
{
    QFile f(fileName);
    if (!f.open(QFile::ReadOnly | QFile::Text))
    {
	Q_EMIT ThrowWarning(QStringLiteral("Unable to Open CKL"), "The CKL file " + fileName + " cannot be opened.");
        return;
    }
    DbManager db;
    bool inStigs = false;
    QXmlStreamReader *xml = new QXmlStreamReader(f.readAll());
    Asset a;
    QVector<CKLCheck> checks;
    STIGCheck tmpCheck;
    CKLCheck tmpCKL;
    QString onVar;
    STIG tmpSTIG;

    // Cycle through all XML elements looking for ones we care about
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isEndElement())
        {
            if (xml->name().compare(QStringLiteral("VULN")) == 0)
            {
                tmpCKL.stigCheckId = tmpCheck.id;
                checks.append(tmpCKL);
            }
        }
        if (xml->isStartElement())
        {
            if (inStigs)
            {
                if ((xml->name().compare(QStringLiteral("iSTIG")) == 0) && (checks.count() > 0))
                {
                    a = CheckAsset(a);
                    QVector<STIG> stigs = a.GetSTIGs();
                    //Make sure the Asset doesn't already have STIG details for this STIG
                    if (stigs.contains(tmpSTIG))
                    {
                        Q_EMIT updateStatus("Unable to add " + PrintSTIG(tmpSTIG) + " to " + PrintAsset(a) + "!");
                        Q_EMIT ThrowWarning(QStringLiteral("Asset already has STIG applied!"), "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(tmpSTIG) + " applied and will not be imported.");
                    }
                    else
                    {
                        //Apply STIG - the Asset does not have this STIG yet
                        Q_EMIT updateStatus("Adding " + PrintSTIG(tmpSTIG) + " to " + PrintAsset(a) + "…");
                        db.AddSTIGToAsset(tmpSTIG, a);
                        db.DelayCommit(true);
                        Q_FOREACH (CKLCheck c, checks)
                        {
                            c.assetId = a.id;
                            db.UpdateCKLCheck(c);
                        }
                        db.DelayCommit(false);
                    }
                    checks.clear();
                }
                else if ((xml->name().compare(QStringLiteral("SID_NAME")) == 0) || (xml->name().compare(QStringLiteral("VULN_ATTRIBUTE")) == 0))
                {
                    onVar = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("SID_DATA")) == 0)
                {
                    if (onVar == QStringLiteral("version"))
                    {
                        tmpSTIG.version = xml->readElementText().trimmed().toInt();
                    }
                    else if (onVar == QStringLiteral("releaseinfo"))
                    {
                        tmpSTIG.release = xml->readElementText().trimmed();
                    }
                    else if (onVar == QStringLiteral("title"))
                    {
                        tmpSTIG.title = xml->readElementText().trimmed();
                    }
                }
                else if (xml->name().compare(QStringLiteral("ATTRIBUTE_DATA")) == 0)
                {
                    if (onVar == QStringLiteral("Rule_ID"))
                    {
                        QString tmpStr = tmpSTIG.title + " version " + QString::number(tmpSTIG.version) + " " + tmpSTIG.release;
                        STIG tmpSTIG2 = db.GetSTIG(tmpSTIG.title, tmpSTIG.version, tmpSTIG.release);
                        if (tmpSTIG2.id < 0)
                        {
                            QString autostig = db.GetVariable("autostig");
                            if (autostig == QStringLiteral("true"))
                            {
                                QUrl u("https://www.stigqter.com/autostig.php");
                                QUrlQuery q;
                                q.addQueryItem(QStringLiteral("stig"), tmpStr);
                                u.setQuery(q);
                                QString u2 = DownloadPage(u);

                                if (!u2.isEmpty())
                                {
                                    QTemporaryFile tf;
                                    if (tf.open())
                                    {
                                        Q_EMIT updateStatus(QStringLiteral("Attempting to download missing STIG…"));
                                        if (DownloadFile(u2, &tf))
                                        {
                                            Q_EMIT updateStatus(QStringLiteral("Parsing missing STIG…"));
                                            WorkerSTIGAdd wa;
                                            wa.AddSTIGs({tf.fileName()});
                                            wa.process();
                                            tmpSTIG2 = db.GetSTIG(tmpSTIG.title, tmpSTIG.version, tmpSTIG.release);
                                        }
                                    }
                                }
                            }
                        }
                        if (tmpSTIG2.id < 0)
                        {
                            //The STIG has not been imported.
                            Q_EMIT ThrowWarning(QStringLiteral("STIG/SRG Not Found"), "The CKL file " + fileName + " is mapped against a STIG that has not been imported (" + tmpStr + ").");
                            return;
                        }
                        tmpSTIG = tmpSTIG2;
                        tmpCheck = db.GetSTIGCheck(tmpSTIG2, xml->readElementText().trimmed());
                    }
                }
                else if (xml->name().compare(QStringLiteral("STATUS")) == 0)
                {
                    tmpCKL.status = GetStatus(xml->readElementText().trimmed());
                }
                else if (xml->name().compare(QStringLiteral("FINDING_DETAILS")) == 0)
                {
                    tmpCKL.findingDetails = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("COMMENTS")) == 0)
                {
                    tmpCKL.comments = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("SEVERITY_OVERRIDE")) == 0)
                {
                    tmpCKL.severityOverride = GetSeverity(xml->readElementText().trimmed());
                }
                else if (xml->name().compare(QStringLiteral("SEVERITY_JUSTIFICATION")) == 0)
                {
                    tmpCKL.severityJustification = xml->readElementText().trimmed();
                }
            }
            else
            {
                if (xml->name().compare(QStringLiteral("STIGS")) == 0)
                {
                    inStigs = true;
                }
                else if (xml->name().compare(QStringLiteral("ASSET_TYPE")) == 0)
                {
                    a.assetType = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("HOST_NAME")) == 0)
                {
                    a.hostName = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("HOST_IP")) == 0)
                {
                    a.hostIP = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("HOST_MAC")) == 0)
                {
                    a.hostMAC = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("HOST_FQDN")) == 0)
                {
                    a.hostFQDN = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("TECH_AREA")) == 0)
                {
                    a.techArea = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("TARGET_KEY")) == 0)
                {
                    a.targetKey = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("WEB_OR_DATABASE")) == 0)
                {
                    a.webOrDB = xml->readElementText().trimmed().startsWith(QStringLiteral("t"), Qt::CaseInsensitive);
                }
                else if (xml->name().compare(QStringLiteral("WEB_DB_SITE")) == 0)
                {
                    a.webDbSite = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("WEB_DB_INSTANCE")) == 0)
                {
                    a.webDbInstance = xml->readElementText().trimmed();
                }
            }
        }
    }

    //if the asset is already in the database, use it as the one to import the CKL against
    a = CheckAsset(a);
    if (a.GetSTIGs().contains(tmpSTIG))
    {
        Q_EMIT ThrowWarning(QStringLiteral("Asset already has STIG applied!"), "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(tmpSTIG) + " applied.");
        return;
    }
    db.AddSTIGToAsset(tmpSTIG, a);
    db.DelayCommit(true);
    Q_FOREACH (CKLCheck c, checks)
    {
        c.assetId = a.id;
        db.UpdateCKLCheck(c);
    }
    db.DelayCommit(false);
    delete xml;
}

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

    Q_EMIT initialize(_fileNames.count(), 0);
    Q_FOREACH(const QString fileName, _fileNames)
    {
        Q_EMIT updateStatus("Parsing " + fileName);
        ParseCKL(fileName);
        Q_EMIT progress(-1);
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
