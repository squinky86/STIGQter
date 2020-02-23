/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2020 Jon Hood, http://www.hoodsecurity.com/
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
#include "dbmanager.h"
#include "workercklimport.h"

#include <QFile>
#include <QMessageBox>
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
        QMessageBox::warning(nullptr, QStringLiteral("Unable to Open CKL"), "The CKL file " + fileName + " cannot be opened.");
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
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isEndElement())
        {
            if (xml->name() == "VULN")
            {
                tmpCKL.stigCheckId = tmpCheck.id;
                checks.append(tmpCKL);
            }
        }
        if (xml->isStartElement())
        {
            if (inStigs)
            {
                if (xml->name() == "iSTIG" && checks.count() > 0)
                {
                    a = CheckAsset(a);
                    QVector<STIG> stigs = a.GetSTIGs();
                    if (stigs.contains(tmpSTIG))
                    {
                        Q_EMIT updateStatus("Unable to add " + PrintSTIG(tmpSTIG) + " to " + PrintAsset(a) + "!");
                        QMessageBox::warning(nullptr, QStringLiteral("Asset already has STIG applied!"), "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(tmpSTIG) + " applied and will not be imported.");
                    }
                    else
                    {
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
                else if (xml->name() == "SID_NAME" || xml->name() == "VULN_ATTRIBUTE")
                {
                    onVar = xml->readElementText().trimmed();
                }
                else if (xml->name() == "SID_DATA")
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
                else if (xml->name() == "ATTRIBUTE_DATA")
                {
                    if (onVar == QStringLiteral("Rule_ID"))
                    {
                        QString tmpStr = tmpSTIG.title + " version " + QString::number(tmpSTIG.version) + " " + tmpSTIG.release;
                        tmpSTIG = db.GetSTIG(tmpSTIG.title, tmpSTIG.version, tmpSTIG.release);
                        if (tmpSTIG.id < 0)
                        {
                            //The STIG has not been imported.
                            Q_EMIT ThrowWarning(QStringLiteral("STIG/SRG Not Found"), "The CKL file " + fileName + " is mapped against a STIG that has not been imported (" + tmpStr + ").");
                            return;
                        }
                        tmpCheck = db.GetSTIGCheck(tmpSTIG, xml->readElementText().trimmed());
                    }
                }
                else if (xml->name() == "STATUS")
                {
                    tmpCKL.status = GetStatus(xml->readElementText().trimmed());
                }
                else if (xml->name() == "FINDING_DETAILS")
                {
                    tmpCKL.findingDetails = xml->readElementText().trimmed();
                }
                else if (xml->name() == "COMMENTS")
                {
                    tmpCKL.comments = xml->readElementText().trimmed();
                }
                else if (xml->name() == "SEVERITY_OVERRIDE")
                {
                    tmpCKL.severityOverride = GetSeverity(xml->readElementText().trimmed());
                }
                else if (xml->name() == "SEVERITY_JUSTIFICATION")
                {
                    tmpCKL.severityJustification = xml->readElementText().trimmed();
                }
            }
            else
            {
                if (xml->name() == "STIGS")
                {
                    inStigs = true;
                }
                else if (xml->name() == "ASSET_TYPE")
                {
                    a.assetType = xml->readElementText().trimmed();
                }
                else if (xml->name() == "HOST_NAME")
                {
                    a.hostName = xml->readElementText().trimmed();
                }
                else if (xml->name() == "HOST_IP")
                {
                    a.hostIP = xml->readElementText().trimmed();
                }
                else if (xml->name() == "HOST_MAC")
                {
                    a.hostMAC = xml->readElementText().trimmed();
                }
                else if (xml->name() == "HOST_FQDN")
                {
                    a.hostFQDN = xml->readElementText().trimmed();
                }
                else if (xml->name() == "TECH_AREA")
                {
                    a.techArea = xml->readElementText().trimmed();
                }
                else if (xml->name() == "TARGET_KEY")
                {
                    a.targetKey = xml->readElementText().trimmed();
                }
                else if (xml->name() == "WEB_OR_DATABASE")
                {
                    a.webOrDB = xml->readElementText().trimmed().startsWith(QStringLiteral("t"), Qt::CaseInsensitive);
                }
                else if (xml->name() == "WEB_DB_SITE")
                {
                    a.webDbSite = xml->readElementText().trimmed();
                }
                else if (xml->name() == "WEB_DB_INSTANCE")
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
