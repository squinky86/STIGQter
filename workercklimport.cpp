/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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
    QList<CKLCheck> checks;
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
                    if (a.STIGs().contains(tmpSTIG))
                    {
                        QMessageBox::warning(nullptr, QStringLiteral("Asset already has STIG applied!"), "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(tmpSTIG) + " applied and will not be imported.");
                    }
                    else
                    {
                        db.AddSTIGToAsset(tmpSTIG, a);
                        db.DelayCommit(true);
                        foreach (CKLCheck c, checks)
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
                        tmpSTIG = db.GetSTIG(tmpSTIG.title, tmpSTIG.version, tmpSTIG.release);
                        if (tmpSTIG.id < 0)
                        {
                            //This STIG does not exist in the database and a warning message has already been presented to the user
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
    if (a.STIGs().contains(tmpSTIG))
    {
        QMessageBox::warning(nullptr, QStringLiteral("Asset already has STIG applied!"), "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(tmpSTIG) + " applied.");
        return;
    }
    db.AddSTIGToAsset(tmpSTIG, a);
    db.DelayCommit(true);
    foreach (CKLCheck c, checks)
    {
        c.assetId = a.id;
        db.UpdateCKLCheck(c);
    }
    db.DelayCommit(false);
    delete xml;
}

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

WorkerCKLImport::WorkerCKLImport(QObject *parent) : QObject(parent)
{
}

void WorkerCKLImport::AddCKLs(const QStringList &ckls)
{
    _fileNames = ckls;
}

void WorkerCKLImport::process()
{
    emit initialize(_fileNames.count(), 0);
    foreach(const QString fileName, _fileNames)
    {
        emit updateStatus("Parsing " + fileName);
        ParseCKL(fileName);
        emit progress(-1);
    }
    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
