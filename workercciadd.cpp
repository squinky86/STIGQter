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

#include "workercciadd.h"
#include "common.h"
#include "cci.h"
#include "dbmanager.h"

#include <zip.h>

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTemporaryFile>
#include <QXmlStreamReader>

WorkerCCIAdd::WorkerCCIAdd(QObject *parent) : QObject(parent)
{
}

void WorkerCCIAdd::process()
{
    //open database in this thread
    emit initialize(1, 0);
    DbManager db;

    //populate CCIs

    //Step 1: download NIST Families
    emit updateStatus(QStringLiteral("Downloading Families…"));
    QUrl nist(QStringLiteral("https://nvd.nist.gov"));
    QString rmf = DownloadPage(nist.toString() + "/800-53/Rev4/");

    //Step 2: Convert NIST page to XML
    rmf = CleanXML(rmf);

    //Step 3: read the families
    QXmlStreamReader *xml = new QXmlStreamReader(rmf);
    QList<QString> todo;
    db.DelayCommit(true);
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isStartElement() && (xml->name() == "a"))
        {
            if (xml->attributes().hasAttribute(QStringLiteral("id")) && xml->attributes().hasAttribute(QStringLiteral("href")))
            {
                QString id = QString();
                QString href = QString();
                foreach (const QXmlStreamAttribute &attr, xml->attributes())
                {
                    if (attr.name() == "id")
                        id = attr.value().toString();
                    else if (attr.name() == "href")
                        href = attr.value().toString();
                }
                if (id.endsWith(QStringLiteral("FamilyLink")))
                {
                    QString family(xml->readElementText().trimmed());
                    QString acronym(family.left(2));
                    QString familyName(family.right(family.length() - 5).trimmed());
                    emit updateStatus("Adding " + acronym + "—" + familyName + "…");
                    db.AddFamily(acronym, familyName);
                    todo.append(href);
                }
            }
        }
    }
    db.DelayCommit(false);
    emit initialize(todo.size() + 1, 1);
    delete xml;

    //Step 3a: Additional Privacy Controls
    //obtained from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf contents
    db.AddFamily(QStringLiteral("AP"), QStringLiteral("Authority and Purpose"));
    db.AddFamily(QStringLiteral("AR"), QStringLiteral("Accountability, Audit, and Risk Management"));
    db.AddFamily(QStringLiteral("DI"), QStringLiteral("Data Quality and Integrity"));
    db.AddFamily(QStringLiteral("DM"), QStringLiteral("Data Minimization and Retention"));
    db.AddFamily(QStringLiteral("IP"), QStringLiteral("Individual Participation and Redress"));
    db.AddFamily(QStringLiteral("SE"), QStringLiteral("Security"));
    db.AddFamily(QStringLiteral("TR"), QStringLiteral("Transparency"));
    db.AddFamily(QStringLiteral("UL"), QStringLiteral("Use Limitation"));

    //Step 4: download all controls for each family
    QString rmfControls = DownloadPage(nist.toString() + "/static/feeds/xml/sp80053/rev4/800-53-controls.xml");
    xml = new QXmlStreamReader(rmfControls);
    QString control;
    QString title;
    QString description;
    bool inStatement = false;
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isStartElement())
        {
            if (inStatement)
            {
                if (xml->name() == "supplemental-guidance")
                {
                    inStatement = false;
                }
                else if (xml->name() == "description")
                {
                    description = xml->readElementText().trimmed();
                }
                else if (xml->name() == "control" || xml->name() == "control-enhancement")
                {
                    inStatement = false;
                    emit updateStatus("Adding " + control);
                    db.AddControl(control, title, description);
                    emit progress(-1);
                }
            }
            else
            {
                if (xml->name() == "statement")
                    inStatement = true;
                else if (xml->name() == "number")
                    control = xml->readElementText().trimmed();
                else if (xml->name() == "title")
                    title = xml->readElementText().trimmed();
                else if (xml->name() == "description")
                    description = xml->readElementText().trimmed();
                else if (xml->name() == "control" || xml->name() == "control-enhancement")
                {
                    emit updateStatus("Adding " + control);
                    db.AddControl(control, title, description);
                    emit progress(-1);
                }
            }
        }
    }
    if (!control.isEmpty())
        db.AddControl(control, title, description);

    //Step 4a: additional privacy controls
    //obtained from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf (Appendix J) contents
    db.AddControl(QStringLiteral("AP-1"), QStringLiteral("AUTHORITY TO COLLECT"), QString());
    db.AddControl(QStringLiteral("AP-2"), QStringLiteral("PURPOSE SPECIFICATION"), QString());
    db.AddControl(QStringLiteral("AR-1"), QStringLiteral("GOVERNANCE AND PRIVACY PROGRAM"), QString());
    db.AddControl(QStringLiteral("AR-2"), QStringLiteral("PRIVACY IMPACT AND RISK ASSESSMENT"), QString());
    db.AddControl(QStringLiteral("AR-3"), QStringLiteral("PRIVACY REQUIREMENTS FOR CONTRACTORS AND SERVICE PROVIDERS"), QString());
    db.AddControl(QStringLiteral("AR-4"), QStringLiteral("PRIVACY MONITORING AND AUDITING"), QString());
    db.AddControl(QStringLiteral("AR-5"), QStringLiteral("PRIVACY AWARENESS AND TRAINING"), QString());
    db.AddControl(QStringLiteral("AR-6"), QStringLiteral("PRIVACY REPORTING"), QString());
    db.AddControl(QStringLiteral("AR-7"), QStringLiteral("PRIVACY-ENHANCED SYSTEM DESIGN AND DEVELOPMENT"), QString());
    db.AddControl(QStringLiteral("AR-8"), QStringLiteral("ACCOUNTING OF DISCLOSURES"), QString());
    db.AddControl(QStringLiteral("DI-1"), QStringLiteral("DATA QUALITY"), QString());
    db.AddControl(QStringLiteral("DI-1 (1)"), QStringLiteral("DATA QUALITY | VALIDATE PII"), QString());
    db.AddControl(QStringLiteral("DI-1 (2)"), QStringLiteral("DATA QUALITY | RE-VALIDATE PII"), QString());
    db.AddControl(QStringLiteral("DI-2"), QStringLiteral("DATA INTEGRITY AND DATA INTEGRITY BOARD"), QString());
    db.AddControl(QStringLiteral("DI-2 (1)"), QStringLiteral("DATA INTEGRITY AND DATA INTEGRITY BOARD | PUBLISH AREEMENTS ON WEBSITE"), QString());
    db.AddControl(QStringLiteral("DM-1"), QStringLiteral("MINIMIZATION OF PERSONALLY IDENTIFIABLE INFORMATION"), QString());
    db.AddControl(QStringLiteral("DM-1 (1)"), QStringLiteral("MINIMIZATION OF PERSONALLY IDENTIFIABLE INFORMATION | LOCATE / REMOVE / REDACT / ANONYMIZE PII"), QString());
    db.AddControl(QStringLiteral("DM-2"), QStringLiteral("DATA RETENTION AND DISPOSAL"), QString());
    db.AddControl(QStringLiteral("DM-2 (1)"), QStringLiteral("DATA RETENTION AND DISPOSAL | SYSTEM CONFIGURATION"), QString());
    db.AddControl(QStringLiteral("DM-3"), QStringLiteral("MINIMIZATION OF PII USED IN TESTING, TRAINING, AND RESEARCH"), QString());
    db.AddControl(QStringLiteral("DM-3 (1)"), QStringLiteral("MINIMIZATION OF PII USED IN TESTING, TRAINING, AND RESEARCH | RISK MINIMIZATION TECHNIQUES"), QString());
    db.AddControl(QStringLiteral("IP-1"), QStringLiteral("CONSENT"), QString());
    db.AddControl(QStringLiteral("IP-1 (1)"), QStringLiteral("CONSENT | MECHANISMS SUPPORTING ITEMIZED OR TIERED CONSENT"), QString());
    db.AddControl(QStringLiteral("IP-2"), QStringLiteral("INDIVIDUAL ACCESS"), QString());
    db.AddControl(QStringLiteral("IP-3"), QStringLiteral("REDRESS"), QString());
    db.AddControl(QStringLiteral("IP-4"), QStringLiteral("COMPLAINT MANAGEMENT"), QString());
    db.AddControl(QStringLiteral("IP-4 (1)"), QStringLiteral("COMPLAINT MANAGEMENT | RESPONSE TIMES"), QString());
    db.AddControl(QStringLiteral("SE-1"), QStringLiteral("INVENTORY OF PERSONALLY IDENTIFIABLE INFORMATION"), QString());
    db.AddControl(QStringLiteral("SE-2"), QStringLiteral("PRIVACY INCIDENT RESPONSE"), QString());
    db.AddControl(QStringLiteral("TR-1"), QStringLiteral("PRIVACY NOTICE"), QString());
    db.AddControl(QStringLiteral("TR-1 (1)"), QStringLiteral("PRIVACY NOTICE | REAL-TIME OR LAYERED NOTICE"), QString());
    db.AddControl(QStringLiteral("TR-2"), QStringLiteral("SYSTEM OF RECORDS NOTICES AND PRIVACY ACT STATEMENTS"), QString());
    db.AddControl(QStringLiteral("TR-2 (1)"), QStringLiteral("SYSTEM OF RECORDS NOTICES AND PRIVACY ACT STATEMENTS | PUBLIC WEBSITE PUBLICATION"), QString());
    db.AddControl(QStringLiteral("TR-3"), QStringLiteral("DISSEMINATION OF PRIVACY PROGRAM INFORMATION"), QString());
    db.AddControl(QStringLiteral("UL-1"), QStringLiteral("INTERNAL USE"), QString());
    db.AddControl(QStringLiteral("UL-2"), QStringLiteral("INFORMATION SHARING WITH THIRD PARTIES"), QString());

    //Step 5: download all CCIs
    QTemporaryFile tmpFile;
    QByteArrayList xmlFiles;
    db.DelayCommit(true);
    if (tmpFile.open())
    {
        QUrl ccis(QStringLiteral("http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip"));
        emit updateStatus("Downloading " + ccis.toString() + "…");
        DownloadFile(ccis, &tmpFile);
        emit progress(-1);
        emit updateStatus(QStringLiteral("Extracting CCIs…"));
        xmlFiles = GetFilesFromZip(tmpFile.fileName().toStdString().c_str(), QStringLiteral(".xml")).values();
        tmpFile.close();
    }

    //Step 6: Parse all CCIs
    emit updateStatus(QStringLiteral("Parsing CCIs…"));
    QList<CCI> toAdd;
    foreach (const QByteArray &xmlFile, xmlFiles)
    {
        xml = new QXmlStreamReader(xmlFile);
        QString cci = QString();
        QString definition = QString();
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name() == "cci_item")
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("id")))
                    {
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "id")
                                cci = attr.value().toString();
                        }
                    }
                }
                else if (xml->name() == "definition")
                {
                    definition = xml->readElementText();
                }
                else if (xml->name() == "reference")
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("version")) && xml->attributes().hasAttribute(QStringLiteral("index")) && !cci.isEmpty())
                    {
                        QString version = QString();
                        QString index = QString();
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "version")
                                version = attr.value().toString();
                            else if (attr.name() == "index")
                                index = attr.value().toString();
                        }
                        if (!version.isEmpty() && !index.isEmpty() && (version == QStringLiteral("4"))) //Only Rev 4 supported
                        {
                            int cciInt = cci.rightRef(6).toInt();
                            QString control = index;
                            int tmpIndex = index.indexOf(' ');
                            if (control.contains(' '))
                                control = control.left(control.indexOf(' '));
                            if (control.contains('.'))
                                control = control.left(control.indexOf('.'));
                            if (index.contains('('))
                            {
                                tmpIndex = index.indexOf(' ', tmpIndex + 1);
                                int tmpInt = index.indexOf('(');
                                if (tmpIndex == 0 || tmpInt < tmpIndex)
                                {
                                    QStringRef enhancement(&index, tmpInt, index.indexOf(')') - tmpInt + 1);
                                    control.append(enhancement);
                                }
                            }
                            CCI c;
                            c.cci = cciInt;
                            c.controlId = db.GetControl(control).id;
                            c.definition = definition;
                            toAdd.append(c);
                            //delayed add
                            //db.AddCCI(cciInt, control, definition);
                        }
                    }
                }
            }
        }
        delete xml;
    }
    QFile::remove(tmpFile.fileName());

    //Step 7: add CCIs
    emit initialize(toAdd.size() + 1, 1);
    db.DelayCommit(true);
    foreach (const CCI &c, toAdd)
    {
        CCI tmpCCI = c;
        emit updateStatus("Adding CCI-" + QString::number(c.cci) + "…");
        db.AddCCI(tmpCCI);
        emit progress(-1);
    }
    db.DelayCommit(false);

    //complete
    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
