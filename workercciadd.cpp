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
    emit updateStatus("Downloading Families…");
    QUrl nist("https://nvd.nist.gov");
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
            if (xml->attributes().hasAttribute("id") && xml->attributes().hasAttribute("href"))
            {
                QString id("");
                QString href("");
                foreach (const QXmlStreamAttribute &attr, xml->attributes())
                {
                    if (attr.name() == "id")
                        id = attr.value().toString();
                    else if (attr.name() == "href")
                        href = attr.value().toString();
                }
                if (id.endsWith("FamilyLink"))
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
    db.AddFamily("AP", "Authority and Purpose");
    db.AddFamily("AR", "Accountability, Audit, and Risk Management");
    db.AddFamily("DI", "Data Quality and Integrity");
    db.AddFamily("DM", "Data Minimization and Retention");
    db.AddFamily("IP", "Individual Participation and Redress");
    db.AddFamily("SE", "Security");
    db.AddFamily("TR", "Transparency");
    db.AddFamily("UL", "Use Limitation");

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
    db.AddControl("AP-1", "AUTHORITY TO COLLECT", "");
    db.AddControl("AP-2", "PURPOSE SPECIFICATION", "");
    db.AddControl("AR-1", "GOVERNANCE AND PRIVACY PROGRAM", "");
    db.AddControl("AR-2", "PRIVACY IMPACT AND RISK ASSESSMENT", "");
    db.AddControl("AR-3", "PRIVACY REQUIREMENTS FOR CONTRACTORS AND SERVICE PROVIDERS", "");
    db.AddControl("AR-4", "PRIVACY MONITORING AND AUDITING", "");
    db.AddControl("AR-5", "PRIVACY AWARENESS AND TRAINING", "");
    db.AddControl("AR-6", "PRIVACY REPORTING", "");
    db.AddControl("AR-7", "PRIVACY-ENHANCED SYSTEM DESIGN AND DEVELOPMENT", "");
    db.AddControl("AR-8", "ACCOUNTING OF DISCLOSURES", "");
    db.AddControl("DI-1", "DATA QUALITY", "");
    db.AddControl("DI-1 (1)", "DATA QUALITY | VALIDATE PII", "");
    db.AddControl("DI-1 (2)", "DATA QUALITY | RE-VALIDATE PII", "");
    db.AddControl("DI-2", "DATA INTEGRITY AND DATA INTEGRITY BOARD", "");
    db.AddControl("DI-2 (1)", "DATA INTEGRITY AND DATA INTEGRITY BOARD | PUBLISH AREEMENTS ON WEBSITE", "");
    db.AddControl("DM-1", "MINIMIZATION OF PERSONALLY IDENTIFIABLE INFORMATION", "");
    db.AddControl("DM-1 (1)", "MINIMIZATION OF PERSONALLY IDENTIFIABLE INFORMATION | LOCATE / REMOVE / REDACT / ANONYMIZE PII", "");
    db.AddControl("DM-2", "DATA RETENTION AND DISPOSAL", "");
    db.AddControl("DM-2 (1)", "DATA RETENTION AND DISPOSAL | SYSTEM CONFIGURATION", "");
    db.AddControl("DM-3", "MINIMIZATION OF PII USED IN TESTING, TRAINING, AND RESEARCH", "");
    db.AddControl("DM-3 (1)", "MINIMIZATION OF PII USED IN TESTING, TRAINING, AND RESEARCH | RISK MINIMIZATION TECHNIQUES", "");
    db.AddControl("IP-1", "CONSENT", "");
    db.AddControl("IP-1 (1)", "CONSENT | MECHANISMS SUPPORTING ITEMIZED OR TIERED CONSENT", "");
    db.AddControl("IP-2", "INDIVIDUAL ACCESS", "");
    db.AddControl("IP-3", "REDRESS", "");
    db.AddControl("IP-4", "COMPLAINT MANAGEMENT", "");
    db.AddControl("IP-4 (1)", "COMPLAINT MANAGEMENT | RESPONSE TIMES", "");
    db.AddControl("SE-1", "INVENTORY OF PERSONALLY IDENTIFIABLE INFORMATION", "");
    db.AddControl("SE-2", "PRIVACY INCIDENT RESPONSE", "");
    db.AddControl("TR-1", "PRIVACY NOTICE", "");
    db.AddControl("TR-1 (1)", "PRIVACY NOTICE | REAL-TIME OR LAYERED NOTICE", "");
    db.AddControl("TR-2", "SYSTEM OF RECORDS NOTICES AND PRIVACY ACT STATEMENTS", "");
    db.AddControl("TR-2 (1)", "SYSTEM OF RECORDS NOTICES AND PRIVACY ACT STATEMENTS | PUBLIC WEBSITE PUBLICATION", "");
    db.AddControl("TR-3", "DISSEMINATION OF PRIVACY PROGRAM INFORMATION", "");
    db.AddControl("UL-1", "INTERNAL USE", "");
    db.AddControl("UL-2", "INFORMATION SHARING WITH THIRD PARTIES", "");

    //Step 5: download all CCIs
    QTemporaryFile tmpFile;
    QByteArrayList xmlFiles;
    db.DelayCommit(true);
    if (tmpFile.open())
    {
        QUrl ccis("http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip");
        emit updateStatus("Downloading " + ccis.toString() + "…");
        DownloadFile(ccis, &tmpFile);
        emit progress(-1);
        emit updateStatus("Extracting CCIs…");
        xmlFiles = GetXMLFromZip(tmpFile.fileName().toStdString().c_str());
        tmpFile.close();
    }

    //Step 6: Parse all CCIs
    emit updateStatus("Parsing CCIs…");
    QList<CCI> toAdd;
    foreach (const QByteArray &xmlFile, xmlFiles)
    {
        xml = new QXmlStreamReader(xmlFile);
        QString cci("");
        QString definition("");
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name() == "cci_item")
                {
                    if (xml->attributes().hasAttribute("id"))
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
                    if (xml->attributes().hasAttribute("version") && xml->attributes().hasAttribute("index") && !cci.isEmpty())
                    {
                        QString version("");
                        QString index("");
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "version")
                                version = attr.value().toString();
                            else if (attr.name() == "index")
                                index = attr.value().toString();
                        }
                        if (!version.isEmpty() && !index.isEmpty() && (version == "4")) //Only Rev 4 supported
                        {
                            int cciInt = cci.rightRef(6).toInt();
                            QString control = index;
                            int tmpIndex = index.indexOf(' ');
                            if (control.contains(' '))
                                control = control.left(control.indexOf(" "));
                            if (control.contains('.'))
                                control = control.left(control.indexOf("."));
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
    emit updateStatus("Done!");
    emit finished();
}
