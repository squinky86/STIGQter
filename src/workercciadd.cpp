/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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

#include <iostream>

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTemporaryFile>
#include <QXmlStreamReader>

/**
 * @class WorkerCCIAdd
 * @brief Indexing @a CCI and @a Control information from the
 * internet can take a while. These tasks are sent to a background
 * worker process to afford progress to the user.
 *
 * This class indexes @a Family and @a Control information from NIST,
 * and it indexes @a CCI information from DISA.
 */

/**
 * @brief WorkerCCIAdd::WorkerCCIAdd
 * @param parent
 *
 * Default constructor.
 */
WorkerCCIAdd::WorkerCCIAdd(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCCIAdd::CheckFamily
 * @param acronym
 * @param addedFamilies
 * @param resetDelay
 *
 * Verifies that families have been added to the database
 */
void WorkerCCIAdd::CheckFamily(const QString &acronym, const QString &description, QList<QString> &addedFamilies, bool resetDelay)
{
    if (addedFamilies.contains(acronym))
        return;

    DbManager db;
    if (resetDelay)
        db.DelayCommit(false);

    db.AddFamily(acronym, description);
    addedFamilies.append(acronym);

    if (resetDelay)
        db.DelayCommit(true);
}

/**
 * @brief WorkerCCIAdd::process
 *
 * In general:
 * @list
 * @li Download and parse the NIST RMF information.
 * @li Download and parse the cyber.mil CCI information.
 * @endlist
 */
void WorkerCCIAdd::process()
{
    Worker::process();

    //open database in this thread
    Q_EMIT initialize(1, 0);
    DbManager db;

    //populate CCIs

    //Step 1: download NIST Families and controls
    Q_EMIT updateStatus(QStringLiteral("Downloading Families and Controls…"));

    //Step 2: read the families and controls
    //privacy controls obtained from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf contents
    QList<QString> familiesAdded = {QStringLiteral("AP"), QStringLiteral("AR"), QStringLiteral("DI"), QStringLiteral("DM"), QStringLiteral("IP"), QStringLiteral("SE"), QStringLiteral("TR"), QStringLiteral("UL")};
    db.DelayCommit(true);
    Q_EMIT initialize(959, 1); //# of base controls: 958
    db.AddFamily(QStringLiteral("AP"), QStringLiteral("Authority and Purpose"));
    db.AddFamily(QStringLiteral("AR"), QStringLiteral("Accountability, Audit, and Risk Management"));
    db.AddFamily(QStringLiteral("DI"), QStringLiteral("Data Quality and Integrity"));
    db.AddFamily(QStringLiteral("DM"), QStringLiteral("Data Minimization and Retention"));
    db.AddFamily(QStringLiteral("IP"), QStringLiteral("Individual Participation and Redress"));
    db.AddFamily(QStringLiteral("SE"), QStringLiteral("Security"));
    db.AddFamily(QStringLiteral("TR"), QStringLiteral("Transparency"));
    db.AddFamily(QStringLiteral("UL"), QStringLiteral("Use Limitation"));
    db.DelayCommit(false);

    //Step 3: download all controls for each family
    db.DelayCommit(true);
    QString rmfControls = DownloadPage(QUrl("https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r4/800-53-rev4-controls.xml"));
    auto *xml = new QXmlStreamReader(rmfControls);
    QString control;
    QString family;
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
                if (xml->name().compare(QStringLiteral("supplemental-guidance")) == 0)
                    inStatement = false;
                else if (xml->name().compare(QStringLiteral("description")) == 0)
                    description = xml->readElementText().trimmed();
                else if (xml->name().compare(QStringLiteral("family")) == 0)
                    family = xml->readElementText().trimmed();
                else if ((xml->name().compare(QStringLiteral("control")) == 0) || (xml->name().compare(QStringLiteral("control-enhancement")) == 0))
                {
                    inStatement = false;
                    Q_EMIT updateStatus("Adding " + control);
                    CheckFamily(control.left(2), family, familiesAdded, true);
                    db.AddControl(control, title, description);
                    Q_EMIT progress(-1);
                }
            }
            else
            {
                if (xml->name().compare(QStringLiteral("statement")) == 0)
                    inStatement = true;
                else if (xml->name().compare(QStringLiteral("number")) == 0)
                    control = xml->readElementText().trimmed();
                else if (xml->name().compare(QStringLiteral("title")) == 0)
                    title = xml->readElementText().trimmed();
                else if (xml->name().compare(QStringLiteral("description")) == 0)
                    description = xml->readElementText().trimmed();
                else if (xml->name().compare(QStringLiteral("family")) == 0)
                    family = xml->readElementText().trimmed();
                else if ((xml->name().compare(QStringLiteral("control")) == 0) || (xml->name().compare(QStringLiteral("control-enhancement")) == 0))
                {
                    Q_EMIT updateStatus("Adding " + control);
                    CheckFamily(control.left(2), family, familiesAdded, true);
                    db.AddControl(control, title, description);
                    Q_EMIT progress(-1);
                }
            }
        }
    }
    if (!control.isEmpty())
    {
        CheckFamily(control.left(2), family, familiesAdded, true);
        db.AddControl(control, title, description);
    }

    //Step 4: additional privacy controls
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
        //On 8/12/19, the content was removed from http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip
        QUrl ccis(QStringLiteral("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/u_cci_list.zip"));
        Q_EMIT updateStatus("Downloading " + ccis.toString() + "…");
        DownloadFile(ccis, &tmpFile);
        Q_EMIT progress(-1);
        Q_EMIT updateStatus(QStringLiteral("Extracting CCIs…"));
        xmlFiles = GetFilesFromZip(tmpFile.fileName(), QStringLiteral(".xml")).values();
        tmpFile.close();
    }

    //Step 6: Parse all CCIs
    Q_EMIT updateStatus(QStringLiteral("Parsing CCIs…"));
    QList<CCI> toAdd;
    Q_FOREACH (const QByteArray &xmlFile, xmlFiles)
    {
        xml = new QXmlStreamReader(xmlFile);
        QString cci = QString();
        QString definition = QString();
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name().compare(QStringLiteral("cci_item")) == 0)
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("id")))
                    {
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name().compare(QStringLiteral("id")) == 0)
                                cci = attr.value().toString();
                        }
                    }
                }
                else if (xml->name().compare(QStringLiteral("definition")) == 0)
                {
                    definition = xml->readElementText();
                }
                else if (xml->name().compare(QStringLiteral("reference")) == 0)
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("version")) && xml->attributes().hasAttribute(QStringLiteral("index")) && !cci.isEmpty())
                    {
                        QString version = QString();
                        QString index = QString();
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name().compare(QStringLiteral("version")) == 0)
                                version = attr.value().toString();
                            else if (attr.name().compare(QStringLiteral("index")) == 0)
                                index = attr.value().toString();
                        }
                        if (!version.isEmpty() && !index.isEmpty() && (version == QStringLiteral("4"))) //Only Rev 4 supported
                        {
                            int cciInt = QStringView{cci}.right(6).toString().toInt();
                            QString control2 = index;
                            int tmpIndex = index.indexOf(' ');
                            if (control2.contains(' '))
                                control2 = control2.left(control2.indexOf(' '));
                            if (control2.contains('.'))
                                control2 = control2.left(control2.indexOf('.'));
                            if (index.contains('('))
                            {
                                //check if a second space is present. If the parenthesis is after the second space, it is not an enhancement.
                                tmpIndex = index.indexOf(' ', tmpIndex + 1);
                                int tmpInt = index.indexOf('(');
                                if (tmpIndex <= 0 || tmpInt < tmpIndex)
                                {
                                    QString enhancement(index);
                                    enhancement = enhancement.remove(0, tmpInt);
                                    enhancement = enhancement.left(index.indexOf(')') - tmpInt + 1);
                                    control2.append(enhancement);
                                }
                            }
                            CCI c;
                            c.cci = cciInt;
                            c.controlId = db.GetControl(control2).id;
                            c.definition = definition;
                            toAdd.append(c);
                        }
                    }
                }
            }
        }
        delete xml;
    }
    QFile::remove(tmpFile.fileName());

    //Step 7: add CCIs
    Q_EMIT initialize(toAdd.size() + 1, 1);
    db.DelayCommit(true);
    QList<CCI> inDB = db.GetCCIs().toList();
    Q_FOREACH (const CCI &c, toAdd)
    {
        //check if the DB has this CCI already here for performance
        if (inDB.contains(c))
            continue;
        inDB.append(c);
        CCI tmpCCI = c;
        Q_EMIT updateStatus("Adding CCI-" + QString::number(c.cci) + "…");
        db.AddCCI(tmpCCI, false);
        Q_EMIT progress(-1);
    }
    db.DelayCommit(false);

    //complete
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
