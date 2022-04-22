/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021–2022 Jon Hood, http://www.hoodsecurity.com/
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
#include "workerckl.h"

#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <QXmlStreamReader>

#include <functional>

/**
 * @class WorkerCKL
 * @brief When generating an asset's CKL file, multiple STIG checklists can be
 * used to comprise it. Traditionally, CKL files are used to store a single
 * asset's individual test results for one STIG; however, the format supports
 * multiple checklists.
 *
 * To generate the individual STIGs mapping single assets to single STIG
 * checklists, use the Reports → STIG CKLs export.
 */

/**
 * @brief WorkerCKL::WorkerCKL
 * @param parent
 *
 * Default Constructor
 */
WorkerCKL::WorkerCKL(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCKL::AddAsset
 * @param asset
 * @param stigs
 *
 * The asset to operate on and an optional set of STIGs
 */
void WorkerCKL::AddAsset(const Asset &asset, const QVector<STIG> &stigs)
{
    _asset = asset;
    if (stigs.isEmpty())
    {
        AddSTIGs(asset.GetSTIGs());
    }
    else
    {
        AddSTIGs(stigs);
    }
}

/**
 * @brief WorkerCKL::AddSTIGs
 * @param stigs
 *
 * List of STIGs to use with CKL file
 */
void WorkerCKL::AddSTIGs(const QVector<STIG> &stigs)
{
    _stigs.append(stigs.toList());
}

/**
 * @brief WorkerCKL::AddFilename
 * @param name
 *
 * The checklist will be written to this supplied filename.
 */
void WorkerCKL::AddFilename(const QString &name)
{
    _fileName = name;
}

/**
 * @brief WorkerCKL::process
 *
 * Perform the operations of this worker process.
 *
 * @example process
 * @title process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerCKL *ckl = new WorkerCKL();
 * ckl->moveToThread(thread); // move the worker to the new thread
 * ckl->AddFilename(fileName); // "fileName" is a QString with the path to where the CKL file should be exported.
 * connect(thread, SIGNAL(started()), ckl, SLOT(process())); // Start the worker when the new thread emits its started() signal.
 * connect(ckl, SIGNAL(finished()), thread, SLOT(quit())); // Kill the thread once the worker emits its finished() signal.
 * connect(thread, SIGNAL(finished()), this, SLOT(EndFunction()));  // execute some EndFunction() (custom code) when the thread is cleaned up.
 * connect(ckl, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int))); // If progress status is needed, connect a custom Initialize(int, int) function to the initialize slot.
 * connect(ckl, SIGNAL(progress(int)), this, SLOT(Progress(int))); // If progress status is needed, connect the progress slot to a custom Progress(int) function.
 * connect(ckl, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString))); // If progress status is needed, connect a human-readable display of the status to the updateStatus(QString) slot.
 * t->start(); // Start the thread
 *
 * //Don't forget to handle the *thread and *addAsset cleanup!
 * @endcode
 */
void WorkerCKL::process()
{
    Worker::process();

    Q_EMIT updateStatus(QStringLiteral("Writing CKL file…"));
    Q_EMIT initialize(_stigs.count() + 1, 0);
    QFile file(_fileName);
    if (file.open(QIODevice::WriteOnly))
    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(_fileName).absolutePath());
        QXmlStreamWriter stream(&file);
        //xml for a CKL file
        stream.writeStartDocument(QStringLiteral("1.0"));
        stream.writeComment("STIGQter :: " + VERSION);

        stream.writeStartElement(QStringLiteral("CHECKLIST"));

        stream.writeStartElement(QStringLiteral("ASSET"));
        WriteXMLEntry(stream, QStringLiteral("ROLE"), QStringLiteral("None")); //ROLE
        WriteXMLEntry(stream, QStringLiteral("ASSET_TYPE"), _asset.assetType); //ASSET_TYPE
        WriteXMLEntry(stream, QStringLiteral("MARKING"), _asset.marking); //MARKING
        WriteXMLEntry(stream, QStringLiteral("HOST_NAME"), _asset.hostName);//HOST_NAME
        WriteXMLEntry(stream, QStringLiteral("HOST_IP"), _asset.hostIP); //HOST_IP
        WriteXMLEntry(stream, QStringLiteral("HOST_MAC"), _asset.hostMAC);//HOST_MAC
        WriteXMLEntry(stream, QStringLiteral("HOST_FQDN"), _asset.hostFQDN); //HOST_FQDN
        WriteXMLEntry(stream, QStringLiteral("TECH_AREA"), _asset.techArea); //TECH_AREA
        WriteXMLEntry(stream, QStringLiteral("TARGET_KEY"), _asset.targetKey); //TARGET_KEY
        WriteXMLEntry(stream, QStringLiteral("TARGET_COMMENT"), _asset.targetComment); //TARGET_COMMENT
        WriteXMLEntry(stream, QStringLiteral("WEB_OR_DATABASE"), PrintTrueFalse(_asset.webOrDB)); //WEB_OR_DATABASE
        WriteXMLEntry(stream, QStringLiteral("WEB_DB_SITE"), _asset.webDbSite); //WEB_DB_SITE
        WriteXMLEntry(stream, QStringLiteral("WEB_DB_INSTANCE"), _asset.webDbInstance); //WEB_DB_INSTANCE
        stream.writeEndElement(); //ASSET

        stream.writeStartElement(QStringLiteral("STIGS"));

        Q_EMIT progress(-1);

        Q_FOREACH (const STIG &s, _stigs)
        {
            Q_EMIT updateStatus("Adding " + PrintSTIG(s) + "…");
            stream.writeStartElement(QStringLiteral("iSTIG"));

            stream.writeStartElement(QStringLiteral("STIG_INFO"));

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("version")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QString::number(s.version)); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("classification")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QStringLiteral("UNCLASSIFIED")); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("customname")); //SID_NAME
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("stigid")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), s.benchmarkId); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("description")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), s.description); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("filename")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), s.fileName); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("releaseinfo")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), s.release); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("title")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), s.title); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("uuid")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QUuid::createUuid().toString(QUuid::WithoutBraces)); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("notice")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QStringLiteral("terms-of-use")); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("source")); //SID_NAME
            WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QStringLiteral("STIG.DOD.MIL")); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeEndElement(); //STIG_INFO

            Q_FOREACH (const CKLCheck &cc, _asset.GetCKLChecks(&s))
            {
                const STIGCheck sc = cc.GetSTIGCheck();
                stream.writeStartElement(QStringLiteral("VULN"));

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Vuln_Num")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.vulnNum); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Severity")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), GetSeverity(cc.GetSeverity(), false)); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Group_Title")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.groupTitle); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Rule_ID")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.rule); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Rule_Ver")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.ruleVersion); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Rule_Title")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.title); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Vuln_Discuss")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.vulnDiscussion); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("IA_Controls")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.iaControls); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Check_Content")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.check); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Fix_Text")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.fix); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("False_Positives")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.falsePositives); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("False_Negatives")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.falseNegatives); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Documentable")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), PrintTrueFalse(sc.documentable)); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Mitigations")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.mitigations); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Potential_Impact")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.potentialImpact); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Third_Party_Tools")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.thirdPartyTools); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Mitigation_Control")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.mitigationControl); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Responsibility")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.responsibility); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Security_Override_Guidance")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.severityOverrideGuidance); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Check_Content_Ref")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.checkContentRef); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Weight")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), QString::number(sc.weight)); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("Class")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), QStringLiteral("Unclass")); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("STIGRef")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), s.title + " :: Version " + QString::number(s.version) + ", " + s.release); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("TargetKey")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), sc.targetKey); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                Q_FOREACH(CCI cci, sc.GetCCIs())
                {
                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("CCI_REF")); //VULN_ATTRIBUTE
                    WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), PrintCCI(cci)); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA
                }

                Q_FOREACH (QString legacyId, sc.legacyIds)
                {
                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("LEGACY_ID")); //VULN_ATTRIBUTE
                    WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), legacyId); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA
                }

                WriteXMLEntry(stream, QStringLiteral("STATUS"), GetStatus(cc.status, true)); //STATUS

                WriteXMLEntry(stream, QStringLiteral("FINDING_DETAILS"), cc.findingDetails); //FINDING_DETAILS

                WriteXMLEntry(stream, QStringLiteral("COMMENTS"), cc.comments); //COMMENTS

                WriteXMLEntry(stream, QStringLiteral("SEVERITY_OVERRIDE"), GetSeverity(cc.severityOverride, false)); //SEVERITY_OVERRIDE

                WriteXMLEntry(stream, QStringLiteral("SEVERITY_JUSTIFICATION"), cc.severityJustification); //SEVERITY_JUSTIFICATION

                stream.writeEndElement(); //VULN
            }

            stream.writeEndElement(); //iSTIG
            Q_EMIT progress(-1);
        }
        stream.writeEndElement(); //STIGS
        stream.writeEndElement(); //CHECKLIST
        stream.writeEndDocument();
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}

/**
 * @brief WorkerCKL::WriteXMLEntry
 * @param stream
 * @param name
 * @param value
 *
 * Write an element to the XML stream
 */
void WorkerCKL::WriteXMLEntry(QXmlStreamWriter &stream, const QString &name, const QString &value)
{
    stream.writeStartElement(name);
    stream.writeCharacters(value);
    stream.writeEndElement();
}

