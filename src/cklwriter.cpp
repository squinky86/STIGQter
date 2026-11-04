/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021–2023 Jon Hood, http://www.hoodsecurity.com/
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

#include "checklistwriter.h"
#include "common.h"
#include "cklcheck.h"
#include <QXmlStreamWriter>
#include <QUuid>

namespace {
void WriteXMLEntry(QXmlStreamWriter &stream, const QString &name, const QString &value)
{
    stream.writeTextElement(name, value);
}
}

bool WriteCkl(QIODevice *output, const Asset &asset, const QList<STIG> &stigs, const ChecklistProgress &progress)
{
    QXmlStreamWriter stream(output);
    //xml for a CKL file
    stream.writeStartDocument(QStringLiteral("1.0"));
    stream.writeComment("STIGQter :: " + VERSION);

    stream.writeStartElement(QStringLiteral("CHECKLIST"));

    stream.writeStartElement(QStringLiteral("ASSET"));
    WriteXMLEntry(stream, QStringLiteral("ROLE"), QStringLiteral("None")); //ROLE
    WriteXMLEntry(stream, QStringLiteral("ASSET_TYPE"), asset.assetType); //ASSET_TYPE
    WriteXMLEntry(stream, QStringLiteral("MARKING"), asset.marking); //MARKING
    WriteXMLEntry(stream, QStringLiteral("HOST_NAME"), asset.hostName);//HOST_NAME
    WriteXMLEntry(stream, QStringLiteral("HOST_IP"), asset.hostIP); //HOST_IP
    WriteXMLEntry(stream, QStringLiteral("HOST_MAC"), asset.hostMAC);//HOST_MAC
    WriteXMLEntry(stream, QStringLiteral("HOST_FQDN"), asset.hostFQDN); //HOST_FQDN
    WriteXMLEntry(stream, QStringLiteral("TARGET_COMMENT"), asset.targetComment); //TARGET_COMMENT
    WriteXMLEntry(stream, QStringLiteral("TECH_AREA"), asset.techArea); //TECH_AREA
    WriteXMLEntry(stream, QStringLiteral("TARGET_KEY"), asset.targetKey); //TARGET_KEY
    WriteXMLEntry(stream, QStringLiteral("WEB_OR_DATABASE"), PrintTrueFalse(asset.webOrDB)); //WEB_OR_DATABASE
    WriteXMLEntry(stream, QStringLiteral("WEB_DB_SITE"), asset.webDbSite); //WEB_DB_SITE
    WriteXMLEntry(stream, QStringLiteral("WEB_DB_INSTANCE"), asset.webDbInstance); //WEB_DB_INSTANCE
    stream.writeEndElement(); //ASSET

    stream.writeStartElement(QStringLiteral("STIGS"));
	QString stigUuid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    progress(-1, {});

    for (const STIG &s : stigs)
    {
        progress(0, "Adding " + PrintSTIG(s) + "…");
        stream.writeStartElement(QStringLiteral("iSTIG"));

        stream.writeStartElement(QStringLiteral("STIG_INFO"));

        stream.writeStartElement(QStringLiteral("SI_DATA"));
        WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("version")); //SID_NAME
        WriteXMLEntry(stream, QStringLiteral("SID_DATA"), QString::number(s.version)); //SID_DATA
        stream.writeEndElement(); //SI_DATA

        stream.writeStartElement(QStringLiteral("SI_DATA"));
        WriteXMLEntry(stream, QStringLiteral("SID_NAME"), QStringLiteral("classification")); //SID_NAME
        WriteXMLEntry(stream, QStringLiteral("SID_DATA"), asset.marking.isEmpty() ? QStringLiteral("UNCLASSIFIED") : GetClassificationString(GetClassification(asset.marking))); //SID_DATA
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

        for (const CKLCheck &cc : asset.GetCKLChecks(&s))
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
            WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("STIG_UUID")); //VULN_ATTRIBUTE
            WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), stigUuid); //ATTRIBUTE_DATA
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

            for (CCI cci : sc.GetCCIs())
            {
                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                WriteXMLEntry(stream, QStringLiteral("VULN_ATTRIBUTE"), QStringLiteral("CCI_REF")); //VULN_ATTRIBUTE
                WriteXMLEntry(stream, QStringLiteral("ATTRIBUTE_DATA"), PrintCCI(cci)); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA
            }

            for (QString legacyId : sc.legacyIds)
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
        progress(-1, {});
    }
    stream.writeEndElement(); //STIGS
    stream.writeEndElement(); //CHECKLIST
    stream.writeEndDocument();
    return !stream.hasError();
}
