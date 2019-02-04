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
#include "workercklexport.h"

#include <QDir>
#include <QXmlStreamWriter>

WorkerCKLExport::WorkerCKLExport(QObject *parent) : QObject(parent)
{
}

void WorkerCKLExport::SetExportDir(const QString &dir)
{
    _dirName = dir;
}

void WorkerCKLExport::process()
{
    DbManager db;
    QList<Asset> assets = db.GetAssets();
    emit initialize(assets.count(), 0);
    foreach (Asset a, assets)
    {
        emit updateStatus("Exporting CKLs for " + PrintAsset(a));
        foreach (STIG s, a.STIGs())
        {
            updateStatus("Exporting CKL " + PrintSTIG(s) + " for " + PrintAsset(a));
            QString fileName = QDir(_dirName).filePath(PrintAsset(a) + "_" + s.title + "_V" + QString::number(s.version) + "R" + QString::number(GetReleaseNumber(s.release)) + ".ckl");
            QFile file(fileName);
            if (file.exists(fileName))
            {
                Warning(QStringLiteral("File Exists"), "The file " + fileName + " already exists. Please save to an empty directory.");
                return;
            }
            if (file.open(QIODevice::WriteOnly))
            {
                QXmlStreamWriter stream(&file);
                //xml for a CKL file
                stream.writeStartDocument(QStringLiteral("1.0"));
                stream.writeComment("STIGQter :: " + QString(QStringLiteral(VERSION)));
                stream.writeStartElement(QStringLiteral("CHECKLIST"));
                stream.writeStartElement(QStringLiteral("ASSET"));
                stream.writeStartElement(QStringLiteral("ROLE"));
                stream.writeCharacters(QStringLiteral("None"));
                stream.writeEndElement(); //ROLE
                stream.writeStartElement(QStringLiteral("ASSET_TYPE"));
                stream.writeCharacters(a.assetType);
                stream.writeEndElement(); //ASSET_TYPE
                stream.writeStartElement(QStringLiteral("HOST_NAME"));
                stream.writeCharacters(a.hostName);
                stream.writeEndElement(); //HOST_NAME
                stream.writeStartElement(QStringLiteral("HOST_IP"));
                stream.writeCharacters(a.hostIP);
                stream.writeEndElement(); //HOST_IP
                stream.writeStartElement(QStringLiteral("HOST_MAC"));
                stream.writeCharacters(a.hostMAC);
                stream.writeEndElement(); //HOST_MAC
                stream.writeStartElement(QStringLiteral("HOST_FQDN"));
                stream.writeCharacters(a.hostFQDN);
                stream.writeEndElement(); //HOST_FQDN
                stream.writeStartElement(QStringLiteral("TECH_AREA"));
                stream.writeCharacters(a.techArea);
                stream.writeEndElement(); //TECH_AREA
                stream.writeStartElement(QStringLiteral("TARGET_KEY"));
                stream.writeCharacters(a.targetKey);
                stream.writeEndElement(); //TARGET_KEY
                stream.writeStartElement(QStringLiteral("WEB_OR_DATABASE"));
                stream.writeCharacters(PrintTrueFalse(a.webOrDB));
                stream.writeEndElement(); //WEB_OR_DATABASE
                stream.writeStartElement(QStringLiteral("WEB_DB_SITE"));
                stream.writeCharacters(a.webDbSite);
                stream.writeEndElement(); //WEB_DB_SITE
                stream.writeStartElement(QStringLiteral("WEB_DB_INSTANCE"));
                stream.writeCharacters(a.webDbInstance);
                stream.writeEndElement(); //WEB_DB_INSTANCE
                stream.writeEndElement(); //ASSET
                stream.writeStartElement(QStringLiteral("STIGS"));

                stream.writeStartElement(QStringLiteral("iSTIG"));
                stream.writeStartElement(QStringLiteral("STIG_INFO"));

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("version"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(QString::number(s.version));
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("stigid"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(s.benchmarkId);
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("description"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(s.description);
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("filename"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(s.fileName);
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("releaseinfo"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(s.release);
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeStartElement(QStringLiteral("SI_DATA"));
                stream.writeStartElement(QStringLiteral("SID_NAME"));
                stream.writeCharacters(QStringLiteral("title"));
                stream.writeEndElement(); //SID_NAME
                stream.writeStartElement(QStringLiteral("SID_DATA"));
                stream.writeCharacters(s.title);
                stream.writeEndElement(); //SID_DATA
                stream.writeEndElement(); //SI_DATA

                stream.writeEndElement(); //STIG_INFO

                foreach (const CKLCheck &cc, a.CKLChecks(&s))
                {
                    const STIGCheck sc = cc.STIGCheck();
                    stream.writeStartElement(QStringLiteral("VULN"));

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Vuln_Num"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.vulnNum);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Severity"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(GetSeverity(cc.GetSeverity(), false));
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Group_Title"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.groupTitle);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Rule_ID"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.rule);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Rule_Ver"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.ruleVersion);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Rule_Title"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.title);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Vuln_Discuss"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.vulnDiscussion);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("IA_Controls"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.iaControls);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Check_Content"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.check);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Fix_Text"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.fix);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("False_Positives"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.falsePositives);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("False_Negatives"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.falseNegatives);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Documentable"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(PrintTrueFalse(sc.documentable));
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Mitigations"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.mitigations);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Potential_Impact"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.potentialImpact);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Third_Party_Tools"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.thirdPartyTools);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Mitigation_Control"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.mitigationControl);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Responsibility"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.responsibility);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Security_Override_Guidance"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.severityOverrideGuidance);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Check_Content_Ref"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.checkContentRef);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("Weight"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(QString::number(sc.weight));
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("STIGRef"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(s.title + " :: Version " + QString::number(s.version) + ", " + s.release);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("TargetKey"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(sc.targetKey);
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("CCI_REF"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(PrintCCI(sc.CCI()));
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA

                    stream.writeStartElement(QStringLiteral("STATUS"));
                    stream.writeCharacters(GetStatus(cc.status, true));
                    stream.writeEndElement(); //STATUS

                    stream.writeStartElement(QStringLiteral("FINDING_DETAILS"));
                    stream.writeCharacters(cc.findingDetails);
                    stream.writeEndElement(); //FINDING_DETAILS

                    stream.writeStartElement(QStringLiteral("COMMENTS"));
                    stream.writeCharacters(cc.comments);
                    stream.writeEndElement(); //COMMENTS

                    stream.writeStartElement(QStringLiteral("SEVERITY_OVERRIDE"));
                    stream.writeCharacters(GetSeverity(cc.severityOverride, false));
                    stream.writeEndElement(); //SEVERITY_OVERRIDE

                    stream.writeStartElement(QStringLiteral("SEVERITY_JUSTIFICATION"));
                    stream.writeCharacters(cc.severityJustification);
                    stream.writeEndElement(); //SEVERITY_JUSTIFICATION

                    stream.writeEndElement(); //VULN
                }
                stream.writeEndElement(); //iSTIG
                stream.writeEndElement(); //STIGS
                stream.writeEndElement(); //CHECKLIST
                stream.writeEndDocument();
            }
        }
        emit progress(-1);
    }
    emit updateStatus("Done!");
    emit finished();
}
