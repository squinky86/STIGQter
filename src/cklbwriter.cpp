/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2024–2026 Jon Hood, http://www.hoodsecurity.com/
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
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

namespace {

QString cklbStatus(Status s)
{
    switch (s)
    {
    case Status::Open:         return QStringLiteral("open");
    case Status::NotApplicable: return QStringLiteral("not_applicable");
    case Status::NotAFinding:  return QStringLiteral("not_a_finding");
    default:                   return QStringLiteral("not_reviewed");
    }
}

} // namespace


bool WriteCklb(QIODevice *output, const Asset &asset, const QList<STIG> &stigs, const ChecklistProgress &progress)
{
    // target_data object
    QJsonObject targetData;
    targetData[QStringLiteral("target_type")]     = asset.assetType;
    targetData[QStringLiteral("host_name")]       = asset.hostName;
    targetData[QStringLiteral("ip_address")]      = asset.hostIP;
    targetData[QStringLiteral("mac_address")]     = asset.hostMAC;
    targetData[QStringLiteral("fqdn")]            = asset.hostFQDN;
    targetData[QStringLiteral("comments")]        = asset.targetComment;
    targetData[QStringLiteral("role")]            = QStringLiteral("None");
    targetData[QStringLiteral("is_web_database")] = asset.webOrDB;
    targetData[QStringLiteral("technology_area")] = asset.techArea;
    targetData[QStringLiteral("web_db_site")]     = asset.webDbSite;
    targetData[QStringLiteral("web_db_instance")] = asset.webDbInstance;
    targetData[QStringLiteral("marking")]         = asset.marking;

    progress(-1, {});

    QJsonArray stigsArray;

    for (const STIG &s : stigs)
    {
        progress(0, QStringLiteral("Adding ") + PrintSTIG(s) + QStringLiteral("…"));

        QString stigUuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
        QVector<CKLCheck> checks = asset.GetCKLChecks(&s);

        QJsonArray rulesArray;
        for (const CKLCheck &cc : checks)
        {
            const STIGCheck sc = cc.GetSTIGCheck();

            // CCI list
            QJsonArray ccis;
            for (const CCI &cci : sc.GetCCIs())
                ccis.append(PrintCCI(cci));

            // check_content_ref — split "name :: href" that XCCDF stores in
            // checkContentRef; fall back to the raw string as the name.
            QJsonObject checkRef;
            const int sep = sc.checkContentRef.indexOf(QStringLiteral(" :: "));
            if (sep >= 0)
            {
                checkRef[QStringLiteral("name")] = sc.checkContentRef.left(sep);
                checkRef[QStringLiteral("href")] = sc.checkContentRef.mid(sep + 4);
            }
            else
            {
                checkRef[QStringLiteral("name")] = sc.checkContentRef;
                checkRef[QStringLiteral("href")] = QString();
            }

            QString sevOverride = (cc.severityOverride == Severity::none)
                ? QString()
                : GetSeverity(cc.severityOverride, false);

            QJsonObject rule;
            rule[QStringLiteral("uuid")]                      = QUuid::createUuid().toString(QUuid::WithoutBraces);
            rule[QStringLiteral("stig_uuid")]                 = stigUuid;
            rule[QStringLiteral("status")]                    = cklbStatus(cc.status);
            rule[QStringLiteral("override_guidance")]         = cc.severityJustification;
            rule[QStringLiteral("finding_details")]           = cc.findingDetails;
            rule[QStringLiteral("comments")]                  = cc.comments;
            rule[QStringLiteral("severity_override")]         = sevOverride;
            rule[QStringLiteral("severity_justification")]    = cc.severityJustification;
            rule[QStringLiteral("group_id")]                  = sc.vulnNum;
            rule[QStringLiteral("rule_id")]                   = sc.rule;
            rule[QStringLiteral("rule_id_src")]               = sc.rule;
            rule[QStringLiteral("weight")]                    = QString::number(sc.weight, 'f', 1);
            rule[QStringLiteral("classification")]            = asset.marking.isEmpty() ? QStringLiteral("UNCLASSIFIED") : GetClassificationString(GetClassification(asset.marking));
            rule[QStringLiteral("severity")]                  = GetSeverity(cc.GetSeverity(), false);
            rule[QStringLiteral("rule_fix_txt")]              = sc.fix;
            rule[QStringLiteral("false_positives")]           = sc.falsePositives;
            rule[QStringLiteral("false_negatives")]           = sc.falseNegatives;
            rule[QStringLiteral("documentable")]              = sc.documentable;
            rule[QStringLiteral("mitigations")]               = sc.mitigations;
            rule[QStringLiteral("potential_impact")]          = sc.potentialImpact;
            rule[QStringLiteral("third_party_tools")]         = sc.thirdPartyTools;
            rule[QStringLiteral("mitigation_control")]        = sc.mitigationControl;
            rule[QStringLiteral("responsibility")]            = sc.responsibility;
            rule[QStringLiteral("security_override_guidance")] = sc.severityOverrideGuidance;
            rule[QStringLiteral("ia_controls")]               = sc.iaControls;
            rule[QStringLiteral("check_content_ref")]         = checkRef;
            rule[QStringLiteral("check_content")]             = sc.check;
            rule[QStringLiteral("fix_id")]                    = QString();
            rule[QStringLiteral("ccis")]                      = ccis;
            rule[QStringLiteral("group_title")]               = sc.groupTitle;
            rule[QStringLiteral("rule_title")]                = sc.title;
            rule[QStringLiteral("discussion")]                = sc.vulnDiscussion;
            rule[QStringLiteral("check_system")]              = QString();
            rule[QStringLiteral("legacy_ids")]                = QJsonArray::fromStringList(sc.legacyIds);

            rulesArray.append(rule);
        }

        QJsonObject stigObj;
        stigObj[QStringLiteral("stig_name")]           = s.title;
        stigObj[QStringLiteral("display_name")]        = s.title;
        stigObj[QStringLiteral("stig_id")]             = s.benchmarkId;
        stigObj[QStringLiteral("release_info")]        = s.release;
        stigObj[QStringLiteral("uuid")]                = stigUuid;
        stigObj[QStringLiteral("reference_identifier")] = s.benchmarkId;
        stigObj[QStringLiteral("size")]                = rulesArray.count();
        stigObj[QStringLiteral("rules")]               = rulesArray;

        stigsArray.append(stigObj);
        progress(-1, {});
    }

    QJsonObject root;
    root[QStringLiteral("title")]       = asset.hostName;
    root[QStringLiteral("id")]          = QUuid::createUuid().toString(QUuid::WithoutBraces);
    root[QStringLiteral("active")]      = true;
    root[QStringLiteral("mode")]        = 1;
    root[QStringLiteral("has_path")]    = true;
    root[QStringLiteral("target_data")] = targetData;
    root[QStringLiteral("stigs")]       = stigsArray;
    const QByteArray data = QJsonDocument(root).toJson(QJsonDocument::Indented);
    return output->write(data) == data.size();
}
