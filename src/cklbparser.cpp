/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "contentcatalog.h"
#include "dbmanager.h"
#include "workercklimport.h"
#include "workerstigadd.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryFile>
#include <QUrlQuery>
#include <QXmlStreamReader>

/**
 * @brief WorkerCKLImport::ParseCKLB
 * @param fileName
 *
 * Given a CKLB (STIG Viewer 3 JSON) file, parse it and put its data
 * into the database.
 */
void WorkerCKLImport::ParseCKLB(const QString &fileName)
{
    QFile f(fileName);
    if (!f.open(QFile::ReadOnly))
    {
        Q_EMIT ThrowWarning(QStringLiteral("Unable to Open CKLB"), "The CKLB file " + fileName + " cannot be opened.");
        return;
    }

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (doc.isNull())
    {
        Q_EMIT ThrowWarning(QStringLiteral("Invalid CKLB"), "The CKLB file " + fileName + " could not be parsed: " + err.errorString());
        return;
    }

    DbManager db;
    QJsonObject root = doc.object();

    // Parse asset/target metadata
    Asset a;
    QJsonObject td = root[QStringLiteral("target_data")].toObject();
    a.assetType     = td[QStringLiteral("target_type")].toString();
    a.hostName      = td[QStringLiteral("host_name")].toString();
    a.hostIP        = td[QStringLiteral("ip_address")].toString();
    a.hostMAC       = td[QStringLiteral("mac_address")].toString();
    a.hostFQDN      = td[QStringLiteral("fqdn")].toString();
    a.targetComment = td[QStringLiteral("comments")].toString();
    a.webOrDB       = td[QStringLiteral("is_web_database")].toBool();
    a.techArea      = td[QStringLiteral("technology_area")].toString();
    a.webDbSite     = td[QStringLiteral("web_db_site")].toString();
    a.webDbInstance = td[QStringLiteral("web_db_instance")].toString();
    a.marking       = td[QStringLiteral("marking")].toString();

    // Ensure asset exists in DB
    a = CheckAsset(a);

    for (const QJsonValue &stigVal : root[QStringLiteral("stigs")].toArray())
    {
        QJsonObject stigObj = stigVal.toObject();
        QString benchmarkId = stigObj[QStringLiteral("stig_id")].toString();

        // Look up the STIG by benchmarkId
        QVector<STIG> matches = db.GetSTIGs(
            QStringLiteral("WHERE benchmarkId = :benchmarkId"),
            {std::make_tuple<QString, QVariant>(QStringLiteral(":benchmarkId"), benchmarkId)});

        if (matches.isEmpty())
        {
            QString stigName = stigObj[QStringLiteral("stig_name")].toString();
            Q_EMIT ThrowWarning(QStringLiteral("STIG/SRG Not Found"),
                "The CKLB file " + fileName + " references a STIG that has not been imported (" + stigName + " / " + benchmarkId + ").");
            return;
        }

        STIG stig = matches.first();

        QVector<STIG> assetStigs = a.GetSTIGs();
        if (assetStigs.contains(stig))
        {
            Q_EMIT ThrowWarning(QStringLiteral("Asset already has STIG applied!"),
                "The asset " + PrintAsset(a) + " already has the STIG " + PrintSTIG(stig) + " applied and will not be imported.");
            continue;
        }

        Q_EMIT updateStatus("Adding " + PrintSTIG(stig) + " to " + PrintAsset(a) + "…");
        db.AddSTIGToAsset(stig, a);

        db.DelayCommit(true);
        for (const QJsonValue &ruleVal : stigObj[QStringLiteral("rules")].toArray())
        {
            QJsonObject rule = ruleVal.toObject();
            QString ruleId = rule[QStringLiteral("rule_id")].toString();

            STIGCheck sc = db.GetSTIGCheck(stig, ruleId);
            if (sc.id < 0)
                continue;

            CKLCheck cc;
            cc.assetId        = a.id;
            cc.stigCheckId    = sc.id;
            cc.status         = GetStatus(rule[QStringLiteral("status")].toString());
            cc.findingDetails = rule[QStringLiteral("finding_details")].toString();
            cc.comments       = rule[QStringLiteral("comments")].toString();
            cc.severityOverride     = GetSeverity(rule[QStringLiteral("severity_override")].toString());
            cc.severityJustification = rule[QStringLiteral("severity_justification")].toString();

            db.UpdateCKLCheck(cc);
        }
        db.DelayCommit(false);
    }
}
