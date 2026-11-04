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

#include "dbmanager.h"
#include "cklcheck.h"
#include "common.h"

#include <cstdlib>
#include <QCryptographicHash>
#include <QFile>
#include <QMap>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QSqlQuery>
#include <QSqlError>
#include <QThread>
#include <QSqlField>
#include <QSqlDriver>
#include <QStandardPaths>
#include <QFileInfo>
#include <QDir>
#include <QCoreApplication>
#include <QTemporaryFile>

/**
 * @brief DbManager::GetAsset
 * @param hostName
 * @return The @a Asset object associated with the supplied
 * @a hostName. If the hostname does not exist, the @a Asset that is
 * returned is the default empty one with an ID of -1.
 */
Asset DbManager::GetAsset(const QString &hostName)
{
    //fail quietly
    QVector<Asset> tmp = GetAssets(QStringLiteral("WHERE Asset.hostName = :hostName"), {std::make_tuple<QString, QVariant>(QStringLiteral(":hostName"), hostName)});
    if (!tmp.isEmpty())
        return tmp.first();
    Asset a;
    return a;
}

/**
 * @brief DbManager::GetAsset
 * @param asset
 * @return The @a Asset object associated with the supplied @a Asset
 * @a id or @a hostName. If the id does not exist in the database,
 * the @a hostName is used. The @a Asset that is returned when
 * neither the @a id nor the @a hostName is in the database is the
 * default empty one with an ID of -1.
 */
Asset DbManager::GetAsset(const Asset &asset)
{
    //first try to find the Asset by ID
    if (asset.id > 0)
    {
        Asset tmpAsset = GetAsset(asset.id);
        if (tmpAsset.id > 0)
            return tmpAsset;
    }
    //can't find by ID, findby hostName
    return GetAsset(asset.hostName);
}

/**
 * @brief DbManager::GetAsset
 * @param id
 * @param mayNotExist
 * @return The @a Asset object associated with the supplied @a id.
 * If the @a id does not exist, the @a Asset that is returned is the
 * default empty one with an ID of -1.
 */
Asset DbManager::GetAsset(int id)
{
    QVector<Asset> tmp = GetAssets(QStringLiteral("WHERE Asset.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!tmp.isEmpty())
        return tmp.first();
    Warning(QStringLiteral("Unable to Find Asset"), "The Asset ID " + QString::number(id) + " was not found in the database.", true);
    Asset a;
    return a;
}

/**
 * @brief DbManager::GetAssets
 * @param whereClause
 * @param variables
 * @return A QVector of @a Assets that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetAssets
 *
 * The default GetAssets() with no parameters returns all Assets in
 * the database.
 *
 * @code
 * DbManager db;
 * QVector<Asset> assets = db.GetAssets();
 * @endcode
 *
 * @example GetAssetsWhere
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * int id = 4; //Asset ID 4 in the database
 * QString sampleHost = "Sample";
 *
 * //get Asset by ID
 * Asset asset = GetAssets("WHERE id = :id",
 *                         {std::make_tuple<QString, QVariant>(":id", id)}
 *                        ).first();
 *
 * //get Asset by HostName
 * asset = GetAssets("WHERE hostName = :hostName",
 *                    {std::make_tuple<QString, QVariant>(":hostName", sampleHost)}
 *                  ).first();
 *
 * //get Asset by ID and HostName
 * asset = GetAssets("WHERE id = :id AND hostName = :hostName",
 *                   {
 *                       std::make_tuple<QString, QVariant>(":id", id),
 *                       std::make_tuple<QString, QVariant>(":hostName", sampleHost)
 *                   }).first();
 * @endcode
 */
QVector<Asset> DbManager::GetAssets(const QString &whereClause, const QVector<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QVector<Asset> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT Asset.`id`, Asset.`assetType`, Asset.`hostName`, Asset.`hostIP`, Asset.`hostMAC`, Asset.`hostFQDN`, Asset.`techArea`, Asset.`targetKey`, Asset.`marking`, Asset.`targetComment`, Asset.`webOrDatabase`, Asset.`webDBSite`, Asset.`webDBInstance`");
        toPrep.append(QStringLiteral(" FROM Asset"));
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(QStringLiteral(" ORDER BY LOWER(hostName), hostName"));
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            Asset a;
            a.id = q.value(0).toInt();
            a.assetType = q.value(1).toString();
            a.hostName = q.value(2).toString();
            a.hostIP = q.value(3).toString();
            a.hostMAC = q.value(4).toString();
            a.hostFQDN = q.value(5).toString();
            a.techArea = q.value(6).toString();
            a.targetKey = q.value(7).toString();
            a.marking = q.value(8).toString();
            a.targetComment = q.value(9).toString();
            a.webOrDB = q.value(10).toBool();
            a.webDbSite = q.value(11).toString();
            a.webDbInstance = q.value(12).toString();
            ret.append(a);
        }
    }
    return ret;
}

/**
 * @overload DbManager::GetAssets(const STIG &stig)
 * @brief DbManager::GetAssets
 * @param stig
 * @return A QVector of @a Assets that are associated with the supplied
 * @a STIG.
 */
QVector<Asset> DbManager::GetAssets(const STIG &stig)
{
    return GetAssets(QStringLiteral("JOIN AssetSTIG ON AssetSTIG.AssetId = Asset.id JOIN STIG ON STIG.id = AssetSTIG.STIGId WHERE STIG.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), stig.id)});
}

/**
 * @brief DbManager::GetCCI
 * @param id
 * @return The @a CCI specified by the provided database id. If the
 * @a CCI does not exist in the database, the default @a CCI with an
 * ID of -1 is returned.
 */
CCI DbManager::GetCCI(int id)
{
    QVector<CCI> ccis = GetCCIs(QStringLiteral("WHERE CCI.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!ccis.isEmpty())
        return ccis.first();
    CCI ret;
    return ret;
}

/**
 * @brief DbManager::GetCCIs
 * @param ccis
 * @return The @a CCIs specified by the provided database ids. If a
 * @a CCI does not exist in the database, the default @a CCI with an
 * ID of -1 is returned.
 */
QVector<CCI> DbManager::GetCCIs(const QVector<int> &ccis)
{
    QVector<CCI> ret;
    for (int cci : ccis)
    {
        ret.append(GetCCIs(QStringLiteral("WHERE CCI.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), cci)}));
    }
    return ret;
}

/**
 * @brief DbManager::GetCCIs
 * @param c
 * @return The @a CCIs mapped to the specified @a Control.
 */
QVector<CCI> DbManager::GetCCIs(const Control &c)
{
    return GetCCIs(QStringLiteral("WHERE ControlId = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), c.id)});
}

/**
 * @brief DbManager::GetCCIs
 * @param STIGCheckId
 * @return The @a CCIs specified by the provided @a STIGCheck. If a
 * @a CCI does not exist in the database, the default @a CCI with an
 * ID of -1 is returned.
 */
QVector<CCI> DbManager::GetCCIs(int STIGCheckId)
{
    QVector<CCI> ret;
    QSqlDatabase db;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT CCIId FROM STIGCheckCCI WHERE STIGCheckCCI.STIGCheckId = :STIGCheckId"));
        q.bindValue(QStringLiteral(":STIGCheckId"), STIGCheckId);
        q.exec();
        while (q.next())
        {
            ret.append(GetCCI(q.value(0).toInt()));
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetCCIByCCI
 * @param cci
 * @param stig
 * @return The @a CCI in the database that corresponds to the
 * supplied @a cci.
 *
 * The @a stig parameter is optional, but it is useful for generating
 * error messages when a CCI is requested by the selected STIG.
 *
 * When the @a cci does not exist in the database, an error message
 * is opened displaying the broken @a cci information. This function
 * is typically called by STIG import routines, and the failure
 * scenario is most often triggered by STIGs not mapped to CCIs that
 * are part of the latest NIST 800-53rev5. Some STIG checks were
 * errantly "mapped" by DISA to CCIs that were removed or replaced.
 *
 * Formerly, the CCI was supposed to be remapped to CCI-366; however,
 * new commands and updated eMASS implementations now map things
 * differently. A default CCI of ID -1 is returned when the CCI does
 * not exist.
 */
CCI DbManager::GetCCIByCCI(int cci, const STIG *stig)
{
    QVector<CCI> tmpList = GetCCIs(QStringLiteral("WHERE CCI.cci = :cci"), {std::make_tuple<QString, QVariant>(QStringLiteral(":cci"), cci)});
    if (!tmpList.isEmpty())
        return tmpList.first();
    QString tmpMessage = stig ? PrintSTIG(*stig) : QStringLiteral("&lt;insert%20STIG%20information%20here&gt;");
    QString cciStr = PrintCCI(cci);

    //The CCI could not be found. Assume that this will be remapped later.
    Warning(QStringLiteral("Broken CCI"), "The CCI " + cciStr + " does not exist in NIST 800-53r5. If you are importing a STIG, please file a bug with the STIG author (probably DISA, disa.stig_spt@mail.mil) and let them know that their CCI mapping for the STIG you are trying to import is broken. For now, this broken STIG check is being remapped to CCI-000366. <a href=\"mailto:disa.stig_spt@mail.mil?subject=Incorrectly%20Mapped%20STIG%20Check&body=DISA,%0d" + tmpMessage + "%20contains%20rule(s)%20mapped%20against%20" + cciStr + "%20which%20does%20not%20exist%20in%20the%20current%20version%20of%20NIST%20800-53r5.\">Click here</a> to file this bug with DISA automatically.");

    //If the CCI isn't in the database, provide unsuccessful default CCI.
    CCI ret;
    ret.cci = cci;
    return ret;
}

/**
 * @overload GetCCI
 * @brief DbManager::GetCCI
 * @param cci
 * @param stig
 * @return The @a CCI identified by the ID of the supplied @a cci.
 * If the @a cci.id is not valid, the actual @a cci.cci number is
 * used.
 */
CCI DbManager::GetCCI(const CCI &cci, const STIG *stig)
{
    if (cci.id < 0)
    {
        return GetCCIByCCI(cci.cci, stig);
    }
    return GetCCI(cci.id);
}

/**
 * @brief DbManager::GetCCIs
 * @param whereClause
 * @param variables
 * @return A QVector of @a CCIs that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetCCIs
 * @title default
 *
 * The default GetCCIs() with no parameters returns all CCIs in
 * the database.
 *
 * @code
 * DbManager db;
 * QVector<CCI> ccis = db.GetCCIs();
 * @endcode
 *
 * @example GetCCIsWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * int id = 4; //CCI ID 4 in the database
 * int sampleCCI = 366;
 *
 * //get CCI by ID
 * CCI cci = GetCCIs("WHERE id = :id",
 *                         {std::make_tuple<QString, QVariant>(":id", id)}
 *                  ).first();
 *
 * //get CCI by CCI number
 * cci = GetCCIs("WHERE cci = :cci",
 *                    {std::make_tuple<QString, QVariant>(":cci", sampleCCI)}
 *              ).first();
 *
 * //get CCI by ID and CCI number
 * cci = GetCCIs("WHERE id = :id AND cci = :cci"),
 *                   {
 *                       std::make_tuple<QString, QVariant>(":id", id),
 *                       std::make_tuple<QString, QVariant>(":cci", cci)
 *                   }).first();
 * @endcode
 */
QVector<CCI> DbManager::GetCCIs(const QString &whereClause, const QVector<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QVector<CCI> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT id, ControlId, cci, definition, isImport, importCompliance, importDateTested, importTestedBy, importTestResults, importCompliance2, importDateTested2, importTestedBy2, importTestResults2, importControlImplementationStatus, importSecurityControlDesignation, importInherited, importRemoteInheritanceInstance, importApNum, importImplementationGuidance, importAssessmentProcedures, importNarrative FROM CCI");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(QStringLiteral(" ORDER BY cci"));
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            CCI c;
            c.id = q.value(0).toInt();
            c.controlId = q.value(1).toInt();
            c.cci = q.value(2).toInt();
            c.definition = q.value(3).toString();
            c.isImport = q.value(4).toBool();
            c.importCompliance = q.value(5).toString();
            c.importDateTested = q.value(6).toString();
            c.importTestedBy = q.value(7).toString();
            c.importTestResults = q.value(8).toString();
            c.importCompliance2 = q.value(9).toString();
            c.importDateTested2 = q.value(10).toString();
            c.importTestedBy2 = q.value(11).toString();
            c.importTestResults2 = q.value(12).toString();
            c.importControlImplementationStatus = q.value(13).toString();
            c.importSecurityControlDesignation = q.value(14).toString();
            c.importInherited = q.value(15).toString();
            c.importRemoteInheritanceInstance = q.value(16).toString();
            c.importApNum = q.value(17).toString();
            c.importImplementationGuidance = q.value(18).toString();
            c.importAssessmentProcedures = q.value(19).toString();
            c.importNarrative = q.value(20).toString();

            ret.append(c);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetCKLCheck
 * @param id
 * @return The @a CKLCheck associated with the provided database
 * @a id.
 */
CKLCheck DbManager::GetCKLCheck(int id)
{
    QVector<CKLCheck> tmp = GetCKLChecks(QStringLiteral("WHERE CKLCheck.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});

    if (!tmp.isEmpty())
        return tmp.first();

    CKLCheck ret;
    Warning(QStringLiteral("Unable to Find CKLCheck"), "The CKLCheck of ID " + QString::number(id) + " was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetCKLCheck
 * @param ckl
 * @return The @a CKLCheck associated with the provided database
 * @a ckl.id. If the @a ckl.id is not set, the associated
 * @a ckl.assetId and @a ckl.stigCheckId are used to find the
 * @a CKLCheck in the database.
 */
CKLCheck DbManager::GetCKLCheck(const CKLCheck &ckl)
{
    QVector<CKLCheck> tmp;
    if (ckl.id <= 0)
    {
        tmp = GetCKLChecks(QStringLiteral("WHERE CKLCheck.AssetId = :AssetId AND CKLCheck.STIGCheckId = :STIGCheckId"),
            {std::make_tuple<QString, QVariant>(QStringLiteral(":AssetId"), ckl.assetId),
             std::make_tuple<QString, QVariant>(QStringLiteral(":STIGCheckId"), ckl.stigCheckId)});
    }
    else
    {
        tmp = GetCKLChecks(QStringLiteral("WHERE CKLCheck.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), ckl.id)});
    }

    if (!tmp.isEmpty())
        return tmp.first();

    CKLCheck ret;
    Warning(QStringLiteral("Unable to Find CKLCheck"), "The CKLCheck of ID " + QString::number(ckl.id) + " (asset " + QString::number(ckl.assetId) + ", " + QString::number(ckl.stigCheckId) + ") was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetCKLCheckByDISAId
 * @param assetId
 * @param disaId
 * @return The CKLCheck mapped against the provided @a assetId and
 * having the provided @a disaId.
 */
CKLCheck DbManager::GetCKLCheckByDISAId(int assetId, const QString &disaId)
{
    QVector<CKLCheck> ret = GetCKLChecks(QStringLiteral("WHERE AssetId = :AssetId AND STIGCheck.rule = :DISAId"), {
                        std::make_tuple<QString, QVariant>(QStringLiteral(":AssetId"), assetId),
                        std::make_tuple<QString, QVariant>(QStringLiteral(":DISAId"), disaId)
                    });

    if (!ret.isEmpty())
        return ret.first();

    CKLCheck check;
    return check;
}

/**
 * @overload DbManager::GetCKLChecks(const Asset &asset, const STIG &stig)
 * @brief DbManager::GetCKLChecks
 * @param asset
 * @param stig
 * @return The set of @a CKLChecks associated wth the supplied
 * @a Asset. If an optional @a STIG is provided, only the
 * @a CKLChecks also associated with that STIG are returned.
 */
QVector<CKLCheck> DbManager::GetCKLChecks(const Asset &asset, const STIG *stig)
{
    QString whereClause = QStringLiteral("WHERE CKLCheck.AssetId = :AssetId");
    QVector<std::tuple<QString, QVariant> > variables = {std::make_tuple<QString, QVariant>(QStringLiteral(":AssetId"), asset.id)};
    if (stig != nullptr)
    {
        whereClause.append(QStringLiteral(" AND CKLCheck.STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)"));
        variables.append(std::make_tuple<QString, QVariant>(QStringLiteral(":STIGId"), stig->id));
    }
    return GetCKLChecks(whereClause, variables);
}

/**
 * @overload DbManager::GetCKLChecks(const STIGCheck &stigCheck)
 * @brief DbManager::GetCKLChecks
 * @param stigCheck
 * @return The set of @a CKLChecks associated wth the supplied
 * @a STIGCheck.
 */
QVector<CKLCheck> DbManager::GetCKLChecks(const STIGCheck &stigCheck)
{
    QString whereClause = QStringLiteral("WHERE CKLCheck.STIGCheckId = :STIGCheckId");
    QVector<std::tuple<QString, QVariant> > variables = {std::make_tuple<QString, QVariant>(QStringLiteral(":STIGCheckId"), stigCheck.id)};
    return GetCKLChecks(whereClause, variables);
}

/**
 * @brief DbManager::GetCKLChecks
 * @param cci
 * @return The set of @a CKLChecks associated with the supplied
 * @a CCI.
 */
QVector<CKLCheck> DbManager::GetCKLChecks(const CCI &cci)
{
    return GetCKLChecks(QStringLiteral("WHERE STIGCheckId IN (SELECT STIGCheckId FROM STIGCheckCCI WHERE CCIId = :CCIId)"), {std::make_tuple<QString, QVariant>(QStringLiteral(":CCIId"), cci.id)});
}

/**
 * @brief DbManager::GetCKLChecks
 * @param whereClause
 * @param variables
 * @return A QVector of @a CKLChecks that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetCKLChecks
 * @title default
 *
 * The default GetCKLChecks() with no parameters returns all
 * CKLChecks in the database.
 *
 * @code
 * DbManager db;
 * QVector<CKLCheck> ckls = db.GetCKLChecks();
 * @endcode
 *
 * @example GetCKLChecksWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * Asset asset = GetAsset(1); //get the Asset with ID of 1 from the DB
 * STIG stig = GetSTIG(1); //get the STIG of ID 1 from the DB
 *
 * //get all CKLChecks associated with an Asset
 * List<CKLCheck> ckls = GetCKLChecks("WHERE AssetId = :AssetId",
 *                                         {std::make_tuple<QString, QVariant>(":AssetId", asset.id)}
 *                                   );
 *
 * //get CKLChecks associated with a particular STIG
 * ckls = GetCKLChecks("WHERE STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)",
 *                          {std::make_tuple<QString, QVariant>(":STIGId", stig.id)}
 *                    );
 *
 * //get CKLChecks associated wth a particular Asset and STIG
 * ckls = GetCKLChecks("WHERE AssetId = :AssetId AND STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)"),
 *                          {
 *                              std::make_tuple<QString, QVariant>(":AssetId", asset.id),
 *                              std::make_tuple<QString, QVariant>(":STIGId", stig.id)
 *                          });
 * @endcode
 */
QVector<CKLCheck> DbManager::GetCKLChecks(const QString &whereClause, const QVector<std::tuple<QString, QVariant> > &variables)
{
    QSqlDatabase db;
    QVector<CKLCheck> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT CKLCheck.id, CKLCheck.AssetId, CKLCheck.STIGCheckId, CKLCheck.status, CKLCheck.findingDetails, CKLCheck.comments, CKLCheck.severityOverride, CKLCheck.severityJustification, STIGCheck.severity, STIGCheck.rule, STIG.title, STIGCheck.title, STIGCheck.vulnNum FROM CKLCheck JOIN STIGCheck ON CKLCheck.STIGCheckId = STIGCheck.id JOIN STIG ON STIGCheck.STIGId = STIG.id");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            CKLCheck c;
            c.id = q.value(0).toInt();
            c.assetId = q.value(1).toInt();
            c.stigCheckId = q.value(2).toInt();
            c.status = static_cast<Status>(q.value(3).toInt());
            c.findingDetails = q.value(4).toString();
            c.comments = q.value(5).toString();
            c.severityOverride = static_cast<Severity>(q.value(6).toInt());
            c.severityJustification = q.value(7).toString();
            c._cachedSTIGSeverity = static_cast<Severity>(q.value(8).toInt());
            c._cachedRule = q.value(9).toString();
            c._cachedSTIGTitle = q.value(10).toString();
            c._cachedTitle = q.value(11).toString();
            c._cachedVulnerabilityId = q.value(12).toString();
            c._hasCachedSTIGData = true;

            ret.append(c);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetSTIGCheck
 * @param id
 * @return The @a STIGCheck associated with the provided database
 * @a id.
 */
STIGCheck DbManager::GetSTIGCheck(int id)
{
    QVector<STIGCheck> tmp = GetSTIGChecks(QStringLiteral("WHERE STIGCheck.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!tmp.isEmpty())
        return tmp.first();
    STIGCheck ret;
    Warning(QStringLiteral("Unable to Find STIGCheck"), "The STIGCheck of ID " + QString::number(id) + " was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetSTIGCheck
 * @param stig
 * @param rule
 * @return The @a STIGCheck associated with the provided @a STIG and
 * STIG Rule ID.
 */
STIGCheck DbManager::GetSTIGCheck(const STIG &stig, const QString &rule)
{
    //make sure that the STIG exists in the database
    STIG tmpStig = GetSTIG(stig);
    if (tmpStig.id > 0)
    {
        QVector<STIGCheck> tmp = GetSTIGChecks(QStringLiteral("WHERE STIGCheck.STIGId = :STIGId AND STIGCheck.rule = :rule"), {
                                                 std::make_tuple<QString, QVariant>(QStringLiteral(":STIGId"), tmpStig.id),
                                                 std::make_tuple<QString, QVariant>(QStringLiteral(":rule"), rule)
                                             });
        if (!tmp.isEmpty())
            return tmp.first();
    }
    STIGCheck ret;
    Warning(QStringLiteral("Unable to Find STIGCheck"), "The STIGCheck " + rule + " (STIG ID " + QString::number(stig.id) + ") was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetSTIGCheck
 * @param stigcheck
 * @param rule
 * @return The @a STIGCheck associated with the provided @a STIGCheck
 */
STIGCheck DbManager::GetSTIGCheck(const STIGCheck &stigcheck)
{
    //find STIGCheck by ID
    if (stigcheck.id > 0)
    {
        STIGCheck tmpSTIGCheck = GetSTIGCheck(stigcheck.id);
        if (tmpSTIGCheck.id > 0)
            return tmpSTIGCheck;
    }
    //if ID is not provided or isn't in DB, find by STIG parameters
    return GetSTIGCheck(stigcheck.GetSTIG(), stigcheck.rule);
}

/**
 * @brief DbManager::GetSTIGChecks
 * @param stig
 * @return All @a STIGChecks associated with the provided @a stig.
 */
QVector<STIGCheck> DbManager::GetSTIGChecks(const STIG &stig)
{
    return GetSTIGChecks(QStringLiteral("WHERE STIGCheck.STIGId = :STIGId"), {std::make_tuple<QString, QVariant>(QStringLiteral(":STIGId"), stig.id)});
}

/**
 * @brief DbManager::GetSTIGChecks
 * @param cci
 * @return All @a STIGChecks associated with the provided @a cci.
 */
QVector<STIGCheck> DbManager::GetSTIGChecks(const CCI &cci)
{
    return GetSTIGChecks(QStringLiteral("WHERE id IN (SELECT STIGCheckId FROM STIGCheckCCI WHERE CCIId = :CCIId)"), {std::make_tuple<QString, QVariant>(QStringLiteral(":CCIId"), cci.id)});
}

/**
 * @brief DbManager::GetSTIGChecks
 * @param whereClause
 * @param variables
 * @return A QVector of @a STIGCheck that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetSTIGChecks
 * @title default
 *
 * The default GetSTIGChecks() with no parameters returns all
 * STIGChecks in the database.
 *
 * @code
 * DbManager db;
 * QVector<STIGCheck> checks = db.GetSTIGChecks();
 * @endcode
 *
 * @example GetSTIGChecksWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * CCI cci = GetCCIByCCI(366); //get the CCI "CCI-000366" from the DB
 * STIG stig = GetSTIG(1); //get the STIG of ID 1 from the DB
 *
 * //get all STIGChecks associated with a CCI
 * List<STIGCheck> checks = GetSTIGChecks("WHERE CCIId = :CCIId",
 *                                             {std::make_tuple<QString, QVariant>(":CCIId", cci.id)}
 *                                       );
 *
 * //get CKLChecks associated with a particular STIG
 * checks = GetSTIGChecks("WHERE STIGId = :STIGId",
 *                             {std::make_tuple<QString, QVariant>(":STIGId", stig.id)}
 *                       );
 *
 * //get CKLChecks associated wth a particular CCI and STIG
 * checks = GetSTIGChecks("WHERE CCIId = :CCIId AND STIGId = :STIGId"),
 *                             {
 *                                 std::make_tuple<QString, QVariant>(":CCIId", cci.id),
 *                                 std::make_tuple<QString, QVariant>(":STIGId", stig.id)
 *                      });
 * @endcode
 */
QVector<STIGCheck> DbManager::GetSTIGChecks(const QString &whereClause, const QVector<std::tuple<QString, QVariant> > &variables)
{
    QSqlDatabase db;
    QVector<STIGCheck> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT `id`, `STIGId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls`, `targetKey`, `isRemap` FROM STIGCheck");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            STIGCheck c;
            c.id = q.value(0).toInt();
            c.stigId = q.value(1).toInt();
            c.rule = q.value(2).toString();
            c.vulnNum = q.value(3).toString();
            c.groupTitle = q.value(4).toString();
            c.ruleVersion = q.value(5).toString();
            c.severity = static_cast<Severity>(q.value(6).toInt());
            c.weight = q.value(7).toDouble();
            c.title = q.value(8).toString();
            c.vulnDiscussion = q.value(9).toString();
            c.falsePositives = q.value(10).toString();
            c.falseNegatives = q.value(11).toString();
            c.fix = q.value(12).toString();
            c.check = q.value(13).toString();
            c.documentable = q.value(14).toBool();
            c.mitigations = q.value(15).toString();
            c.severityOverrideGuidance = q.value(16).toString();
            c.checkContentRef = q.value(17).toString();
            c.potentialImpact = q.value(18).toString();
            c.thirdPartyTools = q.value(19).toString();
            c.mitigationControl = q.value(20).toString();
            c.responsibility = q.value(21).toString();
            c.iaControls = q.value(22).toString();
            c.targetKey = q.value(23).toString();
            c.isRemap = q.value(24).toBool();
            for (CCI cci : GetCCIs(c.id))
            {
                c.cciIds.append(cci.id);
            }
            for (QString legacyId : GetLegacyIds(c.id))
            {
                c.legacyIds.append(legacyId);
            }
            ret.append(c);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetSTIGs
 * @param asset
 * @return The @a STIGs in the database associated with the provided
 * @a Asset.
 */
QVector<STIG> DbManager::GetSTIGs(const Asset &asset)
{
    return GetSTIGs(QStringLiteral("WHERE STIG.id IN (SELECT STIGId FROM AssetSTIG WHERE AssetId = :AssetId)"), {std::make_tuple<QString, QVariant>(QStringLiteral(":AssetId"), asset.id)});
}

/**
 * @brief DbManager::GetSTIGs
 * @param whereClause
 * @param variables
 * @return A QVector of @a STIGs that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetSTIGs
 * @title default
 *
 * The default GetSTIGs() with no parameters returns all @a STIGs in
 * the database.
 *
 * @code
 * DbManager db;
 * QVector<STIG> stigs = db.GetSTIGs();
 * @endcode
 *
 * @example GetSTIGsWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * int id = 4; //STIG ID 4 in the database
 * QString sampleTitle = "Application Security and Development Security Technical Implementation Guide";
 *
 * //get STIG by ID
 * STIG stig = GetAssets("WHERE id = :id",
 *                            {std::make_tuple<QString, QVariant>(":id", id)}
 *                      ).first();
 *
 * //get STIG by STIG title
 * stig = GetSTIGs("WHERE title = :title",
 *                      {std::make_tuple<QString, QVariant>(":title", sampleTitle)}
 *                ).first();
 * @endcode
 */
QVector<STIG> DbManager::GetSTIGs(const QString &whereClause, const QVector<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QVector<STIG> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT id, title, description, release, version, benchmarkId, fileName FROM STIG");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(QStringLiteral(" ORDER BY LOWER(title), title"));
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            STIG s;
            s.id = q.value(0).toInt();
            s.title = q.value(1).toString();
            s.description = q.value(2).toString();
            s.release = q.value(3).toString();
            s.version = q.value(4).toInt();
            s.benchmarkId = q.value(5).toString();
            s.fileName = q.value(6).toString();
            ret.append(s);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetSupplements
 * @param stig
 * @return The list of @a Supplements associated with the provided @a STIG.
 */
QVector<Supplement> DbManager::GetSupplements(const STIG &stig)
{
    QSqlDatabase db;
    QVector<Supplement> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT id, path, contents FROM Supplement WHERE STIGId = :STIGId");
        q.prepare(toPrep);
        q.bindValue(QStringLiteral(":STIGId"), stig.id);
        q.exec();
        while (q.next())
        {
            Supplement s;
            s.id = q.value(0).toInt();
            s.STIGId = stig.id;
            s.path = q.value(1).toString();
            s.contents = q.value(2).toByteArray();
            ret.append(s);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetControl
 * @param id
 * @return The @a Control in the database associated with the
 * provided ID. If the @a Control does not exist in the database, the
 * default Control with an ID of -1 is returned.
 */
Control DbManager::GetControl(int id)
{
    QVector<Control> tmpControl = GetControls(QStringLiteral("WHERE Control.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!tmpControl.isEmpty())
        return tmpControl.first();
    Control ret;
    Warning(QStringLiteral("Control Not Found"), "The Control ID " + QString::number(id) + " was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetControl
 * @param control
 * @return The @a Control in the database associated with the
 * provided control string. If the @a Control does not exist in the
 * database, the default Control with an ID of -1 is returned.
 *
 * @example GetControl
 * @title Control Name Parsing
 *
 * @code
 * DbManager db;
 * Control control = db.GetControl("AC-1 (4)");
 * @endcode
 */
Control DbManager::GetControl(const QString &control)
{
    //see if there are spaces
    QString tmpControl = control.trimmed();
    int tmpIndex = tmpControl.indexOf(' ');
    if (tmpIndex > 0)
    {
        //see if there's a second space
        tmpIndex = tmpControl.indexOf(' ', tmpIndex+1);
        if (tmpIndex > 0)
        {
            tmpControl = tmpControl.left(tmpIndex+1).trimmed();
        }
    }
    QString family(tmpControl.left(2));
    tmpControl = tmpControl.right(tmpControl.length()-3);
    int enhancementInt = -1;
    if (tmpControl.contains('('))
    {
        tmpIndex = tmpControl.indexOf('(');
        QString enhancement = tmpControl.right(tmpControl.length() - tmpIndex - 1);
        enhancement = enhancement.left(enhancement.length() - 1);
        tmpControl = tmpControl.left(tmpControl.indexOf('('));
        enhancementInt = enhancement.toInt(); //will return 0 if enhancement doesn't exist
    }
    int controlNumber = tmpControl.trimmed().toInt();
    int familyId = GetFamily(family).id;

    QString whereClause = QStringLiteral("WHERE Control.number = :number AND Control.FamilyId = :FamilyId");
    QVector<std::tuple<QString, QVariant>> variables = {
        std::make_tuple<QString, QVariant>(QStringLiteral(":number"), controlNumber),
        std::make_tuple<QString, QVariant>(QStringLiteral(":FamilyId"), familyId)
    };

    if (enhancementInt > 0)
    {
        whereClause = whereClause + QStringLiteral(" AND Control.enhancement = :enhancement");
        variables.append(std::make_tuple<QString, QVariant>(QStringLiteral(":enhancement"), enhancementInt));
    }

    QVector<Control> tmpControls = GetControls(whereClause, variables);
    if (!tmpControls.isEmpty())
        return tmpControls.first();

    Control ret;
    Warning(QStringLiteral("Unable to Find Control"), "The Control '" + control + "' could not be found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetControls
 * @param whereClause
 * @param variables
 * @return A QVector of @a Controls that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * Since a @a Control cannot exist without a @a Family, the @a Family
 * table is automatically joined to the @a Control in the internal
 * query.
 *
 * @example GetControls
 * @title default
 *
 * The default GetControls() with no parameters returns all
 * @a Controls in the database.
 *
 * @code
 * DbManager db;
 * QVector<Control> controls = db.GetControls();
 * @endcode
 *
 * @example GetControlsWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * int id = 4; //Control ID 4 in the database
 *
 * //get Control by ID
 * Control control = GetControls("WHERE Control.id = :id",
 *                                    {std::make_tuple<QString, QVariant>(":id", id)}
 *                              ).first();
 *
 * //get Controls that relate to audit records
 * QVector<Control> controls = GetControls("WHERE Control.description LIKE :description",
 *                                            {std::make_tuple<QString, QVariant>(":description", "%audit record%")}
 *                                      );
 * @endcode
 */
QVector<Control> DbManager::GetControls(const QString &whereClause, const QVector<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QVector<Control> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT Control.id, Control.FamilyId, Control.number, Control.enhancement, Control.title, Control.description, Control.importSeverity, Control.importRelevanceOfThreat, Control.importLikelihood, Control.importImpact, Control.importImpactDescription, Control.importResidualRiskLevel, Control.importRecommendations FROM Control JOIN Family ON Family.id = Control.FamilyId");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(QStringLiteral(" ORDER BY Family.acronym, Control.number, Control.enhancement"));
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            Control c;
            c.id = q.value(0).toInt();
            c.familyId = q.value(1).toInt();
            c.number = q.value(2).toInt();
            c.enhancement = q.value(3).isNull() ? -1 : q.value(3).toInt();
            c.title = q.value(4).toString();
            c.description = q.value(5).toString();
	    c.importSeverity = q.value(6).toString();
	    c.importRelevanceOfThreat = q.value(7).toString();
	    c.importLikelihood = q.value(8).toString();
	    c.importImpact = q.value(9).toString();
	    c.importImpactDescription = q.value(10).toString();
	    c.importResidualRiskLevel = q.value(11).toString();
	    c.importRecommendations = q.value(12).toString();
            ret.append(c);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetDBPath
 * @return The path to the database file
 */
QString DbManager::GetDBPath()
{
    return _dbPath;
}

/**
 * @brief DbManager::GetFamily
 * @param id
 * @return The @a Family associated with the provided database @a id.
 * If the @a id is not in the database, the default @a Family with an
 * ID of -1 is returned.
 */
Family DbManager::GetFamily(int id)
{
    QVector<Family> tmpFamily = GetFamilies(QStringLiteral("WHERE Family.id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!tmpFamily.isEmpty())
        return tmpFamily.first();
    Family ret;
    Warning(QStringLiteral("Family Not Found"), "The Family associated with ID " + QString::number(id) + " could not be found.");
    return ret;
}

/**
 * @brief DbManager::GetLegacyIds
 * @param STIGCheckId
 * @return The list of Legacy IDs associated with this STIGCheck
 */
QVector<QString> DbManager::GetLegacyIds(int STIGCheckId)
{
    QVector<QString> ret;
    QSqlDatabase db;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT LegacyId FROM STIGCheckLegacyId WHERE STIGCheckLegacyId.STIGCheckId = :STIGCheckId"));
        q.bindValue(QStringLiteral(":STIGCheckId"), STIGCheckId);
        q.exec();
        while (q.next())
        {
            ret.append(q.value(0).toString());
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetLogLevel
 * @return the log level of the database
 *
 * This function is used for caching and multithreading optimization.
 */
int DbManager::GetLogLevel()
{
    if (_logLevel < 0)
        _logLevel = GetVariable(QStringLiteral("loglevel")).toInt();
    return _logLevel;
}

QVector<CCI> DbManager::GetRemapCCIs()
{
    CCI cci366 = GetCCIByCCI(366);

    if (GetVariable("remapCM6") == QStringLiteral("n"))
    {
        return {cci366};
    }

    QString isImportStr = IsEmassImport() ? QStringLiteral(" isImport > 0 AND") : QString();

    QVector<CCI> toRet = GetCCIs("WHERE" + isImportStr + " ControlId = (SELECT id FROM Control WHERE FamilyId = (SELECT id FROM Family WHERE Acronym = 'CM') AND number = 6 AND enhancement IS NULL)");

    if (!toRet.isEmpty())
        return toRet;

    return {cci366};
}

/**
 * @brief DbManager::GetFamily
 * @param acronym
 * @return The @a Family associated with the provided @a acronym. If
 * the @a acronym is not in the database, the default @a Family with
 * an ID of -1 is returned.
 */
Family DbManager::GetFamily(const QString &acronym)
{
    QVector<Family> tmpFamily = GetFamilies(QStringLiteral("WHERE Family.acronym = :acronym"), {std::make_tuple<QString, QVariant>(QStringLiteral(":acronym"), acronym)});
    if (!tmpFamily.isEmpty())
        return tmpFamily.first();
    Family ret;
    Warning(QStringLiteral("Family Not Found"), "The Family associated with " + acronym + " could not be found.");
    return ret;
}

/**
 * @brief DbManager::GetFamilies
 * @param whereClause
 * @param variables
 * @return A QVector of @a Families that are in the database. SQL
 * commands are dynamically built from an optional supplied
 * @a whereClause. SQL parameters are bound by supplying them in a
 * list of tuples in the @a variables parameter.
 *
 * @example GetFamilies
 * @title default
 *
 * The default GetFamilies() with no parameters returns all
 * @a Families in the database.
 *
 * @code
 * DbManager db;
 * QVector<Family> families = db.GetFamilies();
 * @endcode
 *
 * @example GetFamiliesWhere
 * @title where clause
 *
 * A WHERE clause with parameterized SQL can be added to the query.
 *
 * @code
 * DbManager db;
 * int id = 4; //Family ID 4 in the database
 * QString sampleAcronym = "AC";
 *
 * //get Family by ID
 * Family family = GetFamilies("WHERE Family.id = :id",
 *                                  {std::make_tuple<QString, QVariant>(":id", id)}
 *                            ).first();
 *
 * //get Family by Acronym
 * family = GetFamilies("WHERE Family.acronym = :acronym",
 *                           {std::make_tuple<QString, QVariant>(":acronym", "AC")}
 *                     ).first();
 * @endcode
 */
QVector<Family> DbManager::GetFamilies(const QString &whereClause, const QVector<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QVector<Family> ret;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = QStringLiteral("SELECT Family.id, Family.acronym, Family.description FROM Family");
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(QStringLiteral(" ORDER BY Family.acronym"));
        q.prepare(toPrep);
        for (const auto &variable : variables)
        {
            QString key;
            QVariant val;
            std::tie(key, val) = variable;
            q.bindValue(key, val);
        }
        q.exec();
        while (q.next())
        {
            Family f;
            f.id = q.value(0).toInt();
            f.acronym = q.value(1).toString();
            f.description = q.value(2).toString();
            ret.append(f);
        }
    }
    return ret;
}

/**
 * @brief DbManager::GetSTIG
 * @param id
 * @return The @a STIG associated with the provided database @a id.
 * If the @a STIG does not exist in the database, the default @a STIG
 * with an id of -1 is returned.
 */
STIG DbManager::GetSTIG(int id)
{
    QVector<STIG> tmpStigs = GetSTIGs(QStringLiteral("WHERE id = :id"), {std::make_tuple<QString, QVariant>(QStringLiteral(":id"), id)});
    if (!tmpStigs.isEmpty())
        return tmpStigs.first();
    STIG ret;
    Warning(QStringLiteral("Unable to Find STIG"), "The STIG of ID " + QString::number(id) + " was not found in the database.");
    return ret;
}

/**
 * @brief DbManager::GetSTIG
 * @param id
 * @return The @a STIG associated with the provided @a STIG metadata.
 * If the @a STIG does not exist in the database, the default @a STIG
 * with an id of -1 is returned.
 *
 * A @a STIG has an implied unique constraint formed with the
 * @a title, @a version, and @a release metadata.
 */
STIG DbManager::GetSTIG(const QString &title, int version, const QString &release)
{
    QVector<STIG> tmpStigs = GetSTIGs(QStringLiteral("WHERE title = :title AND release = :release AND version = :version"), {
                                        std::make_tuple<QString, QVariant>(QStringLiteral(":title"), title),
                                        std::make_tuple<QString, QVariant>(QStringLiteral(":release"), release),
                                        std::make_tuple<QString, QVariant>(QStringLiteral(":version"), version)
                                    });
    if (!tmpStigs.isEmpty())
        return tmpStigs.first();
    STIG ret;
    Warning(QStringLiteral("Unable to Find STIG"), "The following STIG has not been added to the master database (This is normal if you are attempting to import a new STIG that does not currently exist in the DB, and the new STIG will likely be inserted if there are no other errors.):\nTitle: " + title + "\nVersion: " + QString::number(version) + "\n" + release, true);
    return ret;
}

/**
 * @brief DbManager::GetSTIG
 * @param stig
 * @return The provided @a STIG is checked to make sure that it is
 * part of the database. If the provided @a stig.id is not in the
 * database, the metadata elements are checked. If the @a STIG is
 * still not found, the default @a STIG with an id of -1 is returned.
 */
STIG DbManager::GetSTIG(const STIG &stig)
{
    //find STIG by ID
    if (stig.id > 0)
    {
        STIG tmpSTIG = GetSTIG(stig.id);
        if (tmpSTIG.id > 0)
            return tmpSTIG;
    }
    //if ID is not provided or isn't in DB, find by STIG parameters
    return GetSTIG(stig.title, stig.version, stig.release);
}

/**
 * @brief DbManager::GetVariable
 * @param name
 * @return The value associated with the requested variable.
 *
 * The internal variables table stores program-related metadata, such
 * as the version of the database. This version number is checked
 * each time the database object is created to make sure that it is
 * valid.
 */
QString DbManager::GetVariable(const QString &name)
{
    QSqlDatabase db;
    QString ret = QString();
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT value FROM variables WHERE name = :name"));
        q.bindValue(QStringLiteral(":name"), name);
        q.exec();
        if (q.next())
        {
            ret = q.value(0).toString();
        }
    }
    return ret;
}

/**
 * @brief DbManager::IsEmassImport
 * @return \c True when an eMASS spreadsheet has been imported.
 * Otherwise, \c false.
 */
bool DbManager::IsEmassImport()
{
    QSqlDatabase db;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT COUNT(*) FROM CCI WHERE isImport > 0"));
        q.exec();
        if (q.next() && q.value(0).toInt() > 0)
        {
            return true;
        }
    }
    return false;
}
