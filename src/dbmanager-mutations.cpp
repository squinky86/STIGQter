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
 * @brief DbManager::AddAsset
 * @param asset
 * @return @c True when the @a Asset is added to the database,
 * @c false when the @a Asset is already part of the database or has
 * not been added.
 *
 * To add a new @a Asset to the database, a new @a Asset instance is
 * created in code and sent to this function. If the @a Asset has the
 * default @a id (or an @a id less than or equal to 0), it is assumed
 * to not be part of the database and is committed. On commit, the
 * provided @a Asset's @a id is set to the newly inserted record's
 * @a id.
 *
 * @a Assets must be uniquely named. A single Asset can have multiple
 * @a STIGs that are performed against it. A single computing node
 * usually qualifies as an @a Asset, and the individual components it
 * contains (the OS, applications, custom devices) have @a STIGs that
 * correspond to them. The hierarchy is
 * @a Asset → @a STIG → @a STIGCheck.
 *
 * Example: A single desktop computer will often have the following
 * @a STIGs: Windows 10, Internet Explorer, Microsoft Office (and its
 * subcomponents), FireFox, JRE, and Adobe.
 */
bool DbManager::AddAsset(Asset &asset)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);

        //check if Asset exists in the database
        q.prepare(QStringLiteral("SELECT count(*) FROM Asset WHERE hostName = :hostName"));
        q.bindValue(QStringLiteral(":hostName"), asset.hostName);
        q.exec();
        if (q.next() && q.value(0).toInt() > 0)
        {
            Warning(QStringLiteral("Asset Already Exists"), "The Asset " + PrintAsset(asset) + " already exists in the database.");
            return false;
        }
        q.prepare(QStringLiteral("INSERT INTO Asset (`assetType`, `hostName`, `hostIP`, `hostMAC`, `hostFQDN`, `techArea`, `targetKey`, `marking`, `targetComment`, `webOrDatabase`, `webDBSite`, `webDBInstance`) VALUES(:assetType, :hostName, :hostIP, :hostMAC, :hostFQDN, :techArea, :targetKey, :marking, :targetComment, :webOrDatabase, :webDBSite, :webDBInstance)"));
        q.bindValue(QStringLiteral(":assetType"), asset.assetType);
        q.bindValue(QStringLiteral(":hostName"), asset.hostName);
        q.bindValue(QStringLiteral(":hostIP"), asset.hostIP);
        q.bindValue(QStringLiteral(":hostMAC"), asset.hostMAC);
        q.bindValue(QStringLiteral(":hostFQDN"), asset.hostFQDN);
        q.bindValue(QStringLiteral(":techArea"), asset.techArea);
        q.bindValue(QStringLiteral(":targetKey"), asset.targetKey);
        q.bindValue(QStringLiteral(":marking"), asset.marking);
        q.bindValue(QStringLiteral(":targetComment"), asset.targetComment);
        q.bindValue(QStringLiteral(":webOrDatabase"), asset.webOrDB);
        q.bindValue(QStringLiteral(":webDBSite"), asset.webDbSite);
        q.bindValue(QStringLiteral(":webDBInstance"), asset.webDbInstance);
        ret = q.exec();
        db.commit();
        asset.id = q.lastInsertId().toInt();
        Log(6, QStringLiteral("AddAsset"), q);
    }
    return ret;
}

/**
 * @brief DbManager::AddCCI
 * @param cci
 * @param check
 * @return @c True when the @a CCI is added to the database,
 * @c false when the @a CCI is already part of the database or has
 * not been added.
 *
 * To add a new @a CCI to the database, a new @a CCI instance is
 * created in code and sent to this function. If the @a CCI has the
 * default @a id (or an @a id less than or equal to 0), it is assumed
 * to not be part of the database and is committed. On commit, the
 * provided @a CCI's @a id is set to the newly inserted record's
 * @a id.
 */
bool DbManager::AddCCI(CCI &cci, bool check)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);

        if (check)
        {
            //check if CCI already exists in the DB
            q.prepare(QStringLiteral("SELECT count(*) FROM CCI WHERE cci = :cci"));
            q.bindValue(QStringLiteral(":cci"), cci.cci);
            q.exec();
            if (q.next() && q.value(0).toInt() > 0)
            {
                Warning(QStringLiteral("CCI Already Exists"), "The CCI " + PrintCCI(cci) + " already exists in the database.", true);
                return ret;
            }
        }

        q.prepare(QStringLiteral("INSERT INTO CCI (ControlId, cci, definition) VALUES(:ControlId, :CCI, :definition)"));
        q.bindValue(QStringLiteral(":ControlId"), cci.controlId);
        q.bindValue(QStringLiteral(":CCI"), cci.cci);
        q.bindValue(QStringLiteral(":definition"), cci.definition);
        ret = q.exec();
        if (!_delayCommit)
        {
            db.commit();
            cci.id = q.lastInsertId().toInt();
        }
        Log(6, QStringLiteral("AddCCI"), q);
    }
    return ret;
}

/**
 * @brief DbManager::AddControl
 * @param control
 * @param title
 * @param description
 * @param importSeverity
 * @param importRelevanceOfThreat
 * @param importLikelihood
 * @param importImpact
 * @param importImpactDescription
 * @param importResidualRiskLevel
 * @param importRecommendations
 * @return @c True when the @a Control is added to the database,
 * @c false when the @a Control is already part of the database or
 * has not been added.
 *
 * When providing controls formatted as FAMILY-NUMBER (ENHANCEMENT),
 * this function parses the Family, Control Number, and Enhancement
 * Number out of the string before adding it to the database. This is
 * useful when receiving new @a Controls formatted in human-readable
 * format from an external data source.
 */
bool DbManager::AddControl(const QString &control, const QString &title, const QString &description, const QString &importSeverity, const QString &importRelevanceOfThreat, const QString &importLikelihood, const QString &importImpact, const QString &importImpactDescription, const QString &importResidualRiskLevel, const QString &importRecommendations)
{
    bool ret = false;

    QString tmpControl(control.trimmed());
    if (tmpControl.length() < 4)
    {
        //control length can't store the family and a control number.
        Warning(QStringLiteral("Control Does Not Exist"), "Received bad control, \"" + control + "\".", true);
    }
    else
    {
        //see if there are spaces
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
        QString enhancement = QString();
        if (tmpControl.contains('('))
        {
            //Attempt to parse the parenthesised portion of the control as an enhancement
            int tmpIndex2 = tmpControl.indexOf('(');
            enhancement = tmpControl.right(tmpControl.length() - tmpIndex2 - 1);
            enhancement = enhancement.left(enhancement.length() - 1);
            tmpControl = tmpControl.left(tmpControl.indexOf('('));
            //if it's not an integral, remove the enhancement
            if (enhancement.toInt() == 0)
                enhancement = QString();
        }

        //The family should already be in the database.
        Family f = GetFamily(family);

        if (f.id >= 0)
        {
            QSqlDatabase db;
            if (CheckDatabase(db))
            {
                QSqlQuery q(db);

                q.prepare(QStringLiteral("INSERT INTO Control (FamilyId, number, enhancement, title, description, importSeverity, importRelevanceOfThreat, importLikelihood, importImpact, importImpactDescription, importResidualRiskLevel, importRecommendations) VALUES(:FamilyId, :number, :enhancement, :title, :description, :importSeverity, :importRelevanceOfThreat, :importLikelihood, :importImpact, :importImpactDescription, :importResidualRiskLevel, :importRecommendations)"));
                q.bindValue(QStringLiteral(":FamilyId"), f.id);
                q.bindValue(QStringLiteral(":number"), tmpControl.toInt());
                q.bindValue(QStringLiteral(":enhancement"), enhancement.isEmpty() ? QVariant(QMetaType(QMetaType::Int)) : enhancement.toInt());
                q.bindValue(QStringLiteral(":title"), title);
                q.bindValue(QStringLiteral(":description"), description);
                q.bindValue(QStringLiteral(":importSeverity"), importSeverity);
                q.bindValue(QStringLiteral(":importRelevanceOfThreat"), importRelevanceOfThreat);
                q.bindValue(QStringLiteral(":importLikelihood"), importLikelihood);
                q.bindValue(QStringLiteral(":importImpact"), importImpact);
                q.bindValue(QStringLiteral(":importImpactDescription"), importImpactDescription);
                q.bindValue(QStringLiteral(":importResidualRiskLevel"), importResidualRiskLevel);
                q.bindValue(QStringLiteral(":importRecommendations"), importRecommendations);
                ret = q.exec();
                if (!_delayCommit)
                    db.commit();
                Log(6, QStringLiteral("AddControl"), q);
            }
        }
        else
        {
            //Family was not found in the database.
            Warning(QStringLiteral("Family Does Not Exist"), "The Family " + family + " does not exist in the database.");
        }
    }

    return ret;
}

/**
 * @brief DbManager::AddFamily
 * @param acronym
 * @param description
 * @return @c True when the @a Family is added to the database,
 * @c false when the @a Family is already part of the database or
 * has not been added.
 *
 * When parsing @a Families, the standard Acronym (which becomes
 * incorporated into the @a Control's human-readable presentation)
 * corresponds to a particular @a Family. The NIST 800-53rev5
 * @a Families are (obtained from
 * @l {https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final} {NIST}.):
 * @list
 * @li AC - Access Control
 * @li AT - Awareness and Training
 * @li AU - Audit and Accountability
 * @li CA - Assessment, Authorization, and Monitoring
 * @li CM - Configuration Management
 * @li CP - Contingency Planning
 * @li IA - Identification and Authentication
 * @li IR - Incident Response
 * @li MA - Maintenance
 * @li MP - Media Protection
 * @li PE - Physical and Environmental Protection
 * @li PL - Planning
 * @li PM - Program Management
 * @li PS - Personnel Security
 * @li PT - PII Processing and Transparency
 * @li RA - Risk Assessment
 * @li SA - System and Services Acquisition
 * @li SC - System and Communications Protection
 * @li SI - System and Information Integrity
 * @li SR - Supply Chain Risk Management
 * @endlist
 */
bool DbManager::AddFamily(const QString &acronym, const QString &description)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("INSERT INTO Family (Acronym, Description) VALUES(:acronym, :description)"));
        q.bindValue(QStringLiteral(":acronym"), acronym);
        q.bindValue(QStringLiteral(":description"), Sanitize(description));
        ret = q.exec();
        if (!_delayCommit)
            db.commit();
        Log(6, QStringLiteral("AddFamily"), q);
    }
    return ret;
}

/**
 * @brief DbManager::AddSTIG
 * @param stig
 * @param checks
 * @param supplements
 * @param stigExists
 * @return @c True when the @a STIG, its @a STIGChecks, and its
 * @a Supplements are added to the database, @c false when the any
 * part of the data have not been added.
 *
 * When @a stigExists is @c true, the @a STIGChecks are added to the
 * existing @a STIG already in the database. Otherwise, if the
 * @a STIG already exists, the @a STIGChecks are not added.
 */
bool DbManager::AddSTIG(STIG &stig, const QVector<STIGCheck> &checks, const QVector<Supplement> &supplements, bool stigExists)
{
    QSqlDatabase db;
    bool ret = false;
    bool stigCheckRet = true; //turns "false" if a check fails to be added

    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        QVector<CCI> remapCCIs = GetRemapCCIs();

        if (stig.id <= 0)
        {
            STIG tmpSTIG = GetSTIG(stig.title, stig.version, stig.release);
            if (tmpSTIG.id > 0)
            {
                if (stigExists)
                {
                    stig = tmpSTIG;
                }
                else
                {
                    Warning(QStringLiteral("STIG Already Exists"), "The STIG " + PrintSTIG(stig) + " already exists in the database.");
                    return ret;
                }
            }
            else
            {
                q.prepare(QStringLiteral("INSERT INTO STIG (title, description, release, version, benchmarkId, fileName) VALUES(:title, :description, :release, :version, :benchmarkId, :fileName)"));
                q.bindValue(QStringLiteral(":title"), stig.title);
                q.bindValue(QStringLiteral(":description"), stig.description);
                q.bindValue(QStringLiteral(":release"), stig.release);
                q.bindValue(QStringLiteral(":version"), stig.version);
                q.bindValue(QStringLiteral(":benchmarkId"), stig.benchmarkId);
                q.bindValue(QStringLiteral(":fileName"), stig.fileName);
                ret = q.exec();
                stig.id = q.lastInsertId().toInt();
                //do not delay this commit; the STIG should be added to the DB to prevent inconsistencies with adding the checks.
                db.commit();
                Log(6, QStringLiteral("AddSTIG"), q);
            }
        }
        if (stig.id <= 0)
        {
            Warning(QStringLiteral("Unable to Add STIG"), "The new STIG, " + PrintSTIG(stig) + ", could not be added to the database.");
            return ret;
        }
        ret = true; // we have a valid STIG
        bool newChecks = false;
        //store the old value of the "delay commit" feature. The STIGCheck additions will always be a delayed commit.
        bool delayed = _delayCommit;
        if (!delayed)
            this->DelayCommit(true);

        for (STIGCheck c : checks)
        {
            newChecks = true;
            q.prepare(QStringLiteral("INSERT INTO STIGCheck (`STIGId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls`, `targetKey`, `isRemap`) VALUES(:STIGId, :rule, :vulnNum, :groupTitle, :ruleVersion, :severity, :weight, :title, :vulnDiscussion, :falsePositives, :falseNegatives, :fix, :check, :documentable, :mitigations, :severityOverrideGuidance, :checkContentRef, :potentialImpact, :thirdPartyTools, :mitigationControl, :responsibility, :IAControls, :targetKey, :isRemap)"));
            q.bindValue(QStringLiteral(":STIGId"), stig.id);
            q.bindValue(QStringLiteral(":rule"), c.rule);
            q.bindValue(QStringLiteral(":vulnNum"), c.vulnNum);
            q.bindValue(QStringLiteral(":groupTitle"), c.groupTitle);
            q.bindValue(QStringLiteral(":ruleVersion"), c.ruleVersion);
            q.bindValue(QStringLiteral(":severity"), c.severity);
            q.bindValue(QStringLiteral(":weight"), c.weight);
            q.bindValue(QStringLiteral(":title"), c.title);
            q.bindValue(QStringLiteral(":vulnDiscussion"), c.vulnDiscussion);
            q.bindValue(QStringLiteral(":falsePositives"), c.falsePositives);
            q.bindValue(QStringLiteral(":falseNegatives"), c.falseNegatives);
            q.bindValue(QStringLiteral(":fix"), c.fix);
            q.bindValue(QStringLiteral(":check"), c.check);
            q.bindValue(QStringLiteral(":documentable"), c.documentable ? 1 : 0);
            q.bindValue(QStringLiteral(":mitigations"), c.mitigations);
            q.bindValue(QStringLiteral(":severityOverrideGuidance"), c.severityOverrideGuidance);
            q.bindValue(QStringLiteral(":checkContentRef"), c.checkContentRef);
            q.bindValue(QStringLiteral(":potentialImpact"), c.potentialImpact);
            q.bindValue(QStringLiteral(":thirdPartyTools"), c.thirdPartyTools);
            q.bindValue(QStringLiteral(":mitigationControl"), c.mitigationControl);
            q.bindValue(QStringLiteral(":responsibility"), c.responsibility);
            q.bindValue(QStringLiteral(":IAControls"), c.iaControls);
            q.bindValue(QStringLiteral(":targetKey"), c.targetKey);
            q.bindValue(QStringLiteral(":isRemap"), (c.isRemap || c.cciIds.isEmpty()) ? 1 : 0);
            bool tmpRet = q.exec();
            stigCheckRet = stigCheckRet && tmpRet;
            if (!tmpRet)
            {
                //for every check that can't be added, pop a warning.
                Warning(QStringLiteral("Unable to Add STIGCheck"), "The STIGCheck " + PrintSTIGCheck(c) + " could not be added to STIG " + PrintSTIG(stig) + ".");
            }
            int STIGCheckId = q.lastInsertId().toInt();
            Log(6, QStringLiteral("AddSTIG-check"), q);
            if (STIGCheckId > 0)
            {
                //check if the STIG is mapped to at least one CCI
                if (c.cciIds.isEmpty())
                {
                    c.isRemap = true;
                    QString remapCCIsStr = QString();
                    for (CCI cci : remapCCIs)
                    {
                        if (!remapCCIsStr.isEmpty())
                            remapCCIsStr = remapCCIsStr + QStringLiteral(", ");
                        remapCCIsStr = remapCCIsStr + PrintCCI(cci);
                        c.cciIds.append(cci.id);
                    }
                    Warning(QStringLiteral("Broken CCI"), "The STIGCheck rule " + c.rule + " is not mapped against a known CCI. If you are importing a STIG, please file a bug with the STIG author (probably DISA, disa.stig_spt@mail.mil) and let them know that their CCI mapping for the STIG you are trying to import is broken. For now, this broken STIG check is being remapped to " + remapCCIsStr + ". <a href=\"mailto:disa.stig_spt@mail.mil?subject=Incorrectly%20Mapped%20STIG%20Check&body=DISA,%0d" + PrintSTIG(stig) + "%20contains%20rule%20" + c.rule + "%20mapped%20against%20an%20unknown%20CCI%20which%20does%20not%20exist%20in%20the%20current%20version%20of%20NIST%20800-53r5.\">Click here</a> to file this bug with DISA automatically.");
                }

                for (int cciId : c.cciIds)
                {
                    q.prepare(QStringLiteral("INSERT INTO STIGCheckCCI (`STIGCheckId`, `CCIId`) VALUES(:STIGCheckId, :CCIId)"));
                    q.bindValue(QStringLiteral(":STIGCheckId"), STIGCheckId);
                    q.bindValue(QStringLiteral(":CCIId"), cciId);
                    ret = q.exec() && ret;
                    Log(6, QStringLiteral("AddAsset-CCI"), q);
                }

                for (QString legacyId : c.legacyIds)
                {
                    q.prepare(QStringLiteral("INSERT INTO STIGCheckLegacyId (`STIGCheckId`, `LegacyId`) VALUES(:STIGCheckId, :LegacyId)"));
                    q.bindValue(QStringLiteral(":STIGCheckId"), STIGCheckId);
                    q.bindValue(QStringLiteral(":LegacyId"), legacyId);
                    ret = q.exec() && ret;
                    Log(6, QStringLiteral("AddAsset-LegacyIds"), q);
                }
            }
        }

        for (auto supplement : supplements)
        {
            newChecks = true;
            q.prepare(QStringLiteral("INSERT INTO Supplement (`STIGId`, `path`, `contents`) VALUES(:STIGId, :path, :contents)"));
            q.bindValue(QStringLiteral(":STIGId"), stig.id);
            q.bindValue(QStringLiteral(":path"), supplement.path);
            q.bindValue(QStringLiteral(":contents"), supplement.contents);
            ret = q.exec() && ret;
            Log(6, QStringLiteral("AddAsset-Supplement"), q);
        }

        //restore the old value of the "delayed commit" feature
        if (!delayed)
        {
            this->DelayCommit(false);
        }
        if (newChecks)
            db.commit();
    }
    return ret && stigCheckRet;
}

/**
 * @brief DbManager::AddSTIGCheck
 * @param stig
 * @param check
 * @return @c true when the @a check was added to the database.
 *
 * Adds a single @a STIGCheck to an existing @a STIG. This is used by the
 * STIG editor to author new checks. Unlike @a AddSTIG, a freshly authored
 * check is allowed to start with no @a CCI mapping, so no remap-to-CCI-366
 * warning is raised here. On success, @a check.id is populated with the new
 * database id.
 */
bool DbManager::AddSTIGCheck(const STIG &stig, STIGCheck &check)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("INSERT INTO STIGCheck (`STIGId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls`, `targetKey`, `isRemap`) VALUES(:STIGId, :rule, :vulnNum, :groupTitle, :ruleVersion, :severity, :weight, :title, :vulnDiscussion, :falsePositives, :falseNegatives, :fix, :check, :documentable, :mitigations, :severityOverrideGuidance, :checkContentRef, :potentialImpact, :thirdPartyTools, :mitigationControl, :responsibility, :IAControls, :targetKey, :isRemap)"));
        q.bindValue(QStringLiteral(":STIGId"), stig.id);
        q.bindValue(QStringLiteral(":rule"), check.rule);
        q.bindValue(QStringLiteral(":vulnNum"), check.vulnNum);
        q.bindValue(QStringLiteral(":groupTitle"), check.groupTitle);
        q.bindValue(QStringLiteral(":ruleVersion"), check.ruleVersion);
        q.bindValue(QStringLiteral(":severity"), check.severity);
        q.bindValue(QStringLiteral(":weight"), check.weight);
        q.bindValue(QStringLiteral(":title"), check.title);
        q.bindValue(QStringLiteral(":vulnDiscussion"), check.vulnDiscussion);
        q.bindValue(QStringLiteral(":falsePositives"), check.falsePositives);
        q.bindValue(QStringLiteral(":falseNegatives"), check.falseNegatives);
        q.bindValue(QStringLiteral(":fix"), check.fix);
        q.bindValue(QStringLiteral(":check"), check.check);
        q.bindValue(QStringLiteral(":documentable"), check.documentable ? 1 : 0);
        q.bindValue(QStringLiteral(":mitigations"), check.mitigations);
        q.bindValue(QStringLiteral(":severityOverrideGuidance"), check.severityOverrideGuidance);
        q.bindValue(QStringLiteral(":checkContentRef"), check.checkContentRef);
        q.bindValue(QStringLiteral(":potentialImpact"), check.potentialImpact);
        q.bindValue(QStringLiteral(":thirdPartyTools"), check.thirdPartyTools);
        q.bindValue(QStringLiteral(":mitigationControl"), check.mitigationControl);
        q.bindValue(QStringLiteral(":responsibility"), check.responsibility);
        q.bindValue(QStringLiteral(":IAControls"), check.iaControls);
        q.bindValue(QStringLiteral(":targetKey"), check.targetKey);
        q.bindValue(QStringLiteral(":isRemap"), check.isRemap ? 1 : 0);
        ret = q.exec();
        Log(6, QStringLiteral("AddSTIGCheck"), q);
        if (ret)
        {
            check.id = q.lastInsertId().toInt();
            check.stigId = stig.id;

            for (int cciId : check.cciIds)
            {
                q.prepare(QStringLiteral("INSERT INTO STIGCheckCCI (`STIGCheckId`, `CCIId`) VALUES(:STIGCheckId, :CCIId)"));
                q.bindValue(QStringLiteral(":STIGCheckId"), check.id);
                q.bindValue(QStringLiteral(":CCIId"), cciId);
                ret = q.exec() && ret;
                Log(6, QStringLiteral("AddSTIGCheck-CCI"), q);
            }

            for (const QString &legacyId : check.legacyIds)
            {
                q.prepare(QStringLiteral("INSERT INTO STIGCheckLegacyId (`STIGCheckId`, `LegacyId`) VALUES(:STIGCheckId, :LegacyId)"));
                q.bindValue(QStringLiteral(":STIGCheckId"), check.id);
                q.bindValue(QStringLiteral(":LegacyId"), legacyId);
                ret = q.exec() && ret;
                Log(6, QStringLiteral("AddSTIGCheck-LegacyId"), q);
            }
        }
        if (!_delayCommit)
            db.commit();
    }
    return ret;
}

/**
 * @brief DbManager::AddSTIGToAsset
 * @param stig
 * @param asset
 * @return @c True when the @a STIG is mapped to the @a Asset.
 * Otherwise, @c false.
 *
 * When a @a STIG is mapped to an @a Asset, a new STIG Checklist
 * is created for the Asset, and all of the @a STIG's @a STIGChecks
 * are added to the @a CKLCheck with a default status of
 * @a Status.NotChecked.
 */
bool DbManager::AddSTIGToAsset(const STIG &stig, const Asset &asset)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        //check if Asset and STIG exist
        Asset tmpAsset = GetAsset(asset);
        STIG tmpSTIG = GetSTIG(stig);

        //if so, attempt to add the relationship to the DB
        if (tmpAsset.id > 0 && tmpSTIG.id > 0)
        {
            QSqlQuery q(db);
                q.prepare(QStringLiteral("INSERT INTO AssetSTIG (`AssetId`, `STIGId`) VALUES(:AssetId, :STIGId)"));
                q.bindValue(QStringLiteral(":AssetId"), tmpAsset.id);
                q.bindValue(QStringLiteral(":STIGId"), tmpSTIG.id);
                ret = q.exec();
                Log(6, QStringLiteral("AddSTIGToAsset"), q);
                if (ret)
                {
                    q.prepare(QStringLiteral("INSERT INTO CKLCheck (AssetId, STIGCheckId, status, findingDetails, comments, severityOverride, severityJustification) SELECT :AssetId, id, :status, '', '', '', '' FROM STIGCheck WHERE STIGId = :STIGId"));
                    q.bindValue(QStringLiteral(":AssetId"), tmpAsset.id);
                    q.bindValue(QStringLiteral(":status"), Status::NotReviewed);
                    q.bindValue(QStringLiteral(":STIGId"), tmpSTIG.id);
                    ret = q.exec();
                    db.commit();
                    Log(6, QStringLiteral("AddSTIGToAsset-2"), q);
                }
        }
    }
    return ret;
}

/**
 * @override DbManager::DeleteAsset(Asset)
 * @brief DbManager::DeleteAsset
 * @param id
 * @return @c True when the supplied @a Asset with the supplied @a id
 * is removed from the database. Otherwise, @c false.
 */
bool DbManager::DeleteAsset(int id)
{
    return DeleteAsset(GetAsset(id));
}

/**
 * @brief DbManager::DeleteAsset
 * @param asset
 * @return @c True when the supplied @a Asset with the supplied @a id
 * is removed from the database. Otherwise, @c false.
 */
bool DbManager::DeleteAsset(const Asset &asset)
{
    bool ret = false;
    if (asset.GetSTIGs().isEmpty())
    {
        QSqlDatabase db;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("DELETE FROM Asset WHERE id = :AssetId"));
            q.bindValue(QStringLiteral(":AssetId"), asset.id);
            ret = q.exec();
            if (!_delayCommit)
                db.commit();
            Log(6, QStringLiteral("DeleteAsset"), q);
        }
    }
    else
    {
        Warning(QStringLiteral("Asset Has Mapped STIGs"), "The Asset '" + PrintAsset(asset) + "' has STIGs selected that must be removed.");
    }

    return ret;
}

/**
 * @brief DbManager::DeleteCCIs
 * @return @c True when the CCIs and controls are cleared from the
 * database. Otherwise, @c false.
 *
 * Removes RMF @a Controls and @a CCIs from the database.
 */
bool DbManager::DeleteCCIs()
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        ret = true; //assume success until one of the queries fails.
        QSqlQuery q(db);
        q.prepare(QStringLiteral("DELETE FROM Family"));
        ret = q.exec() && ret; //q.exec() first to avoid short-circuit evaluation
        Log(6, QStringLiteral("DeleteCCIs-Family"), q);
        q.prepare(QStringLiteral("DELETE FROM Control"));
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteCCIs-Control"), q);
        q.prepare(QStringLiteral("DELETE FROM CCI"));
        ret = q.exec() && ret;
        if (!_delayCommit)
            db.commit();
        Log(6, QStringLiteral("DeleteCCIs-CCI"), q);
    }
    return ret;
}

/**
 * @brief DbManager::DeleteDB
 * @return @c True when the database is recreated. Otherwise,
 * @c false.
 */
bool DbManager::DeleteDB()
{
    QFile dest(_dbPath);
    if (dest.open(QFile::WriteOnly))
    {
        dest.write("", 0);
        dest.close();
        return UpdateDatabaseFromVersion(0);
    }
    return false;
}

/**
 * @brief DbManager::DeleteEmassImport
 * @return \c True when the eMASS import is deleted. Otherwise,
 * \c false.
 */
bool DbManager::DeleteEmassImport()
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("UPDATE CCI SET isImport = 0, importCompliance = NULL, importDateTested = NULL, importTestedBy = NULL, importTestResults = NULL, importCompliance2 = NULL, importDateTested2 = NULL, importTestedBy2 = NULL, importTestResults2 = NULL, importControlImplementationStatus = NULL, importSecurityControlDesignation = NULL, importInherited = NULL, importRemoteInheritanceInstance = NULL, importApNum = NULL, importImplementationGuidance = NULL, importAssessmentProcedures = NULL, importNarrative = NULL"));
        ret = q.exec();
        if (!_delayCommit)
            db.commit();
        Log(6, QStringLiteral("DeleteEmassImport"), q);
    }
    return ret;
}

/**
 * @brief DbManager::DeleteSTIG
 * @param id
 * @return @c True when the STIG identified by the provided ID is
 * deleted from the database. Otherwise, @c false.
 */
bool DbManager::DeleteSTIG(int id)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        //check if this STIG is used by any Assets
        STIG tmpStig = GetSTIG(id);
        QVector<Asset> assets = tmpStig.GetAssets();
        int tmpCount = assets.count();
        if (tmpCount > 0)
        {
            QString tmpAssetStr = QString();
            for (const Asset &a : assets)
            {
                tmpAssetStr.append(" '" + PrintAsset(a) + "'");
            }
            Warning(QStringLiteral("STIG In Use"), "The Asset" + Pluralize(tmpCount) + tmpAssetStr + " " + Pluralize(tmpCount, QStringLiteral("are"), QStringLiteral("is")) + " currently using the selected STIG.");
            return ret;
        }
        QSqlQuery q(db);
        ret = true; //assume success from here.
        q.prepare(QStringLiteral("DELETE FROM STIGCheckCCI WHERE STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)"));
        q.bindValue(QStringLiteral(":STIGId"), id);
        ret = q.exec() && ret; //q.exec() first toavoid short-circuit evaluation
        q.prepare(QStringLiteral("DELETE FROM STIGCheckLegacyId WHERE STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)"));
        q.bindValue(QStringLiteral(":STIGId"), id);
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteSTIG-STIGCheckCCI"), q);
        q.prepare(QStringLiteral("DELETE FROM STIGCheck WHERE STIGId = :STIGId"));
        q.bindValue(QStringLiteral(":STIGId"), id);
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteSTIG-STIGCheck"), q);
        q.prepare(QStringLiteral("DELETE FROM Supplement WHERE STIGId = :STIGId"));
        q.bindValue(QStringLiteral(":STIGId"), id);
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteSTIG-Supplement"), q);
        q.prepare(QStringLiteral("DELETE FROM STIG WHERE id = :id"));
        q.bindValue(QStringLiteral(":id"), id);
        ret = q.exec() && ret;
        if (!_delayCommit)
            db.commit();
        Log(6, QStringLiteral("DeleteSTIG-STIG"), q);
    }
    return ret;
}

/**
 * @override DbManager::DeleteSTIG(int id)
 * @brief DbManager::DeleteSTIG
 * @param stig
 * @return @c True when the supplied @a STIG is removed rom the
 * database. Otherwise, @c false.
 */
bool DbManager::DeleteSTIG(const STIG &stig)
{
    return DeleteSTIG(stig.id);
}

/**
 * @brief DbManager::DeleteSTIGCheck
 * @param check
 * @return @c true when the @a STIGCheck (and its CCI/legacy-id mappings)
 * has been removed from the database.
 *
 * Removes a single @a STIGCheck from a @a STIG. Child rows are deleted
 * before the check itself, mirroring the ordering used by @a DeleteSTIG.
 */
bool DbManager::DeleteSTIGCheck(const STIGCheck &check)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        ret = true; //assume success from here.
        q.prepare(QStringLiteral("DELETE FROM STIGCheckCCI WHERE STIGCheckId = :STIGCheckId"));
        q.bindValue(QStringLiteral(":STIGCheckId"), check.id);
        ret = q.exec() && ret; //q.exec() first to avoid short-circuit evaluation
        q.prepare(QStringLiteral("DELETE FROM STIGCheckLegacyId WHERE STIGCheckId = :STIGCheckId"));
        q.bindValue(QStringLiteral(":STIGCheckId"), check.id);
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteSTIGCheck-mappings"), q);
        q.prepare(QStringLiteral("DELETE FROM STIGCheck WHERE id = :id"));
        q.bindValue(QStringLiteral(":id"), check.id);
        ret = q.exec() && ret;
        Log(6, QStringLiteral("DeleteSTIGCheck-STIGCheck"), q);
        if (!_delayCommit)
            db.commit();
    }
    return ret;
}

/**
 * @brief DbManager::DeleteSTIGFromAsset
 * @param stig
 * @param asset
 * @return @c True when the @a STIG has been disassociated with the
 * @a Asset in the database. Otherwise, @c false.
 */
bool DbManager::DeleteSTIGFromAsset(const STIG &stig, const Asset &asset)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        //make sure the STIG and Asset exist in th database
        STIG tmpSTIG = GetSTIG(stig);
        Asset tmpAsset = GetAsset(asset);

        if (tmpSTIG.id > 0 && tmpAsset.id > 0)
        {
            QSqlQuery q(db);
            ret = true; //assume success from this point
            q.prepare(QStringLiteral("DELETE FROM AssetSTIG WHERE AssetId = :AssetId AND STIGId = :STIGId"));
            q.bindValue(QStringLiteral(":AssetId"), tmpAsset.id);
            q.bindValue(QStringLiteral(":STIGId"), tmpSTIG.id);
            ret = q.exec() && ret; //q.exec() first to avoid short-circuit execution
            Log(6, QStringLiteral("DeleteSTIGFromAsset-AssetSTIG"), q);
            q.prepare(QStringLiteral("DELETE FROM CKLCheck WHERE AssetId = :AssetId AND STIGCheckId IN (SELECT id FROM STIGCheck WHERE STIGId = :STIGId)"));
            q.bindValue(QStringLiteral(":AssetId"), tmpAsset.id);
            q.bindValue(QStringLiteral(":STIGId"), tmpSTIG.id);
            ret = q.exec() && ret;
            db.commit();
            Log(6, QStringLiteral("DeleteSTIGFromAsset-CKLCheck"), q);
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateAsset
 * @param asset
 * @return \c True when the Asset is updated with the provided
 * metadata. Otherwise, \c false.
 */
bool DbManager::UpdateAsset(const Asset &asset)
{
    Asset tmpAsset = GetAsset(asset);
    bool ret = false;
    if (tmpAsset.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            //NOTE: The new values use the provided "cci" while the WHERE clause uses the Database-identified "tmpCCI".
            q.prepare(QStringLiteral("UPDATE Asset SET assetType = :assetType, hostName = :hostName, hostIP = :hostIP, hostMAC = :hostMAC, hostFQDN = :hostFQDN, techArea = :techArea, targetKey = :targetKey, marking = :marking, targetComment = :targetComment, webOrDatabase = :webOrDatabase, webDBSite = :webDBSite, webDBInstance = :webDBInstance WHERE id = :id"));
            q.bindValue(QStringLiteral(":assetType"), asset.assetType.isEmpty() ? nullptr : asset.assetType);
            q.bindValue(QStringLiteral(":hostName"), asset.hostName);
            q.bindValue(QStringLiteral(":hostIP"), asset.hostIP.isEmpty() ? nullptr : asset.hostIP);
            q.bindValue(QStringLiteral(":hostMAC"), asset.hostMAC.isEmpty() ? nullptr : asset.hostMAC);
            q.bindValue(QStringLiteral(":hostFQDN"), asset.hostFQDN.isEmpty() ? nullptr : asset.hostFQDN);
            q.bindValue(QStringLiteral(":techArea"), asset.techArea.isEmpty() ? nullptr : asset.techArea);
            q.bindValue(QStringLiteral(":targetKey"), asset.targetKey.isEmpty() ? nullptr : asset.targetKey);
            q.bindValue(QStringLiteral(":marking"), asset.marking.isEmpty() ? nullptr : asset.marking);
            q.bindValue(QStringLiteral(":targetComment"), asset.targetComment.isEmpty() ? nullptr : asset.targetComment);
            q.bindValue(QStringLiteral(":webOrDatabase"), asset.webOrDB);
            q.bindValue(QStringLiteral(":webDBSite"), asset.webDbSite.isEmpty() ? nullptr : asset.webDbSite);
            q.bindValue(QStringLiteral(":webDBInstance"), asset.webDbInstance.isEmpty() ? nullptr : asset.webDbInstance);
            q.bindValue(QStringLiteral(":id"), tmpAsset.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateAsset"), q);
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateCCI
 * @param cci
 * @return \c True when the CCI is updated with the provided
 * metadata. Otherwise, \c false.
 */
bool DbManager::UpdateCCI(const CCI &cci)
{
    CCI tmpCCI = GetCCI(cci);
    bool ret = false;
    if (tmpCCI.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            //NOTE: The new values use the provided "cci" while the WHERE clause uses the Database-identified "tmpCCI".
            q.prepare(QStringLiteral("UPDATE CCI SET ControlId = :ControlId, cci = :cci, definition = :definition, isImport = :isImport, importCompliance = :importCompliance, importDateTested = :importDateTested, importTestedBy = :importTestedBy, importTestResults = :importTestResults, importCompliance2 = :importCompliance2, importDateTested2 = :importDateTested2, importTestedBy2 = :importTestedBy2, importTestResults2 = :importTestResults2, importControlImplementationStatus = :importControlImplementationStatus, importSecurityControlDesignation = :importSecurityControlDesignation, importInherited = :importInherited, importRemoteInheritanceInstance = :importRemoteInheritanceInstance, importApNum = :importApNum, importImplementationGuidance = :importImplementationGuidance, importAssessmentProcedures = :importAssessmentProcedures, importNarrative = :importNarrative WHERE id = :id"));
            q.bindValue(QStringLiteral(":ControlId"), cci.controlId);
            q.bindValue(QStringLiteral(":cci"), cci.cci);
            q.bindValue(QStringLiteral(":definition"), cci.definition);
            q.bindValue(QStringLiteral(":isImport"), cci.isImport);
            q.bindValue(QStringLiteral(":importCompliance"), cci.isImport ? cci.importCompliance : nullptr);
            q.bindValue(QStringLiteral(":importDateTested"), cci.isImport ? cci.importDateTested : nullptr);
            q.bindValue(QStringLiteral(":importTestedBy"), cci.isImport ? cci.importTestedBy : nullptr);
            q.bindValue(QStringLiteral(":importTestResults"), cci.isImport ? cci.importTestResults : nullptr);
            q.bindValue(QStringLiteral(":importCompliance2"), cci.isImport ? cci.importCompliance2 : nullptr);
            q.bindValue(QStringLiteral(":importDateTested2"), cci.isImport ? cci.importDateTested2 : nullptr);
            q.bindValue(QStringLiteral(":importTestedBy2"), cci.isImport ? cci.importTestedBy2 : nullptr);
            q.bindValue(QStringLiteral(":importTestResults2"), cci.isImport ? cci.importTestResults2 : nullptr);
            q.bindValue(QStringLiteral(":importControlImplementationStatus"), cci.isImport ? cci.importControlImplementationStatus : nullptr);
            q.bindValue(QStringLiteral(":importSecurityControlDesignation"), cci.isImport ? cci.importSecurityControlDesignation : nullptr);
            q.bindValue(QStringLiteral(":importInherited"), cci.isImport ? cci.importInherited : nullptr);
            q.bindValue(QStringLiteral(":importRemoteInheritanceInstance"), cci.isImport ? cci.importRemoteInheritanceInstance : nullptr);
            q.bindValue(QStringLiteral(":importApNum"), cci.isImport ? cci.importApNum : nullptr);
            q.bindValue(QStringLiteral(":importImplementationGuidance"), cci.isImport ? cci.importImplementationGuidance : nullptr);
            q.bindValue(QStringLiteral(":importAssessmentProcedures"), cci.isImport ? cci.importAssessmentProcedures : nullptr);
            q.bindValue(QStringLiteral(":importNarrative"), cci.isImport ? cci.importNarrative : nullptr);
            q.bindValue(QStringLiteral(":id"), tmpCCI.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateCCI"), q);
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateCKLCheck
 * @param check
 * @return @c True when the database is updated with the supplied
 * @a CKLCheck information. Otherwise, @c false.
 */
bool DbManager::UpdateCKLCheck(const CKLCheck &check)
{
    CKLCheck tmpCheck = GetCKLCheck(check);
    bool ret = false;
    if (tmpCheck.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            //NOTE: The new values use the provided "check" while the WHERE clause uses the Database-identified "tmpCheck".
            q.prepare(QStringLiteral("UPDATE CKLCheck SET status = :status, findingDetails = :findingDetails, comments = :comments, severityOverride = :severityOverride, severityJustification = :severityJustification WHERE id = :id"));
            q.bindValue(QStringLiteral(":status"), check.status);
            q.bindValue(QStringLiteral(":findingDetails"), check.findingDetails);
            q.bindValue(QStringLiteral(":comments"), check.comments);
            q.bindValue(QStringLiteral(":severityOverride"), check.severityOverride);
            q.bindValue(QStringLiteral(":severityJustification"), check.severityJustification);
            q.bindValue(QStringLiteral(":id"), tmpCheck.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateCKLCheck"), q);
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateControl
 * @param control
 * @return @c True when the database is updated with the supplied
 * @a Control information. Otherwise, @c false.
 */
bool DbManager::UpdateControl(const Control &control)
{
    Control tmpControl = GetControl(control.id);
    bool ret = false;
    if (tmpControl.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("UPDATE Control SET FamilyId = :FamilyId, number = :number, enhancement = :enhancement, title = :title, description = :description, importSeverity = :importSeverity, importRelevanceOfThreat = :importRelevanceOfThreat, importLikelihood = :importLikelihood, importImpact = :importImpact, importImpactDescription = :importImpactDescription, importResidualRiskLevel = :importResidualRiskLevel, importRecommendations = :importRecommendations WHERE id = :id"));
            q.bindValue(QStringLiteral(":FamilyId"), control.familyId);
            q.bindValue(QStringLiteral(":number"), control.number);
            q.bindValue(QStringLiteral(":enhancement"), control.enhancement);
            q.bindValue(QStringLiteral(":title"), control.title);
            q.bindValue(QStringLiteral(":description"), control.description);
            q.bindValue(QStringLiteral(":importSeverity"), control.importSeverity);
            q.bindValue(QStringLiteral(":importRelevanceOfThreat"), control.importRelevanceOfThreat);
            q.bindValue(QStringLiteral(":importLikelihood"), control.importLikelihood);
            q.bindValue(QStringLiteral(":importImpact"), control.importImpact);
            q.bindValue(QStringLiteral(":importImpactDescription"), control.importImpactDescription);
            q.bindValue(QStringLiteral(":importResidualRiskLevel"), control.importResidualRiskLevel);
            q.bindValue(QStringLiteral(":importRecommendations"), control.importRecommendations);
            q.bindValue(QStringLiteral(":id"), tmpControl.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateCKLCheck"), q);
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateSTIG
 * @param stig
 * @return @c True when the STIG is updated with the provided @a STIG.
 * Otherwise, @c false.
 */
bool DbManager::UpdateSTIG(const STIG &stig)
{
    STIG tmpSTIG = GetSTIG(stig);
    bool ret = false;

    if (tmpSTIG.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("UPDATE STIG SET title = :title, description = :description, release = :release, version = :version, benchmarkId = :benchmarkId, fileName = :fileName WHERE id = :id"));
            q.bindValue(QStringLiteral(":title"), stig.title);
            q.bindValue(QStringLiteral(":description"), stig.description);
            q.bindValue(QStringLiteral(":release"), stig.release);
            q.bindValue(QStringLiteral(":version"), stig.version);
            q.bindValue(QStringLiteral(":benchmarkId"), stig.benchmarkId);
            q.bindValue(QStringLiteral(":fileName"), stig.fileName);
            q.bindValue(QStringLiteral(":id"), stig.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateSTIG"), q);
        }
    }

    return ret;
}

/**
 * @brief DbManager::UpdateSTIGCheck
 * @param check
 * @return @c True when the database is updated with the supplied
 * @a STIGCheck information. Otherwise, @c false.
 */
bool DbManager::UpdateSTIGCheck(const STIGCheck &check)
{
    STIGCheck tmpCheck = GetSTIGCheck(check);
    bool ret = false;
    if (tmpCheck.id > 0)
    {
        QSqlDatabase db;
        ret = true;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            //NOTE: The new values use the provided "check" while the WHERE clause uses the Database-identified "tmpCheck".
            q.prepare(QStringLiteral("UPDATE STIGCheck SET `STIGId` = :STIGId, `rule` = :rule, `vulnNum` = :vulnNum, `groupTitle` = :groupTitle, `ruleVersion` = :ruleVersion, `severity` = :severity, `weight` = :weight, `title` = :title, `vulnDiscussion` = :vulnDiscussion, `falsePositives` = :falsePositives, `falseNegatives` = :falseNegatives, `fix` = :fix, `check` = :check, `documentable` = :documentable, `mitigations` = :mitigations, `severityOverrideGuidance` = :severityOverrideGuidance, `checkContentRef` = :checkContentRef, `potentialImpact` = :potentialImpact, `thirdPartyTools` = :thirdPartyTools, `mitigationControl` = :mitigationControl, `responsibility` = :responsibility, `IAControls` = :IAControls, `targetKey` = :targetKey, `isRemap` = :isRemap WHERE `id` = :id"));
            q.bindValue(QStringLiteral(":STIGId"), check.stigId);
            q.bindValue(QStringLiteral(":rule"), check.rule);
            q.bindValue(QStringLiteral(":vulnNum"), check.vulnNum);
            q.bindValue(QStringLiteral(":groupTitle"), check.groupTitle);
            q.bindValue(QStringLiteral(":ruleVersion"), check.ruleVersion);
            q.bindValue(QStringLiteral(":severity"), check.severity);
            q.bindValue(QStringLiteral(":weight"), check.weight);
            q.bindValue(QStringLiteral(":title"), check.title);
            q.bindValue(QStringLiteral(":vulnDiscussion"), check.vulnDiscussion);
            q.bindValue(QStringLiteral(":falsePositives"), check.falsePositives);
            q.bindValue(QStringLiteral(":falseNegatives"), check.falseNegatives);
            q.bindValue(QStringLiteral(":fix"), check.fix);
            q.bindValue(QStringLiteral(":check"), check.check);
            q.bindValue(QStringLiteral(":documentable"), check.documentable);
            q.bindValue(QStringLiteral(":mitigations"), check.mitigations);
            q.bindValue(QStringLiteral(":severityOverrideGuidance"), check.severityOverrideGuidance);
            q.bindValue(QStringLiteral(":checkContentRef"), check.checkContentRef);
            q.bindValue(QStringLiteral(":potentialImpact"), check.potentialImpact);
            q.bindValue(QStringLiteral(":thirdPartyTools"), check.thirdPartyTools);
            q.bindValue(QStringLiteral(":mitigationControl"), check.mitigationControl);
            q.bindValue(QStringLiteral(":responsibility"), check.responsibility);
            q.bindValue(QStringLiteral(":IAControls"), check.iaControls);
            q.bindValue(QStringLiteral(":targetKey"), check.targetKey);
            q.bindValue(QStringLiteral(":isRemap"), check.isRemap);
            q.bindValue(QStringLiteral(":id"), check.id);
            ret = q.exec();
            Log(6, QStringLiteral("UpdateSTIGCheck-STIGCheck"), q);
            q.prepare(QStringLiteral("DELETE FROM STIGCheckCCI WHERE STIGCheckId = :STIGCheckId"));
            q.bindValue(QStringLiteral(":STIGCheckId"), tmpCheck.id);
            ret = q.exec() && ret;
            Log(6, QStringLiteral("UpdateSTIGCheck-STIGCheckCCI1"), q);
            for (int cciId : check.cciIds)
            {
                q.prepare(QStringLiteral("INSERT INTO STIGCheckCCI (`STIGCheckId`, `CCIId`) VALUES(:STIGCheckId, :CCIId)"));
                q.bindValue(QStringLiteral(":STIGCheckId"), tmpCheck.id);
                q.bindValue(QStringLiteral(":CCIId"), cciId);
                ret = q.exec() && ret;
                Log(6, QStringLiteral("UpdateSTIGCheck-STIGCheckCCI2"), q);
            }
            q.prepare(QStringLiteral("DELETE FROM STIGCheckLegacyId WHERE STIGCheckId = :STIGCheckId"));
            q.bindValue(QStringLiteral(":STIGCheckId"), tmpCheck.id);
            ret = q.exec() && ret;
            Log(6, QStringLiteral("UpdateSTIGCheck-STIGCheckLegacyId1"), q);
            for (QString legacyId : check.legacyIds)
            {
                q.prepare(QStringLiteral("INSERT INTO STIGCheckLegacyId (`STIGCheckId`, `LegacyId`) VALUES(:STIGCheckId, :LegacyId)"));
                q.bindValue(QStringLiteral(":STIGCheckId"), tmpCheck.id);
                q.bindValue(QStringLiteral(":LegacyId"), legacyId);
                ret = q.exec() && ret;
                Log(6, QStringLiteral("UpdateSTIGCheck-STIGCheckLegacyId2"), q);
            }
        }
    }
    return ret;
}

/**
 * @brief DbManager::UpdateVariable
 * @param name
 * @param value
 * @return @c True when the variable is updated in the database.
 * Otherwise, @c false.
 */
bool DbManager::UpdateVariable(const QString &name, const QString &value)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("UPDATE variables SET value = :value WHERE name = :name"));
        q.bindValue(QStringLiteral(":value"), value);
        q.bindValue(QStringLiteral(":name"), name);
        ret = q.exec();
        Log(6, QStringLiteral("UpdateVariable"), q);
    }
    return ret;
}
