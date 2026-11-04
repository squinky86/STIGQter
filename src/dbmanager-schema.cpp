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
 * @brief DbManager::UpdateDatabaseFromVersion
 * @param version
 * @return @c True when the database is up-to-date or updated.
 * Otherwise, @c false.
 */
bool DbManager::UpdateDatabaseFromVersion(int version)
{
    QSqlDatabase db;
    bool ret = false;
    if (CheckDatabase(db))
    {
        ret = true; //assume success from here

        //upgrade to version 1 of the database
        if (version <= 0)
        {
            //New database; initial creation and setup

            QSqlQuery q(db);
            q.prepare(QStringLiteral("CREATE TABLE `Family` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`Acronym`	TEXT UNIQUE, "
                        "`Description`	TEXT UNIQUE"
                        ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `Control` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`FamilyId`	INTEGER NOT NULL, "
                        "`number`	INTEGER NOT NULL, "
                        "`enhancement`	INTEGER, "
                        "`title`	TEXT, "
                        "`description`  TEXT, "
                        "FOREIGN KEY(`FamilyID`) REFERENCES `Family`(`id`) "
                        ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `CCI` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`ControlId`	INTEGER, "
                      "`cci`    INTEGER, "
                      "`definition`	TEXT, "
                      "`isImport` INTEGER NOT NULL DEFAULT 0, "
                      "`importCompliance`	TEXT, "
                      "`importDateTested`	TEXT, "
                      "`importTestedBy`	TEXT, "
                      "`importTestResults`	TEXT, "
                      "`importCompliance2`	TEXT, "
                      "`importDateTested2`	TEXT, "
                      "`importTestedBy2`	TEXT, "
                      "`importTestResults2`	TEXT, "
                      "`importControlImplementationStatus`	TEXT, "
                      "`importSecurityControlDesignation`	TEXT, "
                      "`importInherited`	TEXT, "
                      "`importApNum`	TEXT, "
                      "`importImplementationGuidance`	TEXT, "
                      "`importAssessmentProcedures`	TEXT, "
                      "FOREIGN KEY(`ControlId`) REFERENCES `Control`(`id`) "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `variables` ( "
                      "`name`	TEXT, "
                      "`value`	TEXT "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `STIG` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`title`	TEXT, "
                      "`description`	TEXT, "
                      "`release`	TEXT, "
                      "`version`	INTEGER, "
                      "`benchmarkId`	TEXT, "
                      "`fileName`	TEXT "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `STIGCheck` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`STIGId`	INTEGER, "
                      "`rule`	TEXT, "
                      "`vulnNum`    TEXT, "
                      "`groupTitle`    TEXT, "
                      "`ruleVersion`    TEXT, "
                      "`severity`	INTEGER, "
                      "`weight` REAL, "
                      "`title`	TEXT, "
                      "`vulnDiscussion`	TEXT, "
                      "`falsePositives`	TEXT, "
                      "`falseNegatives`	TEXT, "
                      "`fix`	TEXT, "
                      "`check`	TEXT, "
                      "`documentable`	INTEGER, "
                      "`mitigations`	TEXT, "
                      "`severityOverrideGuidance`	TEXT, "
                      "`checkContentRef`	TEXT, "
                      "`potentialImpact`	TEXT, "
                      "`thirdPartyTools`	TEXT, "
                      "`mitigationControl`	TEXT, "
                      "`responsibility`	TEXT, "
                      "`IAControls` TEXT, "
                      "`targetKey` TEXT, "
                      "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`) "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `STIGCheckCCI` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`STIGCheckId`	INTEGER, "
                      "`CCIId`	INTEGER, "
                      "FOREIGN KEY(`STIGCheckId`) REFERENCES `STIGCheck`(`id`), "
                      "FOREIGN KEY(`CCIId`) REFERENCES `CCI`(`id`) "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `Asset` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`assetType`	TEXT, "
                      "`hostName`	TEXT UNIQUE COLLATE NOCASE, "
                      "`hostIP`	TEXT, "
                      "`hostMAC`	TEXT, "
                      "`hostFQDN`	TEXT, "
                      "`techArea`	TEXT, "
                      "`targetKey`	TEXT, "
                      "`webOrDatabase`	INTEGER, "
                      "`webDBSite`	TEXT, "
                      "`webDBInstance`	TEXT "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `AssetSTIG` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`AssetId`	INTEGER, "
                      "`STIGId`	INTEGER, "
                      "FOREIGN KEY(`AssetId`) REFERENCES `Asset`(`id`), "
                      "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`) "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `CKLCheck` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`AssetId`	INTEGER, "
                      "`STIGCheckId`	INTEGER, "
                      "`status`	INTEGER, "
                      "`findingDetails`	TEXT, "
                      "`comments`	TEXT, "
                      "`severityOverride`	INTEGER, "
                      "`severityJustification`	TEXT, "
                      "FOREIGN KEY(`STIGCheckId`) REFERENCES `STIGCheck`(`id`), "
                      "FOREIGN KEY(`AssetId`) REFERENCES `Asset`(`id`) "
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `Log` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`when`	DATETIME, "
                      "`severity`	INTEGER, "
                      "`location`	TEXT, "
                      "`message`	TEXT, "
                      "`user`	TEXT"
                      ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("INSERT INTO variables (name, value) VALUES(:name, :value)"));
            q.bindValue(QStringLiteral(":name"), "version");
            q.bindValue(QStringLiteral(":value"), "1");
            ret = q.exec() && ret;
            q.bindValue(QStringLiteral(":name"), "lastdir");
            q.bindValue(QStringLiteral(":value"), QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation));
            ret = q.exec() && ret;
            q.bindValue(QStringLiteral(":name"), "loglevel");
            q.bindValue(QStringLiteral(":value"), "1");
            ret = q.exec() && ret;

            //write changes from update
            db.commit();
        }

        //upgrade to version 2 of the database
        if (version < 2)
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("CREATE TABLE `Supplement` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`STIGId`	INTEGER, "
                        "`path`	TEXT, "
                        "`contents`	BLOB, "
                        "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`)"
                        ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("CREATE TABLE `STIGCheckLegacyId` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`STIGCheckId`	INTEGER, "
                        "`LegacyId`	TEXT, "
                        "FOREIGN KEY(`STIGCheckId`) REFERENCES `STIGCheck`(`id`)"
                        ")"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("INSERT INTO variables (name, value) VALUES(:name, :value)"));
            q.bindValue(QStringLiteral(":name"), QStringLiteral("indexSupplements"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("n"));
            ret = q.exec() && ret;
            q.bindValue(QStringLiteral(":name"), QStringLiteral("quarterly"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_2020_04v1.zip"));
            ret = q.exec() && ret;
            q.bindValue(QStringLiteral(":name"), QStringLiteral("remapCM6"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("n"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("ALTER TABLE STIGCheck ADD COLUMN isRemap INTEGER NOT NULL DEFAULT 0"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("2")) && ret;
        }
        if (version < 3)
        {
		/*
		 * No longer needed.
		 * This routine previously set the new quarterly download package.
		 * This has been deprecated by version 4 of the DB.
		 */
                ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("3")) && ret;
        }
        if (version < 4)
        {
                QSqlQuery q(db);
                q.prepare(QStringLiteral("ALTER TABLE CCI ADD COLUMN importNarrative TEXT"));
                ret = q.exec() && ret;
                ret = UpdateVariable(QStringLiteral("quarterly"), QStringLiteral("https://www.stigqter.com/stig.php")) && ret;
                ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("4")) && ret;
        }
        if (version < 5)
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("INSERT INTO variables (name, value) VALUES(:name, :value)"));
            q.bindValue(QStringLiteral(":name"), QStringLiteral("checkVersion"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("true"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("5")) && ret;
        }
        if (version < 6)
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("INSERT INTO variables (name, value) VALUES(:name, :value)"));
            q.bindValue(QStringLiteral(":name"), QStringLiteral("autostig"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("true"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("6")) && ret;
        }
        if (version < 7)
        {
                QSqlQuery q(db);
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importSeverity TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importRelevanceOfThreat TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importLikelihood TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importImpact TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importImpactDescription TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importResidualRiskLevel TEXT"));
                ret = q.exec() && ret;
                q.prepare(QStringLiteral("ALTER TABLE Control ADD COLUMN importRecommendations TEXT"));
                ret = q.exec() && ret;
                ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("7")) && ret;
        }
        if (version < 8)
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("ALTER TABLE Asset ADD COLUMN marking TEXT"));
            ret = q.exec() && ret;
            q.prepare(QStringLiteral("ALTER TABLE Asset ADD COLUMN targetComment TEXT"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("8")) && ret;
        }
        if (version < 9)
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("ALTER TABLE CCI ADD COLUMN importRemoteInheritanceInstance TEXT"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("9")) && ret;
        }
        if (version < 10)
        {
            //system-wide classification marking used to mark generated reports
            QSqlQuery q(db);
            q.prepare(QStringLiteral("INSERT INTO variables (name, value) VALUES(:name, :value)"));
            q.bindValue(QStringLiteral(":name"), QStringLiteral("systemMarking"));
            q.bindValue(QStringLiteral(":value"), QStringLiteral("UNCLASSIFIED"));
            ret = q.exec() && ret;
            ret = UpdateVariable(QStringLiteral("version"), QStringLiteral("10")) && ret;
        }
    }
    return ret;
}

/**
 * @brief GetLastExecutedQuery
 * @param query
 * @return String of the last executed query.
 *
 * Modified from:
 *   https://stackoverflow.com/questions/5777409/how-to-get-last-prepared-and-executed-query-using-qsqlquery
 */
QString GetLastExecutedQuery(const QSqlQuery& query)
{
    QString sql = query.executedQuery();

    //Bound name placeholder lookups are not compatible with Qt 6.
#if QT_VERSION >= 0x060000

    QVector<QVariant> values = query.boundValues();

    QRegularExpression reg(QStringLiteral(":[a-zA-Z0-9_]*"));

    for (auto value = values.begin(); value != values.end(); ++value)
    {
        QRegularExpressionMatch match = reg.match(sql);
        QSqlField field(QLatin1String(""), value->metaType());
        if (value->isNull())
        {
            field.clear();
        }
        else
        {
            field.setValue(*value);
        }
        QString formatV = query.driver()->formatValue(field);
        if (match.hasMatch())
            sql.replace(match.capturedStart(), match.capturedLength(), formatV);
    }
#else
    QMapIterator<QString, QVariant> it(query.boundValues());

    while (it.hasNext())
    {
        it.next();
        const QVariant &var = it.value();
        QSqlField field(QLatin1String(""), var.userType());
        if (var.isNull())
        {
            field.clear();
        }
        else
        {
            field.setValue(var);
        }
        QString formatV = query.driver()->formatValue(field);
        sql.replace(it.key(), formatV);
    }
#endif

    return sql;
}
