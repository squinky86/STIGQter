/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018 Jon Hood, http://www.hoodsecurity.com/
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

#include <cstdlib>
#include <QCoreApplication>
#include <QFile>
#include <QMessageBox>
#include <QSqlQuery>
#include <QSqlError>
#include <QtDebug>
#include <QThread>
#include <QSqlField>
#include <QSqlDriver>

DbManager::DbManager() : DbManager(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()))) { }

DbManager::DbManager(const QString& connectionName) : DbManager(QCoreApplication::applicationDirPath() + "/STIGQter.db", connectionName) { }

DbManager::DbManager(const QString& path, const QString& connectionName)
{
    bool initialize = false;
    _delayCommit = false;

    //check if database file exists or create it
    if (!QFile::exists(path))
        initialize = true;

    //open SQLite Database
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    if (!db.isValid())
    {
        db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
        db.setDatabaseName(path);
    }

    if (!db.open())
        qDebug() << "Error: Unable to open SQLite database.";

    if (initialize)
        UpdateDatabaseFromVersion(0);

    int version = GetVariable("version").toInt();
    UpdateDatabaseFromVersion(version);
}

DbManager::~DbManager()
{
    if (_delayCommit)
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            db.commit();
        }
    }
}

void DbManager::DelayCommit(bool delay)
{
    if (delay)
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery("PRAGMA journal_mode = OFF", db);
            QSqlQuery("PRAGMA synchronous = OFF", db);
        }
    }
    else
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery("PRAGMA journal_mode = ON", db);
            QSqlQuery("PRAGMA synchronous = ON", db);
            db.commit();
        }
    }
    _delayCommit = delay;
}

bool DbManager::AddAsset(Asset &a)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        if (a.id <= 0)
        {
            q.prepare("SELECT count(*) FROM Asset WHERE hostName = :hostName");
            q.bindValue(":hostName", a.hostName);
            q.exec();
            if (q.next())
            {
                if (q.value(0).toInt() > 0)
                {
                    QMessageBox::warning(nullptr, "Asset Already Exists", "The Asset " + PrintAsset(a) + " already exists in the database.");
                    return false;
                }
            }
            q.prepare("INSERT INTO Asset (`assetType`, `hostName`, `hostIP`, `hostMAC`, `hostFQDN`, `techArea`, `targetKey`, `webOrDatabase`, `webDBSite`, `webDBInstance`) VALUES(:assetType, :hostName, :hostIP, :hostMAC, :hostFQDN, :techArea, :targetKey, :webOrDatabase, :webDBSite, :webDBInstance)");
            q.bindValue(":assetType", a.assetType);
            q.bindValue(":hostName", a.hostName);
            q.bindValue(":hostIP", a.hostIP);
            q.bindValue(":hostMAC", a.hostMAC);
            q.bindValue(":hostFQDN", a.hostFQDN);
            q.bindValue(":techArea", a.techArea);
            q.bindValue(":targetKey", a.targetKey);
            q.bindValue(":webOrDatabase", a.webOrDB);
            q.bindValue(":webDBSite", a.webDbSite);
            q.bindValue(":webDBInstance", a.webDbInstance);
            q.exec();
            db.commit();
            a.id = q.lastInsertId().toInt();
            return true;
        }
    }
    return false;
}

bool DbManager::AddCCI(CCI &c)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("INSERT INTO CCI (ControlId, cci, definition) VALUES(:ControlId, :CCI, :definition)");
        q.bindValue(":ControlId", c.controlId);
        q.bindValue(":CCI", c.cci);
        q.bindValue(":definition", c.definition);
        q.exec();
        if (!_delayCommit)
        {
            db.commit();
            c.id = q.lastInsertId().toInt();
        }
        return true;
    }
    return false;
}

void DbManager::AddControl(const QString &control, const QString &title, const QString &description)
{
    QString tmpControl(control);
    if (tmpControl.length() < 4)
    {
        qDebug() << "Received bad control.";
        return;
    }
    QString family(tmpControl.left(2));
    tmpControl = tmpControl.right(tmpControl.length()-3);
    QString enhancement("");
    if (tmpControl.contains('('))
    {
        int tmpIndex = tmpControl.indexOf('(');
        enhancement = tmpControl.right(tmpControl.length() - tmpIndex - 1);
        enhancement = enhancement.left(enhancement.length() - 1);
        tmpControl = tmpControl.left(tmpControl.indexOf('('));
        if (enhancement.toInt() == 0)
            enhancement = "";
    }

    Family f = GetFamily(family);

    if (f.id >= 0)
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare("INSERT INTO Control (FamilyId, number, enhancement, title, description) VALUES(:FamilyId, :number, :enhancement, :title, :description)");
            q.bindValue(":FamilyId", f.id);
            q.bindValue(":number", tmpControl.toInt());
            q.bindValue(":enhancement", enhancement.isEmpty() ? QVariant(QVariant::Int) : enhancement.toInt());
            q.bindValue(":title", title);
            q.bindValue(":description", description);
            q.exec();
            if (!_delayCommit)
                db.commit();
        }
    }
}

void DbManager::AddFamily(const QString &acronym, const QString &description)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("INSERT INTO Family (Acronym, Description) VALUES(:acronym, :description)");
        q.bindValue(":acronym", acronym);
        q.bindValue(":description", Sanitize(description));
        q.exec();
        if (!_delayCommit)
            db.commit();
    }
}

void DbManager::AddSTIG(STIG stig, QList<STIGCheck> checks)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        if (stig.id <= 0)
        {
            q.prepare("SELECT count(*) FROM STIG WHERE title = :title AND release = :release AND version = :version");
            q.bindValue(":title", stig.title);
            q.bindValue(":release", stig.release);
            q.bindValue(":version", stig.version);
            q.exec();
            while (q.next())
            {
                if (q.value(0).toInt() > 0)
                {
                    QMessageBox::warning(nullptr, "STIG Already Exists", "The STIG " + PrintSTIG(stig) + " already exists in the database.");
                    return;
                }
            }
            q.prepare("INSERT INTO STIG (title, description, release, version) VALUES(:title, :description, :release, :version)");
            q.bindValue(":title", stig.title);
            q.bindValue(":description", stig.description);
            q.bindValue(":release", stig.release);
            q.bindValue(":version", stig.version);
            q.exec();
            stig.id = q.lastInsertId().toInt();
            db.commit();
        }
        bool newChecks = false;
        bool delayed = _delayCommit;
        if (!delayed)
            this->DelayCommit(true);
        foreach(STIGCheck c, checks)
        {
            newChecks = true;
            q.prepare("INSERT INTO STIGCheck (`STIGId`, `CCIId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls`) VALUES(:STIGId, :CCIId, :rule, :vulnNum, :groupTitle, :ruleVersion, :severity, :weight, :title, :vulnDiscussion, :falsePositives, :falseNegatives, :fix, :check, :documentable, :mitigations, :severityOverrideGuidance, :checkContentRef, :potentialImpact, :thirdPartyTools, :mitigationControl, :responsibility, :IAControls)");
            q.bindValue(":STIGId", stig.id);
            q.bindValue(":CCIId", c.cciId);
            q.bindValue(":rule", c.rule);
            q.bindValue(":vulnNum", c.vulnNum);
            q.bindValue(":groupTitle", c.groupTitle);
            q.bindValue(":ruleVersion", c.ruleVersion);
            q.bindValue(":severity", c.severity);
            q.bindValue(":weight", c.weight);
            q.bindValue(":title", c.title);
            q.bindValue(":vulnDiscussion", c.vulnDiscussion);
            q.bindValue(":falsePositives", c.falsePositives);
            q.bindValue(":falseNegatives", c.falseNegatives);
            q.bindValue(":fix", c.fix);
            q.bindValue(":check", c.check);
            q.bindValue(":documentable", c.documentable ? 1 : 0);
            q.bindValue(":mitigations", c.mitigations);
            q.bindValue(":severityOverrideGuidance", c.severityOverrideGuidance);
            q.bindValue(":checkContentRef", c.checkContentRef);
            q.bindValue(":potentialImpact", c.potentialImpact);
            q.bindValue(":thirdPartyTools", c.thirdPartyTools);
            q.bindValue(":mitigationControl", c.mitigationControl);
            q.bindValue(":responsibility", c.responsibility);
            q.bindValue(":IAControls", c.iaControls);
            q.exec();
        }
        if (!delayed)
        {
            this->DelayCommit(false);
        }
        if (newChecks)
            db.commit();
    }
}

void DbManager::AddSTIGToAsset(const STIG &s, const Asset &a)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        if (a.id > 0 && s.id > 0)
        {
            bool assetExists = false;
            bool stigExists = false;
            q.prepare("SELECT count(*) FROM Asset WHERE id = :id");
            q.bindValue(":id", a.id);
            q.exec();
            while (q.next())
            {
                if (q.value(0).toInt() > 0)
                {
                    assetExists = true;
                }
            }
            q.prepare("SELECT count(*) FROM STIG WHERE id = :id");
            q.bindValue(":id", s.id);
            q.exec();
            while (q.next())
            {
                if (q.value(0).toInt() > 0)
                {
                    stigExists = true;
                }
            }
            if (assetExists && stigExists)
            {
                q.prepare("INSERT INTO AssetSTIG (`AssetId`, `STIGId`) VALUES(:AssetId, :STIGId)");
                q.bindValue(":AssetId", a.id);
                q.bindValue(":STIGId", s.id);
                q.exec();
                q.prepare("INSERT INTO CKLCheck (AssetId, STIGCheckId, status, findingDetails, comments, severityOverride, severityJustification) SELECT :AssetId, id, :status, '', '', '', '' FROM STIGCheck WHERE STIGId = :STIGId");
                q.bindValue(":AssetId", a.id);
                q.bindValue(":status", Status::NotReviewed);
                q.bindValue(":STIGId", s.id);
                q.exec();
                db.commit();
            }
        }
    }
}

void DbManager::DeleteCCIs()
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("DELETE FROM Family");
        q.exec();
        q.prepare("DELETE FROM Control");
        q.exec();
        q.prepare("DELETE FROM CCI");
        q.exec();
        if (!_delayCommit)
            db.commit();
    }
}

bool DbManager::DeleteSTIG(int id)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT hostName FROM AssetSTIG JOIN Asset ON AssetSTIG.AssetID = Asset.id WHERE STIGId = :STIGId");
        q.bindValue(":STIGId", id);
        q.exec();
        if (q.next())
        {
            QMessageBox::warning(nullptr, "STIG In Use", "The Asset '" + q.value(0).toString() + "' is currently using the selected STIG.");
            return false;
        }

        q.prepare("DELETE FROM STIGCheck WHERE STIGId = :STIGId");
        q.bindValue(":STIGId", id);
        q.exec();
        q.prepare("DELETE FROM STIG WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (!_delayCommit)
            db.commit();
        return true;
    }
    return false;
}

bool DbManager::DeleteSTIG(STIG s)
{
    return DeleteSTIG(s.id);
}

Asset DbManager::GetAsset(const QString &hostName)
{
    return GetAssets("WHERE hostName = :hostName", {std::make_tuple<QString, QVariant>(":hostName", hostName)}).first();
}

Asset DbManager::GetAsset(const int &id)
{
    return GetAssets("WHERE id = :id", {std::make_tuple<QString, QVariant>(":id", id)}).first();
}

QList<Asset> DbManager::GetAssets(const QString &whereClause, const QList<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QList<Asset> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = "SELECT `id`, `assetType`, `hostName`, `hostIP`, `hostMAC`, `hostFQDN`, `techArea`, `targetKey`, `webOrDatabase`, `webDBSite`, `webDBInstance` FROM Asset";
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(" ORDER BY LOWER(hostName), hostName");
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
            a.webOrDB = q.value(8).toBool();
            a.webDbSite = q.value(9).toString();
            a.webDbInstance = q.value(10).toString();
            ret.append(a);
        }
    }
    return ret;
}

CCI DbManager::GetCCI(const int &id)
{
    return GetCCIs("WHERE id = :id", {std::make_tuple<QString, QVariant>(":id", id)}).first();
}

CCI DbManager::GetCCIByCCI(const int &cci)
{
    return GetCCIs("WHERE cci = :cci", {std::make_tuple<QString, QVariant>(":cci", cci)}).first();
}

CCI DbManager::GetCCIByCCI(const CCI &cci)
{
    if (cci.id < 0)
    {
        return GetCCIByCCI(cci.cci);
    }
    return GetCCI(cci.id);
}

QList<CCI> DbManager::GetCCIs(const QString &whereClause, const QList<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QList<CCI> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = "SELECT id, ControlId, cci, definition FROM CCI";
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(" ORDER BY cci");
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

            ret.append(c);
        }
    }
    return ret;
}

STIGCheck DbManager::GetSTIGCheck(int id)
{
    QSqlDatabase db;
    STIGCheck c;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT `id`, `STIGId`, `CCIId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls` FROM STIGCheck WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (q.next())
        {
            c.id = q.value(0).toInt();
            c.stigId = q.value(1).toInt();
            c.cciId = q.value(2).toInt();
            c.rule = q.value(3).toString();
            c.vulnNum = q.value(4).toString();
            c.groupTitle = q.value(5).toString();
            c.ruleVersion = q.value(6).toString();
            c.severity = static_cast<Severity>(q.value(7).toInt());
            c.weight = q.value(8).toDouble();
            c.title = q.value(9).toString();
            c.vulnDiscussion = q.value(10).toString();
            c.falsePositives = q.value(11).toString();
            c.falseNegatives = q.value(12).toString();
            c.fix = q.value(13).toString();
            c.check = q.value(14).toString();
            c.documentable = q.value(15).toBool();
            c.mitigations = q.value(16).toString();
            c.severityOverrideGuidance = q.value(17).toString();
            c.checkContentRef = q.value(18).toString();
            c.potentialImpact = q.value(19).toString();
            c.thirdPartyTools = q.value(20).toString();
            c.mitigationControl = q.value(21).toString();
            c.thirdPartyTools = q.value(22).toString();
            c.iaControls = q.value(23).toString();
        }
    }
    return c;
}

QList<STIGCheck> DbManager::GetSTIGChecks(STIG s)
{
    QSqlDatabase db;
    QList<STIGCheck> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT `id`, `STIGId`, `CCIId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`, `IAControls` FROM STIGCheck WHERE STIGId = :STIGId");
        q.bindValue(":STIGId", s.id);
        q.exec();
        while (q.next())
        {
            STIGCheck c;
            c.id = q.value(0).toInt();
            c.stigId = q.value(1).toInt();
            c.cciId = q.value(2).toInt();
            c.rule = q.value(3).toString();
            c.vulnNum = q.value(4).toString();
            c.groupTitle = q.value(5).toString();
            c.ruleVersion = q.value(6).toString();
            c.severity = static_cast<Severity>(q.value(7).toInt());
            c.weight = q.value(8).toDouble();
            c.title = q.value(9).toString();
            c.vulnDiscussion = q.value(10).toString();
            c.falsePositives = q.value(11).toString();
            c.falseNegatives = q.value(12).toString();
            c.fix = q.value(13).toString();
            c.check = q.value(14).toString();
            c.documentable = q.value(15).toBool();
            c.mitigations = q.value(16).toString();
            c.severityOverrideGuidance = q.value(17).toString();
            c.checkContentRef = q.value(18).toString();
            c.potentialImpact = q.value(19).toString();
            c.thirdPartyTools = q.value(20).toString();
            c.mitigationControl = q.value(21).toString();
            c.thirdPartyTools = q.value(22).toString();
            c.iaControls = q.value(23).toString();
            ret.append(c);
        }
    }
    return ret;
}

QList<STIG> DbManager::GetSTIGs(Asset a)
{
    QList<std::tuple<QString, QVariant>> variables;
    variables.append(std::make_tuple<QString, QVariant>(":AssetId", a.id));
    return GetSTIGs("WHERE `id` IN (SELECT STIGId FROM AssetSTIG WHERE AssetId = :AssetId)", variables);
}

QList<STIG> DbManager::GetSTIGs(const QString &whereClause, const QList<std::tuple<QString, QVariant>> &variables)
{
    QSqlDatabase db;
    QList<STIG> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        QString toPrep = "SELECT id, title, description, release, version FROM STIG";
        if (!whereClause.isNull() && !whereClause.isEmpty())
            toPrep.append(" " + whereClause);
        toPrep.append(" ORDER BY LOWER(title), title");
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
            ret.append(s);
        }
    }
    return ret;
}

Control DbManager::GetControl(int id)
{
    Control ret;
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, FamilyId, number, enhancement, title, description FROM Control WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (q.next())
        {
            ret.id = q.value(0).toInt();;
            ret.familyId = q.value(1).toInt();
            ret.number = q.value(2).toInt();
            ret.enhancement = q.value(3).isNull() ? -1 : q.value(3).toInt();
            ret.title = q.value(4).toString();
            ret.description = q.value(5).toString();
        }
    }
    return ret;
}

Control DbManager::GetControl(QString control)
{
    //see if there are spaces
    int tmpIndex = control.indexOf(' ');
    if (tmpIndex > 0)
    {
        //see if there's a second space
        tmpIndex = control.indexOf(' ', tmpIndex+1);
        if (tmpIndex > 0)
        {
            control = control.left(tmpIndex+1).trimmed();
        }
    }
    Control ret;
    ret.id = -1;
    ret.enhancement = -1;
    ret.title = "";
    ret.familyId = -1;
    QString family(control.left(2));
    control = control.right(control.length()-3);
    QString enhancement("");
    if (control.contains('('))
    {
        int tmpIndex = control.indexOf('(');
        enhancement = control.right(control.length() - tmpIndex - 1);
        enhancement = enhancement.left(enhancement.length() - 1);
        control = control.left(control.indexOf('('));
        ret.enhancement = enhancement.toInt(); //will return 0 if enhancement doesn't exist
    }
    ret.number = control.toInt();
    ret.familyId = GetFamily(family).id;
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        if (ret.enhancement > 0)
            q.prepare("SELECT id, title, description FROM Control WHERE number = :number AND FamilyId = :FamilyId AND enhancement = :enhancement");
        else
            q.prepare("SELECT id, title, description FROM Control WHERE number = :number AND FamilyId = :FamilyId");
        q.bindValue(":number", ret.number);
        q.bindValue(":FamilyId", ret.familyId);
        if (ret.enhancement > 0)
            q.bindValue(":enhancement", ret.enhancement);
        q.exec();
        if (q.next())
        {
            ret.id = q.value(0).toInt();
            ret.title = q.value(1).toString();
            ret.description = q.value(2).toString();
        }
    }
    return ret;
}

Family DbManager::GetFamily(int id)
{
    QSqlDatabase db;
    Family ret;
    ret.id = -1;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, acronym, description FROM Family WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (q.next())
        {
            ret.id = q.value(0).toInt();
            ret.acronym = q.value(1).toString();
            ret.description = q.value(2).toString();
        }
    }
    return ret;
}

Family DbManager::GetFamily(const QString &acronym)
{
    QSqlDatabase db;
    Family ret;
    ret.id = -1;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, acronym, description FROM Family WHERE acronym = :acronym");
        q.bindValue(":acronym", acronym);
        q.exec();
        if (q.next())
        {
            ret.id = q.value(0).toInt();
            ret.acronym = q.value(1).toString();
            ret.description = q.value(2).toString();
        }
    }
    return ret;
}

QList<Family> DbManager::GetFamilies()
{
    QSqlDatabase db;
    QList<Family> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, acronym, description FROM Family");
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

STIG DbManager::GetSTIG(int id)
{
    QSqlDatabase db;
    STIG ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, title, description, release, version FROM STIG WHERE id = :id");
        q.bindValue(":id", id);
        if (q.next())
        {
            ret.id = q.value(0).toInt();
            ret.title = q.value(1).toString();
            ret.description = q.value(2).toString();
            ret.release = q.value(3).toString();
            ret.version = q.value(4).toInt();
        }
    }
    return ret;
}

QString DbManager::GetVariable(const QString &name)
{
    QSqlDatabase db;
    QString ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT value FROM variables WHERE name = :name");
        q.bindValue(":name", name);
        q.exec();
        if (q.next())
        {
            ret = q.value(0).toString();
        }
    }
    return ret;
}

void DbManager::UpdateVariable(const QString &name, const QString &value)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("UPDATE variables SET value = :value WHERE name = :name");
        q.bindValue(":value", value);
        q.bindValue(":name", name);
        q.exec();
    }
}

QString DbManager::Sanitize(QString s)
{
    s = s.replace("\r\n", "\n");
    s = s.replace("\n", " ");
    return s;
}

bool DbManager::CheckDatabase(QSqlDatabase &db)
{
    db = QSqlDatabase::database(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId())));
    if (!db.isOpen())
        db.open();
    if (!db.isOpen())
        return false;
    return db.isValid();
}

bool DbManager::UpdateDatabaseFromVersion(int version)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        //upgrade to version 1 of the database
        if (version <= 0)
        {
            //New database; initial setups
            QSqlQuery q(db);
            q.prepare("CREATE TABLE `Family` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`Acronym`	TEXT UNIQUE, "
                        "`Description`	TEXT UNIQUE"
                        ")");
            q.exec();
            q.prepare("CREATE TABLE `Control` ( "
                        "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "`FamilyId`	INTEGER NOT NULL, "
                        "`number`	INTEGER NOT NULL, "
                        "`enhancement`	INTEGER, "
                        "`title`	TEXT, "
                        "`description`  TEXT, "
                        "FOREIGN KEY(`FamilyID`) REFERENCES `Family`(`id`) "
                        ")");
            q.exec();
            q.prepare("CREATE TABLE `CCI` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`ControlId`	INTEGER, "
                      "`cci`    INTEGER, "
                      "`definition`	TEXT, "
                      "FOREIGN KEY(`ControlId`) REFERENCES `Control`(`id`) "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `variables` ( "
                      "`name`	TEXT, "
                      "`value`	TEXT "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `STIG` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`title`	TEXT, "
                      "`description`	TEXT, "
                      "`release`	TEXT, "
                      "`version`	INTEGER "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `STIGCheck` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`STIGId`	INTEGER, "
                      "`CCIId`	INTEGER, "
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
                      "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`), "
                      "FOREIGN KEY(`CCIId`) REFERENCES `CCI`(`id`) "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `Asset` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`assetType`	TEXT, "
                      "`hostName`	TEXT UNIQUE, "
                      "`hostIP`	TEXT, "
                      "`hostMAC`	TEXT, "
                      "`hostFQDN`	TEXT, "
                      "`techArea`	TEXT, "
                      "`targetKey`	TEXT, "
                      "`webOrDatabase`	INTEGER, "
                      "`webDBSite`	TEXT, "
                      "`webDBInstance`	TEXT "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `AssetSTIG` ( "
                      "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "`AssetId`	INTEGER, "
                      "`STIGId`	INTEGER, "
                      "FOREIGN KEY(`AssetId`) REFERENCES `Asset`(`id`), "
                      "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`) "
                      ")");
            q.exec();
            q.prepare("CREATE TABLE `CKLCheck` ( "
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
                      ")");
            q.exec();
            q.prepare("INSERT INTO variables (name, value) VALUES(:name, :value)");
            q.bindValue(":name", "version");
            q.bindValue(":value", "1");
            q.exec();

            //write changes from update
            db.commit();
        }
    }

    return EXIT_SUCCESS;
}
