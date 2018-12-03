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

#include <cstdlib>
#include <QCoreApplication>
#include <QFile>
#include <QMessageBox>
#include <QSqlQuery>
#include <QSqlError>
#include <QtDebug>
#include <QThread>

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

void DbManager::AddCCI(int cci, QString control, QString definition)
{
    Control c = GetControl(control);
    if (c.id >= 0)
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare("INSERT INTO CCI (ControlId, cci, definition) VALUES(:ControlId, :CCI, :definition)");
            q.bindValue(":ControlId", c.id);
            q.bindValue(":CCI", cci);
            q.bindValue(":definition", definition);
            q.exec();
            if (!_delayCommit)
                db.commit();
        }
    }
}

void DbManager::AddControl(QString control, QString title)
{
    if (control.length() < 4)
    {
        qDebug() << "Received bad control.";
        return;
    }
    QString family(control.left(2));
    control = control.right(control.length()-3);
    QString enhancement("");
    if (control.contains('('))
    {
        int tmpIndex = control.indexOf('(');
        enhancement = control.right(control.length() - tmpIndex - 1);
        enhancement = enhancement.left(enhancement.length() - 1);
        control = control.left(control.indexOf('('));
    }

    Family f = GetFamily(family);

    if (f.id >= 0)
    {
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare("INSERT INTO Control (FamilyId, number, enhancement, title) VALUES(:FamilyId, :number, :enhancement, :title)");
            q.bindValue(":FamilyId", f.id);
            q.bindValue(":number", control.toInt());
            q.bindValue(":enhancement", enhancement.isEmpty() ? QVariant(QVariant::Int) : enhancement.toInt());
            q.bindValue(":title", title);
            q.exec();
            if (!_delayCommit)
                db.commit();
        }
    }
}

void DbManager::AddFamily(QString acronym, QString description)
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

void DbManager::AddSTIG(STIG stig, QList<STIGCheck *> checks)
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
            db.commit();
            stig.id = q.lastInsertId().toInt();
        }
        bool newChecks = false;
        bool delayed = _delayCommit;
        if (!delayed)
            this->DelayCommit(true);
        foreach(STIGCheck* c, checks)
        {
            newChecks = true;
            q.prepare("INSERT INTO STIGCheck (`STIGId`, `CCIId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility`) VALUES(:STIGId, :CCIId, :rule, :vulnNum, :groupTitle, :ruleVersion, :severity, :weight, :title, :vulnDiscussion, :falsePositives, :falseNegatives, :fix, :check, :documentable, :mitigations, :severityOverrideGuidance, :checkContentRef, :potentialImpact, :thirdPartyTools, :mitigationControl, :responsibility)");
            if (c->cci.id <= 0)
                c->cci = GetCCI(c->cci.cci, false); //don't need control information
            q.bindValue(":STIGId", stig.id);
            q.bindValue(":CCIId", c->cci.id);
            q.bindValue(":rule", c->rule);
            q.bindValue(":vulnNum", c->vulnNum);
            q.bindValue(":groupTitle", c->groupTitle);
            q.bindValue(":ruleVersion", c->ruleVersion);
            q.bindValue(":severity", c->severity);
            q.bindValue(":weight", c->weight);
            q.bindValue(":title", c->title);
            q.bindValue(":vulnDiscussion", c->vulnDiscussion);
            q.bindValue(":falsePositives", c->falsePositives);
            q.bindValue(":falseNegatives", c->falseNegatives);
            q.bindValue(":fix", c->fix);
            q.bindValue(":check", c->check);
            q.bindValue(":documentable", c->documentable);
            q.bindValue(":mitigations", c->mitigations);
            q.bindValue(":severityOverrideGuidance", c->severityOverrideGuidance);
            q.bindValue(":checkContentRef", c->checkContentRef);
            q.bindValue(":potentialImpact", c->potentialImpact);
            q.bindValue(":thirdPartyTools", c->thirdPartyTools);
            q.bindValue(":mitigationControl", c->mitigationControl);
            q.bindValue(":responsibility", c->responsibility);
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

void DbManager::DeleteSTIG(int id)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("DELETE FROM STIGCheck WHERE STIGId = :STIGId");
        q.bindValue(":STIGId", id);
        q.exec();
        q.prepare("DELETE FROM STIG WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (!_delayCommit)
            db.commit();
    }
}

void DbManager::DeleteSTIG(STIG s)
{
    DeleteSTIG(s.id);
}

CCI DbManager::GetCCI(int cci, bool includeControl)
{
    QSqlDatabase db;
    CCI c;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, ControlId, cci, definition FROM CCI WHERE cci = :cci");
        q.bindValue(":cci", cci);
        q.exec();
        while (q.next())
        {
            c.id = q.value(0).toInt();
            if (includeControl)
            {
                c.control = GetControl(q.value(1).toInt());
            }
            c.cci = q.value(2).toInt();
            c.definition = q.value(3).toString();
        }
    }
    return c;
}

CCI DbManager::GetCCI(CCI cci, bool includeControl)
{
    if (cci.id < 0)
    {
        return GetCCI(cci.cci, includeControl);
    }
    QSqlDatabase db;
    CCI c;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, ControlId, cci, definition FROM CCI WHERE id = :id");
        q.bindValue(":id", cci.id);
        q.exec();
        while (q.next())
        {
            c.id = q.value(0).toInt();
            if (includeControl)
            {
                c.control = GetControl(q.value(1).toInt());
            }
            c.cci = q.value(2).toInt();
            c.definition = q.value(3).toString();
        }
    }
    return c;
}

QList<CCI> DbManager::GetCCIs(bool includeControl)
{
    QSqlDatabase db;
    QList<CCI> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, ControlId, cci, definition FROM CCI ORDER BY cci");
        q.exec();
        while (q.next())
        {
            CCI c;
            c.id = q.value(0).toInt();
            if (includeControl)
            {
                c.control = GetControl(q.value(1).toInt());
            }
            c.cci = q.value(2).toInt();
            c.definition = q.value(3).toString();

            ret.append(c);
        }
    }
    return ret;
}

QList<STIGCheck *> DbManager::GetSTIGChecksPtr(STIG s, bool includeCCI)
{
    QSqlDatabase db;
    QList<STIGCheck*> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT `id`, `STIGId`, `CCIId`, `rule`, `vulnNum`, `groupTitle`, `ruleVersion`, `severity`, `weight`, `title`, `vulnDiscussion`, `falsePositives`, `falseNegatives`, `fix`, `check`, `documentable`, `mitigations`, `severityOverrideGuidance`, `checkContentRef`, `potentialImpact`, `thirdPartyTools`, `mitigationControl`, `responsibility` FROM STIGCheck WHERE STIGId = :STIGId");
        q.bindValue(":STIGId", s.id);
        q.exec();
        while (q.next())
        {
            STIGCheck *c = new STIGCheck(); //must be deleted by STIG container or by caller
            c->id = q.value(0).toInt();
            c->stig = s;
            CCI cci;
            cci.id = q.value(2).toInt();
            c->cci = includeCCI ? GetCCI(cci) : cci;
            c->rule = q.value(3).toString();
            c->vulnNum = q.value(4).toString();
            c->groupTitle = q.value(5).toString();
            c->ruleVersion = q.value(6).toString();
            c->severity = static_cast<Severity>(q.value(7).toInt());
            c->weight = q.value(8).toDouble();
            c->title = q.value(9).toString();
            c->vulnDiscussion = q.value(10).toString();
            c->falsePositives = q.value(11).toString();
            c->falseNegatives = q.value(12).toString();
            c->fix = q.value(13).toString();
            c->check = q.value(14).toString();
            c->documentable = q.value(15).toBool();
            c->mitigations = q.value(16).toString();
            c->severityOverrideGuidance = q.value(17).toString();
            c->checkContentRef = q.value(18).toString();
            c->potentialImpact = q.value(19).toString();
            c->thirdPartyTools = q.value(20).toString();
            c->mitigationControl = q.value(21).toString();
            c->thirdPartyTools = q.value(22).toString();
            ret.append(c);
        }
    }
    return ret;
}

QList<STIG> DbManager::GetSTIGs(bool includeChecks)
{
    QSqlDatabase db;
    QList<STIG> ret;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, title, description, release, version FROM STIG ORDER BY title");
        q.exec();
        while (q.next())
        {
            STIG s;
            s.id = q.value(0).toInt();
            s.title = q.value(1).toString();
            s.description = q.value(2).toString();
            s.release = q.value(3).toString();
            s.version = q.value(4).toInt();
            if (includeChecks)
            {
                s.checks = GetSTIGChecksPtr(s, false);
            }
            ret.append(s);
        }
    }
    return ret;
}

Control DbManager::GetControl(int id, bool includeFamily)
{
    Control ret;
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("SELECT id, FamilyId, number, enhancement, title FROM Control WHERE id = :id");
        q.bindValue(":id", id);
        q.exec();
        if (q.next())
        {
            ret.id = q.value(0).toInt();;
            if (includeFamily)
                ret.family = GetFamily(q.value(1).toInt());
            ret.number = q.value(2).toInt();
            ret.enhancement = q.value(3).isNull() ? -1 : q.value(3).toInt();
            ret.title = q.value(4).toString();
        }
    }
    return ret;
}

Control DbManager::GetControl(QString control, bool includeId)
{
    Control ret;
    ret.id = -1;
    ret.enhancement = -1;
    ret.title = "";
    ret.family.id = -1;
    QString family(control.left(2));
    control = control.right(control.length()-3);
    QString enhancement("");
    if (control.contains('('))
    {
        int tmpIndex = control.indexOf('(');
        enhancement = control.right(control.length() - tmpIndex - 1);
        enhancement = enhancement.left(enhancement.length() - 1);
        control = control.left(control.indexOf('('));
        ret.enhancement = enhancement.toInt();
    }
    ret.number = control.toInt();
    if (includeId)
    {
        ret.family = GetFamily(family);
        QSqlDatabase db;
        if (this->CheckDatabase(db))
        {
            QSqlQuery q(db);
            if (ret.enhancement >= 0)
                q.prepare("SELECT id, title FROM Control WHERE number = :number AND FamilyId = :FamilyId AND enhancement = :enhancement");
            else
                q.prepare("SELECT id, title FROM Control WHERE number = :number AND FamilyId = :FamilyId");
            q.bindValue(":number", ret.number);
            q.bindValue(":FamilyId", ret.family.id);
            if (ret.enhancement >= 0)
                q.bindValue(":enhancement", ret.enhancement);
            q.exec();
            if (q.next())
            {
                ret.id = q.value(0).toInt();
                ret.title = q.value(1).toString();
            }
        }
        else
        {
            ret.family.acronym = family;
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

Family DbManager::GetFamily(QString acronym)
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

QString DbManager::GetVariable(QString name)
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

void DbManager::UpdateVariable(QString name, QString value)
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
                      "FOREIGN KEY(`STIGId`) REFERENCES `STIG`(`id`), "
                      "FOREIGN KEY(`CCIId`) REFERENCES `CCI`(`id`) "
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
