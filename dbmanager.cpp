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
#include <QSqlQuery>
#include <QSqlError>
#include <QtDebug>
#include <QThread>

DbManager::DbManager() : DbManager(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()))) { }

DbManager::DbManager(const QString& connectionName) : DbManager(QCoreApplication::applicationDirPath() + "/STIGQter.db", connectionName) { }

DbManager::DbManager(const QString& path, const QString& connectionName)
{
    bool initialize = false;

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
}

void DbManager::AddFamily(QString acronym, QString description)
{
    QSqlDatabase db;
    if (this->CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare("INSERT INTO Family (Acronym, Description) VALUES(:acronym, :description)");
        q.bindValue(":acronym", acronym);
        q.bindValue(":description", description);
        q.exec();
        db.commit();
    }
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

            //write changes from update
            db.commit();
        }
    }

    return EXIT_SUCCESS;
}
