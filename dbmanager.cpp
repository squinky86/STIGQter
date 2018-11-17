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
#include <QtDebug>

DbManager::DbManager() : DbManager(QCoreApplication::applicationDirPath() + "/STIGQter.db") { }

DbManager::DbManager(const QString& path)
{
    bool initialize = false;

    //check if database exists or create it
    if (!QFile::exists(path))
        initialize = true;

    //open SQLite Database
    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName(path);

    if (!m_db.open())
        qDebug() << "Error: connection with database fail";
    else
        qDebug() << "Database: connection ok";

    if (initialize)
        UpdateDatabaseFromVersion(0);
}

bool DbManager::UpdateDatabaseFromVersion(int version)
{
    if (version <= 0)
    {
        //New database; initial setup
        QSqlQuery q("CREATE TABLE `Family` ( "
                    "`id`	INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "`Acronym`	TEXT UNIQUE, "
                    "`Description`	TEXT UNIQUE"
                    ")");
        q.exec();

        //write changes from update
        m_db.commit();
    }

    return EXIT_SUCCESS;
}
