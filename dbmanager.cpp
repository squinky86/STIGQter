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
