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
 * @class DbManager
 * @brief DbManager::DbManager represents the data layer for the
 * application.
 *
 * Each instance of the @a DbManager uses a thread-specific
 * connection to the SQLite database. Before executing queries, each
 * function checks the connection to the database by checking if the
 * current thread currently has a connection. If it does, the
 * thread's connection is reused. If not, a new, parallel connection
 * is established.
 *
 * Upon successful connection to the database, the version of the
 * database is checked to make sure that it is the latest version.
 *
 * The Semantic Versioning 2.0.0 system is utilized with the database
 * version being the main driver. While in beta (0.1.x), database
 * consistency is not kept. This means that databases built using
 * version 0.1.0_beta of STIGQter are incompatible with 0.1.1_beta.
 * Once released, the database will automatically be upgraded for
 * each new STIGQter revision (for major releases). For example, a
 * database built with STIGQter 1.0.0 would be compatible with
 * STIGQter 1.5.3. However, a database built with STIGQter 1.5.3 may
 * have features unsupported by STIGQter 1.0.0. The constructor for
 * the DbManager handles the automatic detection and upgrade of the
 * database.
 */

/**
 * @brief DbManager::DbManager
 *
 * Default constructor.
 */
DbManager::DbManager() : DbManager(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()))) { }

/**
 * @overload DbManager::DbManager()
 * @brief DbManager::DbManager
 * @param connectionName
 *
 * Overloaded constructor with current thread's connection already
 * provided. If running from a standalone directory, STIGQter.db can
 * be present locally. If there is not a local STIGQter.db, the
 * application directory for the user is used.
 */
DbManager::DbManager(const QString& connectionName) : DbManager(
                                                          QFile::exists(QCoreApplication::applicationDirPath() + "/STIGQter.db") ?
                                                              (QCoreApplication::applicationDirPath() + "/STIGQter.db") :
                                                              QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/STIGQter.db",
                                                          connectionName) { }


/**
 * @overload DbManager::DbManager()
 * @brief DbManager::DbManager
 * @param path
 * @param connectionName
 *
 * Overloaded constructor with path to SQLite DB and current thread's
 * connection already provided.
 */
DbManager::DbManager(const QString& path, const QString& connectionName) :
    _dbPath(path),
    _delayCommit(false),
    _logLevel(-1)
{
    QSqlDatabase db = QSqlDatabase::database(connectionName);

    if (!db.isValid())
    {
        bool initialize = false;

        QFileInfo fi(path);
        if (!fi.absoluteDir().exists())
        {
            fi.absoluteDir().mkpath(QStringLiteral("."));
        }

        //check if database file exists or create it
        if (!QFile::exists(path))
            initialize = true;

        db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(path);

        if (initialize)
            UpdateDatabaseFromVersion(0);

        int version = GetVariable(QStringLiteral("version")).toInt();
        UpdateDatabaseFromVersion(version);
    }

    if (!db.open())
    {
        Warning(QStringLiteral("Unable to Open DB"), "Unable to open DB " + path);
    }
}

/**
 * @brief DbManager::DbManager
 * @param db
 *
 * Copy Constructor
 */
DbManager::DbManager(const DbManager &db)
{
    *this = db;
}

/**
 * @brief DbManager::DbManager
 * @param orig
 *
 * Move Constructor
 */
DbManager::DbManager(DbManager &&orig) noexcept :
    _dbPath(std::move(orig._dbPath)),
    _delayCommit(orig._delayCommit),
    _logLevel(orig._logLevel)
{
}

/**
 * @brief DbManager::~DbManager
 *
 * The destructor verifies that all changes have been written to the
 * database. The connection remains open for multithreaded processing.
 */
DbManager::~DbManager()
{
    if (_delayCommit)
    {
        QSqlDatabase db;
        if (CheckDatabase(db))
        {
            db.commit();
        }
    }
}

/**
 * @brief DbManager::operator=
 * @param right
 * @return this
 *
 * Copy Operator
 */
DbManager &DbManager::operator=(const DbManager &right)
{
    if (this != &right)
    {
        _delayCommit = right._delayCommit;
        _dbPath = right._dbPath;
        _logLevel = right._logLevel;
    }
    return *this;
}

/**
 * @brief DbManager::operator =
 * @param orig
 * @return
 *
 * Move Operator
 */
DbManager &DbManager::operator=(DbManager &&orig) noexcept
{
    if (this != &orig)
    {
        _delayCommit = orig._delayCommit;
        _dbPath = std::move(orig._dbPath);
        _logLevel = orig._logLevel;
    }
    return *this;
}

/**
 * @brief DbManager::DelayCommit
 * @param delay
 *
 * When engaging in a large quantity of writes, the data may be
 * buffered in memory without committing the changes to the database
 * temporarily by setting @a delay to @c true. Setting @a delay to
 * @c false or destructing the database connection will commit the
 * changes that have been buffered.
 *
 * Developers should be cautious: buffered changes may not show up in
 * parallel threads or in threads that are executing and need the
 * data that have not yet been committed.
 */
void DbManager::DelayCommit(bool delay)
{
    if (delay)
    {
        QSqlDatabase db;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("PRAGMA journal_mode = OFF"));
            q.exec();
            q.prepare(QStringLiteral("PRAGMA synchronous = OFF"));
            q.exec();
        }
    }
    else
    {
        QSqlDatabase db;
        if (CheckDatabase(db))
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("PRAGMA journal_mode = ON"));
            q.exec();
            q.prepare(QStringLiteral("PRAGMA synchronous = ON"));
            q.exec();
            db.commit();
        }
    }
    _delayCommit = delay;
}

/**
 * @brief DbManager::Log
 * @param severity
 * @param location
 * @param query
 * @return true if the log record is written to the database; otherwise, false.
 */
bool DbManager::Log(int severity, const QString &location, const QSqlQuery &query)
{
    if (GetLogLevel() > 1)
    {
        return Log(severity, location, GetLastExecutedQuery(query));
    }
    return false;
}

/**
 * @brief DbManager::Log
 * @param severity
 * @param location
 * @param message
 * @param level
 * @return true if the log record is written to the database; otherwise, false.
 *
 * Log events to the logging table.
 */
bool DbManager::Log(int severity, const QString &location, const QString &message)
{
    bool ret = false;
    QSqlDatabase db;
    if (CheckDatabase(db))
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("INSERT INTO Log (`when`, `severity`, `location`, `message`, `user`) VALUES(:datetime, :severity, :location, :message, :user)"));
        //get ISO 8601 datestamp with timezone
        q.bindValue(QStringLiteral(":datetime"), QDateTime::currentDateTime().toOffsetFromUtc(QDateTime::currentDateTime().offsetFromUtc()).toString(Qt::ISODate));
        q.bindValue(QStringLiteral(":severity"), severity);
        q.bindValue(QStringLiteral(":location"), location);
        q.bindValue(QStringLiteral(":message"), message);
        //logging of username required by STIG rule SV-84059r1_rule
        q.bindValue(QStringLiteral(":user"), QDir::home().dirName());
        ret = q.exec();
        //logging is not logged
    }
    return ret;
}

/**
 * @brief DbManager::CheckDatabase
 * @param db
 * @return @c True when the database connection is ready to use.
 * Otherwise, @c false.
 *
 * Each thread in the application gets it own database connection.
 * Calling CheckDatabase on the QSqlDatabase will bind it to the
 * thread's existing connection or create a new one for the current
 * thread.
 */
bool DbManager::CheckDatabase(QSqlDatabase &db)
{
    db = QSqlDatabase::database(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId())));
    if (!db.isOpen())
        db.open();
    if (!db.isOpen())
        return false;
    return db.isValid();
}
