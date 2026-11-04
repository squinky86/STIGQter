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

namespace {
constexpr int CurrentDatabaseVersion = 10;

bool ValidateDatabaseFile(const QString &path, const QString &connectionName,
                          int &version, QString &error)
{
    bool valid = false;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(path);
        if (!db.open())
        {
            error = db.lastError().text();
        }
        else
        {
            QSqlQuery integrity(db);
            if (!integrity.exec(QStringLiteral("PRAGMA quick_check")) ||
                !integrity.next() || integrity.value(0).toString() != QStringLiteral("ok"))
            {
                error = QStringLiteral("The save file failed SQLite's integrity check.");
            }
            else
            {
                QSet<QString> tables;
                QSqlQuery schema(db);
                schema.exec(QStringLiteral("SELECT name FROM sqlite_master WHERE type = 'table'"));
                while (schema.next())
                    tables.insert(schema.value(0).toString());

                const QSet<QString> requiredTables = {
                    QStringLiteral("variables"), QStringLiteral("Family"),
                    QStringLiteral("Control"), QStringLiteral("CCI"),
                    QStringLiteral("STIG"), QStringLiteral("STIGCheck"),
                    QStringLiteral("Asset"), QStringLiteral("AssetSTIG"),
                    QStringLiteral("CKLCheck")
                };
                if (!(requiredTables - tables).isEmpty())
                {
                    error = QStringLiteral("The save file does not contain a complete STIGQter database.");
                }
                else
                {
                    QSqlQuery versionQuery(db);
                    versionQuery.prepare(QStringLiteral("SELECT value FROM variables WHERE name = 'version'"));
                    bool versionOk = false;
                    if (versionQuery.exec() && versionQuery.next())
                        version = versionQuery.value(0).toString().toInt(&versionOk);

                    if (!versionOk || version < 1 || version > CurrentDatabaseVersion)
                    {
                        error = version > CurrentDatabaseVersion
                            ? QStringLiteral("The save file was created by a newer, incompatible STIGQter version.")
                            : QStringLiteral("The save file has an invalid database version.");
                    }
                    else
                    {
                        valid = true;
                    }
                }
            }
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(connectionName);
    return valid;
}
}

/**
 * @brief DbManager::LoadDB
 * @param path
 * @return @c True when the database is restored from @a path,
 * otherwise @c false.
 */
bool DbManager::LoadDB(const QString &path)
{
    QFile source(path);
    if (!source.open(QFile::ReadOnly))
    {
        Warning(QStringLiteral("Unable to Open File"), "The file " + path + " could not be opened for reading.");
        return false;
    }
    if (source.size() > 1073741828)
    {
        Warning(QStringLiteral("File Too Large"), QStringLiteral("The selected save file exceeds the safety limit of 1GB."));
        return false;
    }

    const QByteArray compressedData = source.readAll();
    if (compressedData.size() < 4)
    {
        Warning(QStringLiteral("Invalid Save File"), QStringLiteral("The selected file is truncated or is not a STIGQter save file."));
        return false;
    }

    // qUncompress stores the expected uncompressed size in the first four bytes.
    const quint32 expectedSize = (static_cast<quint32>(static_cast<unsigned char>(compressedData[0])) << 24) |
                                 (static_cast<quint32>(static_cast<unsigned char>(compressedData[1])) << 16) |
                                 (static_cast<quint32>(static_cast<unsigned char>(compressedData[2])) << 8) |
                                 (static_cast<quint32>(static_cast<unsigned char>(compressedData[3])));
    if (expectedSize > 1073741824)
    {
        Warning(QStringLiteral("File Too Large"), "The uncompressed database size (" + QString::number(expectedSize) + " bytes) exceeds the safety limit of 1GB.");
        return false;
    }

    const QByteArray databaseData = qUncompress(compressedData);
    if (databaseData.size() != static_cast<qsizetype>(expectedSize) ||
        !databaseData.startsWith("SQLite format 3\0"))
    {
        Warning(QStringLiteral("Invalid Save File"), QStringLiteral("The selected file could not be decompressed into a valid SQLite database."));
        return false;
    }

    QTemporaryFile candidate;
    if (!candidate.open() || candidate.write(databaseData) != databaseData.size())
    {
        Warning(QStringLiteral("Unable to Load File"), QStringLiteral("A temporary database could not be created for validation."));
        return false;
    }
    candidate.flush();
    const QString candidatePath = candidate.fileName();
    candidate.close();

    int candidateVersion = 0;
    QString validationError;
    const QString validationConnection = QStringLiteral("load-validation-%1").arg(reinterpret_cast<quint64>(QThread::currentThreadId()));
    if (!ValidateDatabaseFile(candidatePath, validationConnection, candidateVersion, validationError))
    {
        Warning(QStringLiteral("Invalid Save File"), validationError);
        return false;
    }

    bool migrationSucceeded = false;
    QThread *migrationThread = QThread::create([candidatePath, &migrationSucceeded]() {
        const QString connectionName = QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()));
        {
            DbManager migration(candidatePath, connectionName);
            migrationSucceeded = migration.GetVariable(QStringLiteral("version")).toInt() == CurrentDatabaseVersion;
        }
        {
            QSqlDatabase migrated = QSqlDatabase::database(connectionName, false);
            migrated.close();
        }
        QSqlDatabase::removeDatabase(connectionName);
    });
    migrationThread->start();
    migrationThread->wait();
    delete migrationThread;

    if (!migrationSucceeded)
    {
        Warning(QStringLiteral("Unable to Load File"), QStringLiteral("The save file could not be upgraded to the current database version."));
        return false;
    }

    int migratedVersion = 0;
    validationError.clear();
    const QString migratedValidationConnection = QStringLiteral("load-migrated-validation-%1").arg(reinterpret_cast<quint64>(QThread::currentThreadId()));
    if (!ValidateDatabaseFile(candidatePath, migratedValidationConnection, migratedVersion, validationError) ||
        migratedVersion != CurrentDatabaseVersion)
    {
        Warning(QStringLiteral("Unable to Load File"), validationError.isEmpty()
            ? QStringLiteral("The upgraded save file has an invalid database version.") : validationError);
        return false;
    }

    QFile migratedCandidate(candidatePath);
    if (!migratedCandidate.open(QFile::ReadOnly))
    {
        Warning(QStringLiteral("Unable to Load File"), QStringLiteral("The validated temporary database could not be read."));
        return false;
    }
    const QByteArray migratedData = migratedCandidate.readAll();

    const QString currentConnectionName = QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()));
    QSqlDatabase currentConnection = QSqlDatabase::database(currentConnectionName, false);
    const bool reopenConnection = currentConnection.isValid() && currentConnection.isOpen();
    if (reopenConnection)
        currentConnection.close();

    QSaveFile destination(_dbPath);
    if (!destination.open(QFile::WriteOnly) ||
        destination.write(migratedData) != migratedData.size() ||
        !destination.commit())
    {
        if (reopenConnection)
            currentConnection.open();
        Warning(QStringLiteral("Unable to Load File"), "The validated database could not replace " + _dbPath + ".");
        return false;
    }

    if (reopenConnection && !currentConnection.open())
    {
        Warning(QStringLiteral("Unable to Open DB"), "Unable to reopen DB " + _dbPath);
        return false;
    }
    return true;
}

/**
 * @brief DbManager::SaveDB
 * @param path
 * @return @c True when the database is saved to @a path. Otherwise,
 * @c false.
 */
bool DbManager::SaveDB(const QString &path)
{
    const QFileInfo sourceInfo(_dbPath), destinationInfo(path);
    if (sourceInfo.absoluteFilePath() == destinationInfo.absoluteFilePath() ||
        (!destinationInfo.canonicalFilePath().isEmpty() && sourceInfo.canonicalFilePath() == destinationInfo.canonicalFilePath())) {
        Warning(QStringLiteral("Unable to Save Project"), QStringLiteral("Choose a separate .stigqter snapshot file; the working database cannot be overwritten by a snapshot."));
        return false;
    }
    QFile source(_dbPath);
    QSaveFile dest(path);

    if (source.open(QFile::ReadOnly) && dest.open(QFile::WriteOnly))
    {
        const QByteArray data = source.readAll();
        if (source.error() == QFile::NoError)
        {
            const QByteArray compressed = qCompress(data, 9);
            if (dest.write(compressed) == compressed.size() && dest.commit())
                return true;
        }
    }

    Warning(QStringLiteral("Unable to Open File"), "The file " + path + " could not be opened for writing.");
    return false;
}

/**
 * @brief DbManager::HashDB
 * @return The SHA3_256 hash of the database file
 */
QByteArray DbManager::HashDB()
{
    QFile source(_dbPath);
    QByteArray ret;
    if (source.open(QFile::ReadOnly))
    {
        ret = QCryptographicHash::hash(qCompress(source.readAll(), 9), QCryptographicHash::Sha3_256);
        source.close();
    }
    return ret;
}
