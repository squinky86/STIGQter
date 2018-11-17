#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <QSqlDatabase>
#include <QString>

class DbManager
{
public:
    DbManager();
    DbManager(const QString& path);
private:
    QSqlDatabase m_db;
    bool UpdateDatabaseFromVersion(int version);
};

#endif // DBMANAGER_H
