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

#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <QSqlDatabase>
#include <QString>

#include <tuple>

#include "asset.h"
#include "cci.h"
#include "control.h"
#include "family.h"
#include "stig.h"
#include "stigcheck.h"

class DbManager
{
public:
    DbManager();
    DbManager(const QString& connectionName);
    DbManager(const QString& path, const QString& connectionName);
    ~DbManager();
    void DelayCommit(bool delay);

    bool AddAsset(Asset &a);
    bool AddCCI(CCI &c);
    void AddControl(QString control, QString title);
    void AddFamily(QString acronym, QString description);
    void AddSTIG(STIG s, QList<STIGCheck*> c);
    void AddSTIGToAsset(STIG s, Asset a);

    void DeleteCCIs();
    void DeleteSTIG(int id);
    void DeleteSTIG(STIG s);

    Asset GetAsset(int id);
    QList<Asset> GetAssets();
    CCI GetCCI(int cci);
    CCI GetCCIByCCI(int cci);
    CCI GetCCIByCCI(CCI cci);
    QList<CCI> GetCCIs();
    Control GetControl(int id);
    Control GetControl(QString control);
    Family GetFamily(QString acronym);
    Family GetFamily(int id);
    QList<Family> GetFamilies();
    STIG GetSTIG(int id);
    STIGCheck GetSTIGCheck(int id);
    QList<STIGCheck> GetSTIGChecks(STIG stig);
    QList<STIG> GetSTIGs(Asset a);
    QList<STIG> GetSTIGs(QString whereClause = "", QList<std::tuple<QString, QVariant>> = {});
    QString GetVariable(QString name);

    void UpdateVariable(QString name, QString value);

    QString Sanitize(QString s);

private:
    bool UpdateDatabaseFromVersion(int version);
    bool CheckDatabase(QSqlDatabase &db);
    bool _delayCommit;
};

#endif // DBMANAGER_H
