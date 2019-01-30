/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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
#include "cklcheck.h"
#include "control.h"
#include "family.h"
#include "stig.h"
#include "stigcheck.h"

class DbManager
{
public:
    explicit DbManager();
    explicit DbManager(const QString& connectionName);
    explicit DbManager(const QString& path, const QString& connectionName);
    ~DbManager();
    void DelayCommit(bool delay);

    bool AddAsset(Asset &asset);
    bool AddCCI(CCI &cci);
    bool AddControl(const QString &control, const QString &title, const QString &description);
    bool AddFamily(const QString &acronym, const QString &description);
    bool AddSTIG(STIG stig, QList<STIGCheck> checks, bool stigExists = false);
    bool AddSTIGToAsset(const STIG &stig, const Asset &asset);

    bool DeleteAsset(int id);
    bool DeleteAsset(const Asset &asset);
    bool DeleteCCIs();
    bool DeleteSTIG(int id);
    bool DeleteSTIG(const STIG &stig);
    bool DeleteSTIGFromAsset(const STIG &stig, const Asset &asset);

    Asset GetAsset(int id);
    Asset GetAsset(const QString &hostName);
    Asset GetAsset(const Asset &asset);
    QList<Asset> GetAssets(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    QList<Asset> GetAssets(const STIG &stig);
    CCI GetCCI(int id);
    CCI GetCCIByCCI(int cci, const STIG *stig = nullptr);
    CCI GetCCIByCCI(const CCI &cci, const STIG *stig = nullptr);
    QList<CCI> GetCCIs(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    CKLCheck GetCKLCheck(int id);
    CKLCheck GetCKLCheck(const CKLCheck &ckl);
    QList<CKLCheck> GetCKLChecks(const Asset &asset, const STIG *stig = nullptr);
    QList<CKLCheck> GetCKLChecks(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    Control GetControl(int id);
    Control GetControl(QString control);
    Family GetFamily(const QString &acronym);
    Family GetFamily(int id);
    QList<Family> GetFamilies();
    STIG GetSTIG(int id);
    STIG GetSTIG(const QString &title, int version, const QString &release);
    STIG GetSTIG(const STIG &stig);
    STIGCheck GetSTIGCheck(int id);
    STIGCheck GetSTIGCheck(const STIG &stig, const QString &rule);
    QList<STIGCheck> GetSTIGChecks(const STIG &stig);
    QList<STIGCheck> GetSTIGChecks(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    QList<STIG> GetSTIGs(const Asset &asset);
    QList<STIG> GetSTIGs(const QString &whereClause = "", const QList<std::tuple<QString, QVariant> > &variables = {});
    QString GetVariable(const QString &name);

    void ImportCCI(const CCI &cci);
    void UpdateCKLCheck(const CKLCheck &check);
    void UpdateVariable(const QString &name, const QString &value);

private:
    bool UpdateDatabaseFromVersion(int version);
    static bool CheckDatabase(QSqlDatabase &db);
    bool _delayCommit;
};

#endif // DBMANAGER_H
