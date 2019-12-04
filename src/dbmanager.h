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
#include <QVector>

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
    DbManager(const DbManager &db);
    DbManager(DbManager &&orig) noexcept;
    ~DbManager();
    DbManager& operator=(const DbManager &right);
    DbManager& operator=(DbManager &&orig) noexcept;
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
    bool DeleteDB();
    bool DeleteEmassImport();
    bool DeleteSTIG(int id);
    bool DeleteSTIG(const STIG &stig);
    bool DeleteSTIGFromAsset(const STIG &stig, const Asset &asset);

    Asset GetAsset(int id);
    Asset GetAsset(const QString &hostName);
    Asset GetAsset(const Asset &asset);
    QList<Asset> GetAssets(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    QList<Asset> GetAssets(const STIG &stig);
    CCI GetCCI(int id);
    CCI GetCCI(const CCI &cci, const STIG *stig = nullptr);
    QList<CCI> GetCCIs(QVector<int> ccis);
    QList<CCI> GetCCIs(const Control &c);
    QList<CCI> GetCCIs(int STIGCheckId);
    CCI GetCCIByCCI(int cci, const STIG *stig = nullptr);
    QList<CCI> GetCCIs(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    CKLCheck GetCKLCheck(int id);
    CKLCheck GetCKLCheck(const CKLCheck &ckl);
    CKLCheck GetCKLCheckByDISAId(int assetId, const QString &disaId);
    QList<CKLCheck> GetCKLChecks(const Asset &asset, const STIG *stig = nullptr);
    QList<CKLCheck> GetCKLChecks(const CCI &cci);
    QList<CKLCheck> GetCKLChecks(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    Control GetControl(int id);
    Control GetControl(const QString &control);
    QList<Control> GetControls(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    QString GetDBPath();
    Family GetFamily(const QString &acronym);
    Family GetFamily(int id);
    QList<Family> GetFamilies(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    STIG GetSTIG(int id);
    STIG GetSTIG(const QString &title, int version, const QString &release);
    STIG GetSTIG(const STIG &stig);
    STIGCheck GetSTIGCheck(int id);
    STIGCheck GetSTIGCheck(const STIG &stig, const QString &rule);
    STIGCheck GetSTIGCheck(const STIGCheck &stigcheck);
    QList<STIGCheck> GetSTIGChecks(const STIG &stig);
    QList<STIGCheck> GetSTIGChecks(const CCI &cci);
    QList<STIGCheck> GetSTIGChecks(const QString &whereClause = "", const QList<std::tuple<QString, QVariant>> &variables = {});
    QList<STIG> GetSTIGs(const Asset &asset);
    QList<STIG> GetSTIGs(const QString &whereClause = "", const QList<std::tuple<QString, QVariant> > &variables = {});
    QString GetVariable(const QString &name);

    bool IsEmassImport();

    bool LoadDB(const QString &path);
    bool SaveDB(const QString &path);
    QByteArray HashDB();

    bool UpdateAsset(const Asset &asset);
    bool UpdateCCI(const CCI &cci);
    bool UpdateCKLCheck(const CKLCheck &check);
    bool UpdateSTIGCheck(const STIGCheck &check);
    bool UpdateVariable(const QString &name, const QString &value);

private:
    bool UpdateDatabaseFromVersion(int version);
    static bool CheckDatabase(QSqlDatabase &db);
    QString _dbPath;
    bool _delayCommit{};
};

#endif // DBMANAGER_H
