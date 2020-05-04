/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2020 Jon Hood, http://www.hoodsecurity.com/
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
#include "supplement.h"

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
    bool AddSTIG(STIG &stig, const QVector<STIGCheck> &checks, const QVector<Supplement> &supplements = {}, bool stigExists = false);
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
    QVector<Asset> GetAssets(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    QVector<Asset> GetAssets(const STIG &stig);
    CCI GetCCI(int id);
    CCI GetCCI(const CCI &cci, const STIG *stig = nullptr);
    QVector<CCI> GetCCIs(QVector<int> ccis);
    QVector<CCI> GetCCIs(const Control &c);
    QVector<CCI> GetCCIs(int STIGCheckId);
    CCI GetCCIByCCI(int cci, const STIG *stig = nullptr);
    QVector<CCI> GetCCIs(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    CKLCheck GetCKLCheck(int id);
    CKLCheck GetCKLCheck(const CKLCheck &ckl);
    CKLCheck GetCKLCheckByDISAId(int assetId, const QString &disaId);
    QVector<CKLCheck> GetCKLChecks(const Asset &asset, const STIG *stig = nullptr);
    QVector<CKLCheck> GetCKLChecks(const CCI &cci);
    QVector<CKLCheck> GetCKLChecks(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    Control GetControl(int id);
    Control GetControl(const QString &control);
    QVector<Control> GetControls(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    QString GetDBPath();
    Family GetFamily(const QString &acronym);
    Family GetFamily(int id);
    QVector<QString> GetLegacyIds(int STIGCheckId);
    int GetLogLevel();
    QVector<Family> GetFamilies(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    STIG GetSTIG(int id);
    STIG GetSTIG(const QString &title, int version, const QString &release);
    STIG GetSTIG(const STIG &stig);
    STIGCheck GetSTIGCheck(int id);
    STIGCheck GetSTIGCheck(const STIG &stig, const QString &rule);
    STIGCheck GetSTIGCheck(const STIGCheck &stigcheck);
    QVector<STIGCheck> GetSTIGChecks(const STIG &stig);
    QVector<STIGCheck> GetSTIGChecks(const CCI &cci);
    QVector<STIGCheck> GetSTIGChecks(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant>> &variables = {});
    QVector<STIG> GetSTIGs(const Asset &asset);
    QVector<STIG> GetSTIGs(const QString &whereClause = QString(), const QVector<std::tuple<QString, QVariant> > &variables = {});
    QVector<Supplement> GetSupplements(const STIG &stig);
    QString GetVariable(const QString &name);

    bool IsEmassImport();

    bool LoadDB(const QString &path);
    bool Log(int severity, const QString &location, const QString &message);
    bool Log(int severity, const QString &location, const QSqlQuery& query);
    bool SaveDB(const QString &path);
    QByteArray HashDB();

    bool UpdateAsset(const Asset &asset);
    bool UpdateCCI(const CCI &cci);
    bool UpdateCKLCheck(const CKLCheck &check);
    bool UpdateSTIG(const STIG &stig);
    bool UpdateSTIGCheck(const STIGCheck &check);
    bool UpdateVariable(const QString &name, const QString &value);

private:
    bool UpdateDatabaseFromVersion(int version);
    static bool CheckDatabase(QSqlDatabase &db);
    QString _dbPath;
    bool _delayCommit{};
    int _logLevel;
};

QString GetLastExecutedQuery(const QSqlQuery& query);

#endif // DBMANAGER_H
