// SPDX-License-Identifier: GPL-3.0-or-later
#include "dbmanager.h"
#include "xccdfresults.h"
#include <QSqlError>
#include <QSqlQuery>
#include <QThread>

bool DbManager::UpdateSTIGChecks(const QVector<STIGCheck> &checks)
{
    QSqlDatabase connection;
    if (!CheckDatabase(connection)) return false;
    QSqlQuery journal(connection);
    if (!journal.exec(QStringLiteral("PRAGMA journal_mode = DELETE"))) return false;
    journal.finish();
    if (!connection.transaction()) return false;
    for (const auto &check : checks) {
        if (QThread::currentThread()->isInterruptionRequested() || !UpdateSTIGCheck(check)) {
            connection.rollback();
            return false;
        }
    }
    if (connection.commit()) return true;
    connection.rollback();
    return false;
}

bool DbManager::ApplyXccdfResults(int assetId, const XccdfResults &results, const QString &source,
                                QStringList &missing, QString &error)
{
    QSqlDatabase connection;
    if (!CheckDatabase(connection)) { error = QStringLiteral("Database unavailable."); return false; }
    // DelayCommit is a legacy performance switch, not a transaction. This new
    // operation uses a real journal and rolls back the whole validated file.
    QSqlQuery journal(connection);
    const bool journalReady = journal.exec(QStringLiteral("PRAGMA journal_mode = DELETE"));
    journal.finish();
    if (!journalReady || !connection.transaction()) {
        error = QStringLiteral("Unable to start the XCCDF import transaction.");
        return false;
    }
    struct Rollback { QSqlDatabase &db; bool committed = false; ~Rollback() { if (!committed) db.rollback(); } } transaction{connection};
    Asset asset = GetAsset(assetId);
    if (asset.id < 0) { error = QStringLiteral("The selected asset no longer exists."); return false; }
    if (!results.ip.isEmpty()) asset.hostIP = results.ip;
    if (!results.mac.isEmpty()) asset.hostMAC = results.mac;
    if (!results.fqdn.isEmpty()) asset.hostFQDN = results.fqdn;
    bool ok = UpdateAsset(asset);
    missing.clear();
    for (const auto &result : results.rules) {
        CKLCheck check = GetCKLCheckByDISAId(assetId, result.id);
        if (check.id < 0) { missing.append(result.id); continue; }
        check.status = result.status;
        check.findingDetails += QStringLiteral("This finding information was set by XCCDF file ") + source;
        ok = UpdateCKLCheck(check) && ok;
    }
    if (!ok || !connection.commit()) {
        error = QStringLiteral("The XCCDF changes could not be saved; the file's changes were rolled back.");
        return false;
    }
    transaction.committed = true;
    error.clear();
    return true;
}
