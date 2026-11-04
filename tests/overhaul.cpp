// SPDX-License-Identifier: GPL-3.0-or-later
#include "tst_stigqter.h"
#include "contentcatalog.h"
#include "common.h"
#include "dbmanager.h"
#include "download.h"
#include "stigqter.h"
#include "workerxccdf.h"
#include "xccdfresults.h"
#include "checklistwriter.h"
#include "workercklimport.h"
#include "workercklupgrade.h"
#include "workercklexport.h"
#include <QXmlStreamReader>
#include <QElapsedTimer>
#include <QSet>
#include <QBuffer>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QSignalSpy>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>
#include <QtEndian>
#include <QProcess>
#include <QSslSocket>
#include <QSslKey>
#include <QTcpServer>
#include <QStandardPaths>

namespace {
bool put(const QString &path, const QByteArray &data) {
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(data) == data.size();
}

QByteArray get(const QString &path) {
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}
struct RemoveFixtureAsset {
    int id;
    ~RemoveFixtureAsset() {
        DbManager db;
        const auto asset = db.GetAsset(id);
        for (const auto &stig : asset.GetSTIGs()) db.DeleteSTIGFromAsset(stig, asset);
        db.DeleteAsset(asset);
    }
};
}

void TestSTIGQter::test00_UntrustedTls()
{
    const QString openssl = QStandardPaths::findExecutable(QStringLiteral("openssl"));
    QVERIFY2(!openssl.isEmpty(), "The TLS fixture requires openssl");
    QTemporaryDir directory;
    const QString key = directory.filePath(QStringLiteral("key.pem"));
    const QString cert = directory.filePath(QStringLiteral("cert.pem"));
    QProcess generate;
    generate.start(openssl, {QStringLiteral("req"), QStringLiteral("-x509"), QStringLiteral("-newkey"), QStringLiteral("rsa:2048"),
        QStringLiteral("-nodes"), QStringLiteral("-keyout"), key, QStringLiteral("-out"), cert, QStringLiteral("-days"), QStringLiteral("1"),
        QStringLiteral("-subj"), QStringLiteral("/CN=localhost"), QStringLiteral("-addext"), QStringLiteral("subjectAltName=IP:127.0.0.1")});
    QVERIFY(generate.waitForFinished(10000));
    QCOMPARE(generate.exitCode(), 0);
    class Server : public QTcpServer {
    public:
        QSslCertificate certificate;
        QSslKey key;
        void incomingConnection(qintptr descriptor) override {
            auto *socket = new QSslSocket(this);
            socket->setLocalCertificate(certificate);
            socket->setPrivateKey(key);
            socket->setSocketDescriptor(descriptor);
            connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
            socket->startServerEncryption();
        }
    } server;
    server.certificate = QSslCertificate(get(cert));
    server.key = QSslKey(get(key), QSsl::Rsa);
    QVERIFY(server.listen(QHostAddress::LocalHost));
    const auto response = Downloads::fetch(QUrl(QStringLiteral("https://127.0.0.1:%1/").arg(server.serverPort())), nullptr, 1024, 3000);
    QVERIFY(!response.ok);
    QVERIFY2(response.error.contains(QStringLiteral("SSL"), Qt::CaseInsensitive) || response.error.contains(QStringLiteral("certificate"), Qt::CaseInsensitive), qPrintable(response.error));
}

void TestSTIGQter::test00_ContentCatalog()
{
    QTemporaryDir root;
    QVERIFY(root.isValid());
    const QString metadata = root.path() + QStringLiteral("/metadata/v1/");
    QVERIFY(QDir().mkpath(metadata));
    const QString archive = root.filePath(QStringLiteral("quarterly.zip"));
    QVERIFY(CreateZip(archive, {{QStringLiteral("STIG.zip"), QByteArrayLiteral("nested ZIP fixture")}, {QStringLiteral("Other.zip"), QByteArrayLiteral("another STIG")}}));
    const QByteArray archiveData = get(archive);
    const QString archiveHash = QString::fromLatin1(QCryptographicHash::hash(archiveData, QCryptographicHash::Sha256).toHex());
    const QString official = QStringLiteral("https://dl.dod.cyber.mil/test.zip");
    const QByteArray catalog = QJsonDocument(QJsonObject{{"schema_version", 1}, {"stigs", QJsonArray{
        QJsonObject{{"title", "Test STIG"}, {"version", 1}, {"release", "Release: 1"}, {"archive_member", "STIG.zip"},
                    {"url", official}, {"sha256", archiveHash}}}}}).toJson();
    const QString digest = QString::fromLatin1(QCryptographicHash::hash(catalog, QCryptographicHash::Sha256).toHex());
    const QString name = QStringLiteral("catalog-%1.json").arg(digest);
    QJsonObject manifest{{"schema_version", 1}, {"updated_at", "2026-11-03T00:00:00Z"},
        {"quarterly", QJsonObject{{"url", official}, {"sha256", archiveHash}, {"size", archiveData.size()}}},
        {"catalog", QJsonObject{{"path", name}, {"sha256", digest}}}};
    QVERIFY(put(metadata + name, catalog));
    QVERIFY(put(metadata + QStringLiteral("content.json"), QJsonDocument(manifest).toJson()));
    const QUrl site = QUrl::fromLocalFile(root.path() + '/');
    const QString cache = root.filePath(QStringLiteral("cache"));
    QString error;
    ContentCatalog first(site, cache);
    QVERIFY2(first.load(error), qPrintable(error));
    ContentCatalog::Archive selected;
    QVERIFY(first.find(QStringLiteral("Test STIG"), 1, QStringLiteral("Release: 1"), selected, error));
    QCOMPARE(selected.member, QStringLiteral("STIG.zip"));
    QVERIFY(!first.find(QStringLiteral("Test STIG"), 2, QStringLiteral("Release: 1"), selected, error));
    QVERIFY(!first.find(QStringLiteral("Test STIG"), 1, QStringLiteral("Release: 2"), selected, error));
    selected.url = QUrl::fromLocalFile(archive);
    QFile output(root.filePath(QStringLiteral("download.zip")));
    QVERIFY2(first.download(selected, &output, error), qPrintable(error));
    QCOMPARE(get(output.fileName()), QByteArrayLiteral("nested ZIP fixture"));
    const QStringList cacheDirectories = QDir(cache).entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    QCOMPARE(cacheDirectories.size(), 1);
    QVERIFY(put(cache + '/' + cacheDirectories.first() + '/' + name, QByteArrayLiteral("damaged cache")));
    ContentCatalog repair(site, cache);
    QVERIFY2(repair.load(error), qPrintable(error));
    // Once verified, a different member of the same quarterly archive remains
    // available even if the original source disappears during a batch import.
    QVERIFY(QFile::rename(archive, archive + QStringLiteral(".moved")));
    selected.member = QStringLiteral("Other.zip");
    QVERIFY2(first.download(selected, &output, error), qPrintable(error));
    QCOMPARE(get(output.fileName()), QByteArrayLiteral("another STIG"));
    selected.member = QStringLiteral("STIG.zip");
    QVERIFY(first.download(selected, &output, error));
    QCOMPARE(get(output.fileName()), QByteArrayLiteral("nested ZIP fixture"));
    QVERIFY(QFile::rename(archive + QStringLiteral(".moved"), archive));
    selected.sha256 = QByteArray(64, '0');
    QVERIFY(!first.download(selected, &output, error));
    QCOMPARE(get(output.fileName()), QByteArrayLiteral("nested ZIP fixture"));
    QVERIFY(put(metadata + QStringLiteral("content.json"), QByteArrayLiteral("truncated")));
    ContentCatalog cached(site, cache);
    QVERIFY2(cached.load(error), qPrintable(error));
    QVERIFY(cached.sourceDescription().startsWith(QStringLiteral("Cached")));
    ContentCatalog empty(site, root.filePath(QStringLiteral("empty-cache")));
    QVERIFY(!empty.load(error));
    QVERIFY(ContentCatalog::isDefaultQuarterly(QUrl(QStringLiteral("https://www.stigqter.com/stig.php"))));
    QVERIFY(!ContentCatalog::isDefaultQuarterly(QUrl(QStringLiteral("https://example.com/custom.zip"))));
    QVERIFY(!ContentCatalog::isDefaultQuarterly(QUrl::fromLocalFile(archive)));
}

void TestSTIGQter::test00_ArchiveFailures()
{
    QTemporaryDir root;
    const QString path = root.filePath(QStringLiteral("fixture.zip"));
    const QMap<QString, QByteArray> input{{QStringLiteral("fixture.xml"), QByteArray(4096, 'a')}, {QStringLiteral("empty"), {}}};
    QVERIFY(CreateZip(path, input));
    QCOMPARE(GetFilesFromZip(path), input);
    QByteArray corrupt = get(path);
    QVERIFY(corrupt.size() > 50);
    const auto filenameOffset = corrupt.indexOf("fixture.xml");
    QVERIFY(filenameOffset >= 30);
    const auto payload = filenameOffset + 11 + qFromLittleEndian<quint16>(corrupt.constData() + filenameOffset - 2);
    corrupt[payload] = static_cast<char>(corrupt[payload] ^ 0xff);
    QVERIFY(put(path, corrupt));
    QVERIFY(GetFilesFromZip(path).isEmpty());
    QVERIFY(put(path, QByteArrayLiteral("not a zip")));
    QVERIFY(GetFilesFromZip(path).isEmpty());
}

void TestSTIGQter::test00_XccdfParser()
{
    QByteArray xml = "<Benchmark><TestResult><fact name=\"urn:test:ipv4\">192.0.2.1</fact>"
        "<rule-result idref=\"xccdf_prefix_SV-1_rule\"><result>pass</result></rule-result>"
        "<rule-result idref=\"SV-2_rule\"><result>notapplicable</result></rule-result>"
        "<rule-result idref=\"SV-3_rule\"><result>fail</result></rule-result>"
        "<rule-result idref=\"SV-4_rule\"><result>error</result></rule-result></TestResult></Benchmark>";
    QBuffer buffer(&xml);
    QVERIFY(buffer.open(QIODevice::ReadOnly));
    XccdfResults results;
    QString error;
    QVERIFY2(ParseXccdfResults(&buffer, results, error), qPrintable(error));
    QCOMPARE(results.ip, QStringLiteral("192.0.2.1"));
    QCOMPARE(results.rules.size(), 3);
    QCOMPARE(results.rules[0].id, QStringLiteral("SV-1_rule"));
    QCOMPARE(results.rules[0].status, Status::NotAFinding);
    QCOMPARE(results.rules[1].status, Status::NotApplicable);
    QCOMPARE(results.rules[2].status, Status::Open);
    xml.chop(5); buffer.seek(0);
    QVERIFY(!ParseXccdfResults(&buffer, results, error));
    QVERIFY(results.rules.isEmpty());
    QVERIFY(results.ip.isEmpty());
}

void TestSTIGQter::test00_WorkerCleanup()
{
    procEvents();
    const auto before = QSqlDatabase::connectionNames();
    auto *worker = new WorkerXccdf(-1, {QStringLiteral("missing-xccdf.xml")});
    QSignalSpy warnings(worker, &Worker::ThrowWarning);
    QSignalSpy deleted(worker, &QObject::destroyed);
    QPointer<QThread> thread = w->ConnectThreads(worker);
    QVERIFY(!w->isProcessingEnabled());
    thread->start();
    procEvents();
    QCOMPARE(warnings.size(), 1);
    QTRY_COMPARE(deleted.size(), 1);
    QTRY_VERIFY(thread.isNull());
    for (const auto &name : QSqlDatabase::connectionNames()) QVERIFY(before.contains(name));
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04c_XccdfTransaction()
{
    DbManager db;
    const auto checks = db.GetCKLChecks();
    QVERIFY(!checks.isEmpty());
    const auto before = checks.first();
    const auto asset = db.GetAsset(before.assetId);
    XccdfResults results;
    results.ip = QStringLiteral("192.0.2.42");
    results.rules.append({before.GetRule(), Status::Open});
    QString error;
    QStringList missing;
    auto connection = QSqlDatabase::database(QString::number(reinterpret_cast<quint64>(QThread::currentThreadId())));
    QSqlQuery query(connection);
    QVERIFY(query.exec(QStringLiteral("CREATE TEMP TRIGGER reject_results BEFORE UPDATE ON CKLCheck BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")));
    QVERIFY(!db.ApplyXccdfResults(asset.id, results, QStringLiteral("fixture.xml"), missing, error));
    QCOMPARE(db.GetAsset(asset.id).hostIP, asset.hostIP);
    QCOMPARE(db.GetCKLCheck(before).findingDetails, before.findingDetails);
    QVERIFY(query.exec(QStringLiteral("DROP TRIGGER reject_results")));
    QVERIFY2(db.ApplyXccdfResults(asset.id, results, QStringLiteral("fixture.xml"), missing, error), qPrintable(error));
    QCOMPARE(db.GetAsset(asset.id).hostIP, results.ip);
    const auto after = db.GetCKLCheck(before);
    QCOMPARE(after.status, Status::Open);
    QCOMPARE(after.comments, before.comments);
    QCOMPARE(after.severityOverride, before.severityOverride);
    QCOMPARE(after.severityJustification, before.severityJustification);
    QCOMPARE(db.GetAsset(asset.id).marking, asset.marking);
    QVERIFY(after.findingDetails.endsWith(QStringLiteral("fixture.xml")));
    QVERIFY(db.UpdateAsset(asset));
    QVERIFY(db.UpdateCKLCheck(before));

    auto guides = db.GetSTIGChecks();
    QVERIFY(guides.size() >= 2);
    const auto originalGuide = guides[0];
    guides[0].title += QStringLiteral(" transaction fixture");
    guides[1].title += QStringLiteral(" transaction fixture");
    QVERIFY(query.exec(QStringLiteral("CREATE TEMP TRIGGER reject_mapping BEFORE UPDATE ON STIGCheck WHEN NEW.id = %1 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").arg(guides[1].id)));
    QVERIFY(!db.UpdateSTIGChecks({guides[0], guides[1]}));
    QCOMPARE(db.GetSTIGCheck(originalGuide).title, originalGuide.title);
    QVERIFY(query.exec(QStringLiteral("DROP TRIGGER reject_mapping")));
}

void TestSTIGQter::test04c_ProjectUpgrade()
{
    DbManager db;
    QTemporaryDir directory;
    const QString original = directory.filePath(QStringLiteral("original.stigqter"));
    QVERIFY(db.SaveDB(original));
    const QByteArray database = qUncompress(get(original));
    QVERIFY(database.startsWith("SQLite format 3"));
    const auto check = db.GetCKLChecks().first();
    const auto asset = db.GetAsset(check.assetId);
    const int count = db.GetCKLChecks().size();
    const QString marking = db.GetVariable(QStringLiteral("systemMarking"));
    for (int version : {9, 999}) {
        const QString path = directory.filePath(QStringLiteral("candidate.db"));
        QVERIFY(put(path, database));
        const QString name = QStringLiteral("fixture-project-editor");
        {
            auto connection = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name);
            connection.setDatabaseName(path);
            QVERIFY(connection.open());
            {
                QSqlQuery query(connection);
                QVERIFY(query.exec(QStringLiteral("UPDATE variables SET value = '%1' WHERE name = 'version'").arg(version)));
                if (version == 9) QVERIFY(query.exec(QStringLiteral("DELETE FROM variables WHERE name = 'systemMarking'")));
            }
            connection.close();
        }
        QSqlDatabase::removeDatabase(name);
        const QString snapshot = directory.filePath(QStringLiteral("candidate.stigqter"));
        QVERIFY(put(snapshot, qCompress(get(path), 9)));
        QCOMPARE(db.LoadDB(snapshot), version == 9);
        QCOMPARE(db.GetVariable(QStringLiteral("version")), QStringLiteral("10"));
        QCOMPARE(db.GetCKLChecks().size(), count);
        QCOMPARE(db.GetCKLCheck(check).comments, check.comments);
        QCOMPARE(db.GetCKLCheck(check).findingDetails, check.findingDetails);
        QCOMPARE(db.GetAsset(asset.id).marking, asset.marking);
        QVERIFY(db.LoadDB(original));
        QCOMPARE(db.GetVariable(QStringLiteral("systemMarking")), marking);
    }
    // A directory cannot be replaced by a snapshot; failures must be reported.
    QVERIFY(!db.SaveDB(directory.path()));
    QVERIFY(!db.SaveDB(db.GetDBPath()));
    QCOMPARE(db.GetCKLChecks().size(), count);
}

void TestSTIGQter::test04c_ChecklistFormats()
{
    DbManager db;
    const Asset asset = db.GetAssets().first();
    const auto stigs = asset.GetSTIGs();
    QVERIFY(!stigs.isEmpty());
    const auto checks = asset.GetCKLChecks(&stigs.first());
    QVERIFY(!checks.isEmpty());
    QBuffer ckl, cklb;
    QVERIFY(ckl.open(QIODevice::ReadWrite));
    QVERIFY(cklb.open(QIODevice::ReadWrite));
    const auto progress = [](int, const QString &) {};
    QVERIFY(WriteCkl(&ckl, asset, {stigs.first()}, progress));
    QXmlStreamReader xml(ckl.data());
    int vulnerabilities = 0;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isStartElement() && xml.name() == QStringLiteral("VULN")) ++vulnerabilities;
    }
    QVERIFY(!xml.hasError());
    QCOMPARE(vulnerabilities, checks.size());
    QVERIFY(WriteCklb(&cklb, asset, {stigs.first()}, progress));
    auto json = QJsonDocument::fromJson(cklb.data()).object();
    auto target = json.value(QStringLiteral("target_data")).toObject();
    QCOMPARE(target.value(QStringLiteral("marking")).toString(), asset.marking);
    const QString name = QStringLiteral("CKLB ROUNDTRIP FIXTURE");
    target[QStringLiteral("host_name")] = name;
    json[QStringLiteral("target_data")] = target;
    QTemporaryDir directory;
    // Exercise successful bulk writes, then nested writer failures in both
    // modes/formats. This also guards normalized paths on native Windows.
    for (bool binary : {false, true}) {
        for (bool monolithic : {false, true}) {
            const QString suffix = binary ? QStringLiteral(".cklb") : QStringLiteral(".ckl");
            QStringList paths;
            if (monolithic) {
                paths.append(directory.filePath(SanitizeFile(PrintAsset(asset)) + QStringLiteral("-monolithic") + suffix));
            } else {
                for (const auto &stig : stigs) {
                    const QString name = SanitizeFile(PrintAsset(asset) + "_" + stig.title + "_V" + QString::number(stig.version)
                        + "R" + QString::number(GetReleaseNumber(stig.release))) + suffix;
                    paths.append(directory.filePath(name));
                }
            }
            WorkerCKLExport exporter;
            exporter.SetAssetName(asset.hostName);
            exporter.SetExportDir(directory.path());
            exporter.SetCKLB(binary);
            exporter.SetMonolithic(monolithic);
            QSignalSpy failures(&exporter, &Worker::ThrowWarning);
            QSignalSpy finished(&exporter, &Worker::finished);
            QSignalSpy statuses(&exporter, &Worker::updateStatus);
            exporter.process();
            QVERIFY(failures.isEmpty());
            QCOMPARE(finished.size(), 1);
            QCOMPARE(statuses.last().first().toString(), QStringLiteral("Done!"));
            for (const auto &path : paths) {
                QVERIFY(QFileInfo(path).isFile());
                QVERIFY(QFileInfo(path).size() > 0);
                QVERIFY(QFile::remove(path));
                QVERIFY(QDir().mkpath(path));
            }
            finished.clear();
            statuses.clear();
            exporter.process();
            QCOMPARE(failures.size(), monolithic ? 1 : stigs.size());
            QCOMPARE(finished.size(), 1);
            QCOMPARE(statuses.last().first().toString(), QStringLiteral("Completed with warnings"));
        }
    }
    const QString path = directory.filePath(QStringLiteral("fixture.cklb"));
    QVERIFY(put(path, QJsonDocument(json).toJson()));
    WorkerCKLImport importer;
    QSignalSpy warnings(&importer, &Worker::ThrowWarning);
    importer.AddCKLs({path});
    importer.process();
    QVERIFY(warnings.isEmpty());
    const Asset imported = db.GetAsset(name);
    QVERIFY(imported.id > 0);
    const RemoveFixtureAsset cleanup{imported.id};
    QCOMPARE(imported.marking, asset.marking);
    QCOMPARE(imported.hostIP, asset.hostIP);
    QCOMPARE(imported.GetCKLChecks().size(), checks.size());
    for (const auto &check : checks) {
        const auto copy = db.GetCKLCheckByDISAId(imported.id, check.GetRule());
        QCOMPARE(copy.status, check.status);
        QCOMPARE(copy.comments, check.comments);
        QCOMPARE(copy.findingDetails, check.findingDetails);
        QCOMPARE(copy.severityOverride, check.severityOverride);
        QCOMPARE(copy.severityJustification, check.severityJustification);
    }
}

void TestSTIGQter::test04c_UpgradePreservation()
{
    DbManager db;
    STIG original, replacement;
    for (const auto &stig : db.GetSTIGs()) {
        if (stig.fileName == QStringLiteral("U_ASD_STIG_V5R1_Manual-xccdf.xml")) original = stig;
        if (stig.fileName == QStringLiteral("U_ASD_STIG_V5R2_Manual-xccdf.xml")) replacement = stig;
    }
    QVERIFY(original.id > 0 && replacement.id > 0);
    Asset asset;
    asset.hostName = QStringLiteral("UPGRADE PRESERVATION FIXTURE");
    asset.marking = QStringLiteral("CUI");
    QVERIFY(db.AddAsset(asset));
    const RemoveFixtureAsset cleanup{asset.id};
    QVERIFY(db.AddSTIGToAsset(original, asset));
    QSet<QString> available;
    for (const auto &check : db.GetSTIGChecks(replacement)) available.insert(check.vulnNum);
    STIGCheck source;
    for (const auto &check : db.GetSTIGChecks(original))
        if (available.contains(check.vulnNum)) { source = check; break; }
    QVERIFY(source.id > 0);
    auto before = db.GetCKLCheckByDISAId(asset.id, source.rule);
    before.status = Status::Open;
    before.comments = QStringLiteral("Upgrade comment fixture");
    before.findingDetails = QStringLiteral("Upgrade finding fixture");
    before.severityOverride = Severity::medium;
    before.severityJustification = QStringLiteral("Upgrade justification fixture");
    QVERIFY(db.UpdateCKLCheck(before));
    WorkerCKLUpgrade worker;
    QSignalSpy warnings(&worker, &Worker::ThrowWarning);
    worker.AddSTIG(asset, original);
    QElapsedTimer timer; timer.start();
    worker.process();
    qInfo("ASD upgrade fixture: %lld ms", static_cast<long long>(timer.elapsed()));
    QVERIFY(warnings.isEmpty());
    QVERIFY(asset.GetSTIGs().contains(replacement));
    bool found = false;
    for (const auto &check : asset.GetCKLChecks(&replacement)) {
        if (check.GetSTIGCheck().vulnNum != source.vulnNum) continue;
        QCOMPARE(check.status, before.status);
        QCOMPARE(check.comments, before.comments);
        QCOMPARE(check.findingDetails, before.findingDetails);
        QCOMPARE(check.severityOverride, before.severityOverride);
        QCOMPARE(check.severityJustification, before.severityJustification);
        found = true;
        break;
    }
    QVERIFY(found);
    QCOMPARE(db.GetAsset(asset.id).marking, asset.marking);
}
