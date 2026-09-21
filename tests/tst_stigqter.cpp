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

#include "tst_stigqter.h"

#include "assetview.h"
#include "common.h"
#include "dbmanager.h"
#include "stigqter.h"
#include "workerassetdelete.h"
#include "workercklimport.h"
#include "workerstigdelete.h"

#include <QDirIterator>
#include <QCheckBox>
#include <QComboBox>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <QtTest>

TestSTIGQter::TestSTIGQter(QObject *parent) : QObject(parent)
{
}

void TestSTIGQter::procEvents()
{
    while (!w->isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }
    QApplication::processEvents();
}

void TestSTIGQter::initTestCase()
{
    IgnoreWarnings = true;

    // Keep test data out of the user's normal application-data directory and
    // remove it before DbManager opens a connection. Constructing STIGQter
    // first starts CCI indexing immediately; truncating the live SQLite file
    // after that races the worker and intermittently leaves the database empty.
    QStandardPaths::setTestModeEnabled(true);
    const QString testDatabase = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                                 + QStringLiteral("/STIGQter.db");
    QVERIFY2(!QFile::exists(testDatabase) || QFile::remove(testDatabase),
             qPrintable(QStringLiteral("Unable to remove test database: ") + testDatabase));

    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("99"));
        db.UpdateVariable(QStringLiteral("indexSupplements"), QStringLiteral("y"));
    }

    w = new STIGQter();
    w->show();
    w->resize(800, 600);

    QApplication::processEvents();
    QCOMPARE(w->size(), QSize(800, 600));
    procEvents();
}

void TestSTIGQter::test00_Classification()
{
    //Normal-side classification verification is intentionally limited to
    //UNCLASSIFIED and CUI. Higher banner levels are reserved for high-side tests.
    QCOMPARE(GetClassification(QStringLiteral("")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("PUBLIC RELEASE")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("UNCLASSIFIED")), Classification::classUnclassified);
    QCOMPARE(GetClassification(QStringLiteral("CUI [Controlled by: ...]")), Classification::classCUI);
    QCOMPARE(GetClassification(QStringLiteral("CONTROLLED")), Classification::classCUI);
    QCOMPARE(GetClassification(QStringLiteral("N/A")), Classification::classPublicRelease);

    //a complete classification word is required: markings that merely start with
    //the same letter (or embed the word in another word) must not escalate
    QCOMPARE(GetClassification(QStringLiteral("Storage array")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Firewall")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Unit 5")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Secretary workstation")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Controller node")), Classification::classPublicRelease);

    //normal-side ordering used for the import mismatch comparison
    QVERIFY(Classification::classCUI > Classification::classUnclassified);

    //normal-side canonical labels
    QCOMPARE(GetClassificationString(Classification::classUnclassified), QStringLiteral("UNCLASSIFIED"));
    QCOMPARE(GetClassificationString(Classification::classCUI), QStringLiteral("CUI"));

    // All XCCDF severity spellings, including informational values.
    QCOMPARE(GetSeverity(QStringLiteral("high")), Severity::high);
    QCOMPARE(GetSeverity(QStringLiteral("medium")), Severity::medium);
    QCOMPARE(GetSeverity(QStringLiteral("low")), Severity::low);
    QCOMPARE(GetSeverity(QStringLiteral("info")), Severity::none);
    QCOMPARE(GetSeverity(QStringLiteral("informational")), Severity::none);
    QCOMPARE(GetSeverity(QStringLiteral("unknown")), Severity::none);
    QCOMPARE(GetSeverity(QStringLiteral("I")), Severity::high);
    QCOMPARE(GetSeverity(QStringLiteral("II")), Severity::medium);
    QCOMPARE(GetSeverity(QStringLiteral("III")), Severity::low);
    QCOMPARE(GetSeverity(QStringLiteral("IV")), Severity::none);

    // Release 10 must sort after release 9 and be offered as an upgrade.
    STIG release9;
    release9.title = QStringLiteral("Release comparison test");
    release9.version = 2;
    release9.release = QStringLiteral("Release: 9 Benchmark Date: 01 Jan 2026");
    STIG release10 = release9;
    release10.release = QStringLiteral("Release: 10 Benchmark Date: 01 Apr 2026");
    QVERIFY(release10.IsNewerThan(release9));
    QVERIFY(!release9.IsNewerThan(release10));
    QVERIFY(release9 < release10);
    QCOMPARE(GetReleaseNumber(QStringLiteral("R12")), 12);

}

void TestSTIGQter::test00_LocalFileDownload()
{
    const QByteArray payload = QByteArrayLiteral("local download fixture");
    QTemporaryFile source;
    QVERIFY(source.open());
    QCOMPARE(source.write(payload), payload.size());
    QVERIFY(source.flush());

    // DownloadFile owns the open/close cycle when given a closed destination.
    QTemporaryFile destination;
    QVERIFY(destination.open());
    const QString destinationPath = destination.fileName();
    destination.close();
    QVERIFY(DownloadFile(QUrl::fromLocalFile(source.fileName()), &destination));
    QVERIFY(!destination.isOpen());

    QFile downloaded(destinationPath);
    QVERIFY(downloaded.open(QIODevice::ReadOnly));
    QCOMPARE(downloaded.readAll(), payload);

    // A missing local source must fail and restore the destination's state.
    QTemporaryFile missingSource;
    QVERIFY(missingSource.open());
    const QString missingPath = missingSource.fileName();
    missingSource.close();
    QVERIFY(QFile::remove(missingPath));

    QTemporaryFile failedDestination;
    QVERIFY(failedDestination.open());
    failedDestination.close();
    QVERIFY(!DownloadFile(QUrl::fromLocalFile(missingPath), &failedDestination));
    QVERIFY(!failedDestination.isOpen());
}

void TestSTIGQter::test01_IndexCCIs()
{
    QMetaObject::invokeMethod(w, "UpdateCCIs", Qt::DirectConnection);
    procEvents();

    DbManager db;
    QVERIFY(db.GetCCIs().count() > 0);
}

void TestSTIGQter::test02_UpdateCCI()
{
    DbManager db;
    CCI cci = db.GetCCIByCCI(366);
    cci.definition.append(QStringLiteral(" (edited)"));
    db.UpdateCCI(cci);
    QApplication::processEvents();
}

void TestSTIGQter::test03_IndexSTIGs()
{
    QMetaObject::invokeMethod(w, "SupplementsChanged", Qt::DirectConnection, Q_ARG(int, Qt::Checked));
    procEvents();

    // Build a small quarterly archive from repository fixtures. The live DISA
    // archive is hundreds of megabytes and changes independently of the code,
    // making this regression suite slow and nondeterministic.
    const auto readFixture = [](const QString &path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
            return QByteArray();
        return file.readAll();
    };

    const QMap<QString, QByteArray> sourceVariantFiles = GetFilesFromZip(QStringLiteral("tests/U_ASD_V5R1_STIG.zip"));
    QString xccdfPath;
    for (const QString &path : sourceVariantFiles.keys())
    {
        if (path.endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive))
        {
            xccdfPath = path;
            break;
        }
    }
    QVERIFY(!xccdfPath.isEmpty());
    const QByteArray originalTitle = QByteArrayLiteral("<title>Application Security and Development Security Technical Implementation Guide</title>");
    QMap<QString, QByteArray> quarterlyFiles;
    quarterlyFiles.insert(QStringLiteral("U_ASD_V5R1_STIG.zip"),
                          readFixture(QStringLiteral("tests/U_ASD_V5R1_STIG.zip")));
    quarterlyFiles.insert(QStringLiteral("U_ASD_V5R2_STIG.zip"),
                          readFixture(QStringLiteral("tests/U_ASD_V5R2_STIG.zip")));

    // The assessment-field test needs three attached guides while the V5R2
    // fixture must remain unattached for the upgrade test. Add two distinct,
    // lightweight variants of V5R1 to satisfy both conditions.
    for (int variant = 1; variant <= 2; ++variant)
    {
        QByteArray variantXccdf = sourceVariantFiles.value(xccdfPath);
        QVERIFY(variantXccdf.contains(originalTitle));
        variantXccdf.replace(
            originalTitle,
            QStringLiteral("<title>Application Security and Development Test Variant %1</title>")
                .arg(variant).toUtf8());

        QMap<QString, QByteArray> variantFiles;
        variantFiles.insert(QStringLiteral("U_ASD_TEST_%1_Manual-xccdf.xml").arg(variant),
                            variantXccdf);

        QTemporaryFile variantArchive;
        QVERIFY(variantArchive.open());
        const QString variantArchivePath = variantArchive.fileName();
        variantArchive.close();
        QVERIFY(CreateZip(variantArchivePath, variantFiles));

        const QByteArray variantContents = readFixture(variantArchivePath);
        QVERIFY(!variantContents.isEmpty());
        quarterlyFiles.insert(QStringLiteral("U_ASD_TEST_%1_STIG.zip").arg(variant),
                              variantContents);
    }
    for (const QByteArray &contents : quarterlyFiles)
        QVERIFY(!contents.isEmpty());

    QTemporaryFile quarterlyArchive;
    QVERIFY(quarterlyArchive.open());
    const QString quarterlyArchivePath = quarterlyArchive.fileName();
    quarterlyArchive.close();
    QVERIFY(CreateZip(quarterlyArchivePath, quarterlyFiles));

    {
        DbManager db;
        QVERIFY(db.UpdateVariable(QStringLiteral("quarterly"),
                                  QUrl::fromLocalFile(quarterlyArchivePath).toString()));
    }

    QMetaObject::invokeMethod(w, "DownloadSTIGs", Qt::DirectConnection);
    procEvents();

    DbManager db;
    QCOMPARE(db.GetSTIGs().count(), 4);
}

// STIGQter::RunTests() is split into five phases so that each gets its own
// Qt Test per-function watchdog budget (default 300 s). Running the whole
// sequence as a single test function under the SonarCloud coverage build
// (-O0 with gcov instrumentation) exceeded that budget and aborted.
void TestSTIGQter::test04a_RunInterface()
{
    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("0"));
    }

    w->RunTests1();
    procEvents();
    QVERIFY(w->isProcessingEnabled());

    //RunTests1 sets the system classification marking via the Main-tab field
    {
        DbManager db;
        QCOMPARE(db.GetVariable(QStringLiteral("systemMarking")), QStringLiteral("CUI"));
    }
}

void TestSTIGQter::test04b_RunInterface()
{
    w->RunTests2();
    procEvents();
    QVERIFY(w->isProcessingEnabled());

    //STIGEdit::RunTests() exports a STIG via WorkerSTIGExport; confirm the
    //archive was written and is a well-formed, re-importable XCCDF benchmark.
    QVERIFY(QFile::exists(QStringLiteral("tests/exported_stig.zip")));
    QMap<QString, QByteArray> exported = GetFilesFromZip(QStringLiteral("tests/exported_stig.zip"));
    bool foundXccdf = false;
    for (auto i = exported.constBegin(); i != exported.constEnd(); ++i)
    {
        if (i.key().endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive) ||
            i.key().endsWith(QStringLiteral("Manual_STIG.xml"), Qt::CaseInsensitive) ||
            i.key().endsWith(QStringLiteral("Manual_xccdf.xml"), Qt::CaseInsensitive))
        {
            foundXccdf = true;
            const QByteArray &xml = i.value();
            QVERIFY(xml.contains("<Benchmark"));
            QVERIFY(xml.contains("<Rule"));
        }
    }
    QVERIFY(foundXccdf);
}

void TestSTIGQter::test04c_RunInterface()
{
    w->RunTests3();
    procEvents();
    QVERIFY(w->isProcessingEnabled());

    DbManager db;
    QCOMPARE(db.GetVariable(QStringLiteral("version")), QStringLiteral("10"));
    QVERIFY(!db.GetSTIGs().isEmpty());
    QVERIFY(!db.GetAssets().isEmpty());
    QVERIFY(!db.GetCKLChecks().isEmpty());
}

void TestSTIGQter::test04c_ProjectLoadSafety()
{
    DbManager db;
    const int stigCount = db.GetSTIGs().count();
    const int assetCount = db.GetAssets().count();
    const QVector<CKLCheck> checks = db.GetCKLChecks();
    QVERIFY(!checks.isEmpty());
    const CKLCheck protectedCheck = checks.first();
    const QString databaseVersion = db.GetVariable(QStringLiteral("version"));
    const QString systemMarking = db.GetVariable(QStringLiteral("systemMarking"));

    const auto verifyProjectContent = [&db, stigCount, assetCount, checks,
                                       protectedCheck, databaseVersion, systemMarking]() {
        QCOMPARE(db.GetSTIGs().count(), stigCount);
        QCOMPARE(db.GetAssets().count(), assetCount);
        QCOMPARE(db.GetCKLChecks().count(), checks.count());
        QCOMPARE(db.GetVariable(QStringLiteral("version")), databaseVersion);
        QCOMPARE(db.GetVariable(QStringLiteral("systemMarking")), systemMarking);
        const CKLCheck reloadedCheck = db.GetCKLCheck(protectedCheck);
        QCOMPARE(reloadedCheck.status, protectedCheck.status);
        QCOMPARE(reloadedCheck.comments, protectedCheck.comments);
        QCOMPARE(reloadedCheck.findingDetails, protectedCheck.findingDetails);
    };

    QTemporaryFile invalidDatabase;
    QVERIFY(invalidDatabase.open());
    const QByteArray invalidData = qCompress(QByteArrayLiteral("not a SQLite database"));
    QCOMPARE(invalidDatabase.write(invalidData), invalidData.size());
    invalidDatabase.flush();
    QVERIFY(!db.LoadDB(invalidDatabase.fileName()));
    verifyProjectContent();

    QTemporaryFile truncatedFile;
    QVERIFY(truncatedFile.open());
    QCOMPARE(truncatedFile.write(QByteArrayLiteral("bad")), 3);
    truncatedFile.flush();
    QVERIFY(!db.LoadDB(truncatedFile.fileName()));
    verifyProjectContent();
}

void TestSTIGQter::test04c_ChecklistAutosave()
{
    QListWidget *assets = w->findChild<QListWidget*>(QStringLiteral("lstAssets"));
    QVERIFY(assets);
    QVERIFY(assets->count() > 0);
    assets->setCurrentRow(0, QItemSelectionModel::ClearAndSelect);
    QMetaObject::invokeMethod(w, "OpenCKL", Qt::DirectConnection);
    QApplication::processEvents();

    AssetView *assetView = w->findChild<AssetView*>();
    QVERIFY(assetView);
    QListWidget *checks = assetView->findChild<QListWidget*>(QStringLiteral("lstChecks"));
    QPlainTextEdit *comments = assetView->findChild<QPlainTextEdit*>(QStringLiteral("txtComments"));
    QVERIFY(checks);
    QVERIFY(comments);
    QVERIFY(checks->count() > 1);

    checks->setCurrentRow(0, QItemSelectionModel::ClearAndSelect);
    QApplication::processEvents();
    const CKLCheck first = checks->item(0)->data(Qt::UserRole).value<CKLCheck>();
    const CKLCheck second = checks->item(1)->data(Qt::UserRole).value<CKLCheck>();
    const QString marker = QStringLiteral("Rapid-selection autosave regression");

    comments->setPlainText(marker);
    checks->setCurrentRow(1, QItemSelectionModel::ClearAndSelect);

    QTRY_COMPARE_WITH_TIMEOUT(DbManager().GetCKLCheck(first).comments, marker, 2000);
    QVERIFY(DbManager().GetCKLCheck(second).comments != marker);
}

void TestSTIGQter::test04c_AssessmentFieldsAndOptions()
{
    DbManager db;
    const QVector<Asset> assets = db.GetAssets();
    QVERIFY(!assets.isEmpty());
    const Asset asset = assets.first();

    // Attach enough distinct guides to audit varied rule content. Keep the
    // bundled ASD V5R2 guide unattached for the later upgrade workflow.
    QVector<STIG> attachedSTIGs = asset.GetSTIGs();
    for (const STIG &stig : db.GetSTIGs())
    {
        if (attachedSTIGs.count() >= 3)
            break;
        if (attachedSTIGs.contains(stig) || stig.GetSTIGChecks().isEmpty() ||
            stig.fileName == QStringLiteral("U_ASD_STIG_V5R2_Manual-xccdf.xml"))
        {
            continue;
        }
        QVERIFY(db.AddSTIGToAsset(stig, asset));
        attachedSTIGs.append(stig);
    }
    QVERIFY2(attachedSTIGs.count() >= 3, "The quarterly library must provide at least three testable STIGs");

    AssetView *assetView = w->findChild<AssetView*>();
    if (!assetView)
    {
        auto *assetList = w->findChild<QListWidget*>(QStringLiteral("lstAssets"));
        QVERIFY(assetList);
        QVERIFY(assetList->count() > 0);
        assetList->setCurrentRow(0, QItemSelectionModel::ClearAndSelect);
        QMetaObject::invokeMethod(w, "OpenCKL", Qt::DirectConnection);
        QApplication::processEvents();
        assetView = w->findChild<AssetView*>();
    }
    QVERIFY(assetView);
    assetView->SelectSTIGs();
    assetView->ShowChecks();

    auto *checks = assetView->findChild<QListWidget*>(QStringLiteral("lstChecks"));
    auto *stigs = assetView->findChild<QListWidget*>(QStringLiteral("lstSTIGs"));
    auto *stigFilter = assetView->findChild<QLineEdit*>(QStringLiteral("txtSTIGFilter"));
    auto *checkFilter = assetView->findChild<QLineEdit*>(QStringLiteral("txtCheckSearch"));
    auto *status = assetView->findChild<QComboBox*>(QStringLiteral("cboBoxStatus"));
    auto *severity = assetView->findChild<QComboBox*>(QStringLiteral("cboBoxSeverity"));
    auto *statusFilter = assetView->findChild<QComboBox*>(QStringLiteral("cboBoxFilterStatus"));
    auto *severityFilter = assetView->findChild<QComboBox*>(QStringLiteral("cboBoxFilterSeverity"));
    auto *findingDetails = assetView->findChild<QPlainTextEdit*>(QStringLiteral("txtFindingDetails"));
    auto *comments = assetView->findChild<QPlainTextEdit*>(QStringLiteral("txtComments"));
    auto *checkRule = assetView->findChild<QLabel*>(QStringLiteral("lblCheckRule"));
    auto *checkTitle = assetView->findChild<QLabel*>(QStringLiteral("lblCheckTitle"));
    auto *documentable = assetView->findChild<QCheckBox*>(QStringLiteral("cbDocumentable"));
    auto *discussion = assetView->findChild<QTextEdit*>(QStringLiteral("lblDiscussion"));
    auto *falsePositives = assetView->findChild<QTextEdit*>(QStringLiteral("lblFalsePositives"));
    auto *falseNegatives = assetView->findChild<QTextEdit*>(QStringLiteral("lblFalseNegatives"));
    auto *fix = assetView->findChild<QTextEdit*>(QStringLiteral("lblFix"));
    auto *checkText = assetView->findChild<QTextEdit*>(QStringLiteral("lblCheck"));
    auto *additionalDetails = assetView->findChild<QTextEdit*>(QStringLiteral("lblAdditionalDetails"));
    auto *ip = assetView->findChild<QLineEdit*>(QStringLiteral("txtIP"));
    auto *mac = assetView->findChild<QLineEdit*>(QStringLiteral("txtMAC"));
    auto *fqdn = assetView->findChild<QLineEdit*>(QStringLiteral("txtFQDN"));
    auto *marking = assetView->findChild<QLineEdit*>(QStringLiteral("txtMarking"));
    auto *notReviewedCount = assetView->findChild<QLabel*>(QStringLiteral("lblNotReviewed"));
    auto *notApplicableCount = assetView->findChild<QLabel*>(QStringLiteral("lblNotApplicable"));
    auto *reviewedProgress = assetView->findChild<QLabel*>(QStringLiteral("lblReviewed"));
    auto *filteredCount = assetView->findChild<QLabel*>(QStringLiteral("lblFilteredChecks"));
    auto *saveState = assetView->findChild<QLabel*>(QStringLiteral("lblSaveState"));
    auto *nextNotReviewed = assetView->findChild<QPushButton*>(QStringLiteral("btnNextNotReviewed"));
    QVERIFY(checks && stigs && stigFilter && checkFilter && status && severity && statusFilter && severityFilter);
    QVERIFY(findingDetails && comments && checkRule && checkTitle && documentable);
    QVERIFY(discussion && falsePositives && falseNegatives && fix && checkText && additionalDetails);
    QVERIFY(ip && mac && fqdn && marking);
    QVERIFY(notReviewedCount && notApplicableCount && reviewedProgress && filteredCount && saveState && nextNotReviewed);
    QVERIFY(checks->count() > 2);

    // Walk representative rules from three different STIGs and verify every
    // imported field presented on the assessment tab.
    for (int stigIndex = 0; stigIndex < 3; ++stigIndex)
    {
        const STIG stig = attachedSTIGs.at(stigIndex);
        const QVector<CKLCheck> stigChecks = db.GetCKLChecks(asset, &stig);
        QVERIFY2(!stigChecks.isEmpty(), qPrintable(stig.title));
        const CKLCheck ckl = stigChecks.first();
        const STIGCheck rule = ckl.GetSTIGCheck();
        assetView->UpdateCKLCheck(ckl);

        QVERIFY(checkRule->text().contains(rule.rule));
        QCOMPARE(checkTitle->text(), rule.title);
        QCOMPARE(documentable->isChecked(), rule.documentable);
        QCOMPARE(discussion->toPlainText(), rule.vulnDiscussion);
        QCOMPARE(falsePositives->toPlainText(), rule.falsePositives);
        QCOMPARE(falseNegatives->toPlainText(), rule.falseNegatives);
        QCOMPARE(fix->toPlainText(), rule.fix);
        QCOMPARE(checkText->toPlainText(), rule.check);
        const QString extra = additionalDetails->toPlainText();
        QVERIFY(extra.contains(QStringLiteral("Vulnerability ID: ")));
        QVERIFY(extra.contains(rule.vulnNum));
        QVERIFY(extra.contains(QStringLiteral("Severity override guidance: ")));
        QVERIFY(extra.contains(QStringLiteral("Potential impact: ")));
        QVERIFY(extra.contains(QStringLiteral("Responsibility: ")));
    }

    // Short queries should filter immediately; the previous three-character
    // threshold made one- and two-character searches appear broken.
    const QString shortQuery = attachedSTIGs.first().title.left(1);
    stigFilter->setText(shortQuery);
    QApplication::processEvents();
    QVERIFY(stigs->count() > 0);
    for (int row = 0; row < stigs->count(); ++row)
        QVERIFY(stigs->item(row)->text().contains(shortQuery, Qt::CaseInsensitive));
    stigFilter->clear();
    QApplication::processEvents();
    QCOMPARE(stigs->count(), db.GetSTIGs().count());

    // Check search covers cached rule, vulnerability, title, and STIG fields,
    // and list rows expose status/severity in text rather than color alone.
    const QVector<CKLCheck> searchableChecks = db.GetCKLChecks(asset);
    QVERIFY(!searchableChecks.isEmpty());
    const CKLCheck searchTarget = searchableChecks.first();
    const QString checkQuery = searchTarget.GetVulnerabilityId();
    QVERIFY(!checkQuery.isEmpty());
    checkFilter->setText(checkQuery);
    QApplication::processEvents();
    QVERIFY(checks->count() > 0);
    for (int row = 0; row < checks->count(); ++row)
    {
        const CKLCheck displayed = checks->item(row)->data(Qt::UserRole).value<CKLCheck>();
        const QString searchable = QStringList({displayed.GetRule(), displayed.GetVulnerabilityId(),
                                                displayed.GetTitle(), displayed.GetSTIGTitle()}).join(QLatin1Char('\n'));
        QVERIFY(searchable.contains(checkQuery, Qt::CaseInsensitive));
        QVERIFY(checks->item(row)->text().contains(GetStatus(displayed.status)));
        QVERIFY(checks->item(row)->text().contains(GetSeverity(displayed.GetSeverity())));
    }
    checkFilter->clear();
    QApplication::processEvents();
    QCOMPARE(checks->count(), searchableChecks.count());

    int expectedNotReviewed = 0;
    int expectedNotApplicable = 0;
    for (const CKLCheck &check : searchableChecks)
    {
        expectedNotReviewed += check.status == Status::NotReviewed ? 1 : 0;
        expectedNotApplicable += check.status == Status::NotApplicable ? 1 : 0;
    }
    QCOMPARE(notReviewedCount->text().toInt(), expectedNotReviewed);
    QCOMPARE(notApplicableCount->text().toInt(), expectedNotApplicable);
    QVERIFY(reviewedProgress->text().contains(QLatin1Char('%')));
    QVERIFY(filteredCount->text().contains(QString::number(searchableChecks.count())));
    if (expectedNotReviewed > 0)
    {
        nextNotReviewed->click();
        QApplication::processEvents();
        QVERIFY(checks->currentItem());
        QCOMPARE(checks->currentItem()->data(Qt::UserRole).value<CKLCheck>().status, Status::NotReviewed);
    }

    // Select a single check and exercise all four status options plus both
    // free-text fields through the real debounce/persistence path.
    checks->setCurrentRow(0, QItemSelectionModel::ClearAndSelect);
    QApplication::processEvents();
    CKLCheck selected = checks->currentItem()->data(Qt::UserRole).value<CKLCheck>();
    const QVector<Status> statuses = {
        Status::NotReviewed, Status::Open, Status::NotAFinding, Status::NotApplicable
    };
    for (int index = 0; index < status->count(); ++index)
    {
        status->setCurrentIndex(index);
        assetView->FlushPendingChanges();
        QCOMPARE(db.GetCKLCheck(selected).status, statuses.at(index));
    }

    const QString findingMarker = QStringLiteral("Observed <condition> & evidence\nSecond line");
    const QString commentMarker = QStringLiteral("Reviewer comment\nValidated manually");
    findingDetails->setPlainText(findingMarker);
    comments->setPlainText(commentMarker);
    assetView->FlushPendingChanges();
    selected = db.GetCKLCheck(selected);
    QCOMPARE(selected.findingDetails, findingMarker);
    QCOMPARE(selected.comments, commentMarker);
    QCOMPARE(saveState->text(), QStringLiteral("All changes saved"));

    // All severity choices: baseline, two valid overrides, informational/CAT
    // IV removal, and cancellation while an existing override is active.
    const Severity baselineSeverity = selected.GetSTIGCheck().severity;
    QVERIFY(baselineSeverity != Severity::none);
    selected.severityOverride = Severity::none;
    selected.severityJustification.clear();
    QVERIFY(db.UpdateCKLCheck(selected));
    assetView->ShowChecks();
    for (int row = 0; row < checks->count(); ++row)
    {
        if (checks->item(row)->data(Qt::UserRole).value<CKLCheck>().id == selected.id)
        {
            checks->setCurrentRow(row, QItemSelectionModel::ClearAndSelect);
            break;
        }
    }
    QCOMPARE(GetSeverity(severity->currentText()), baselineSeverity);

    const auto respondToInputDialog = [](const QString &text, bool accept) {
        auto *timer = new QTimer(qApp);
        timer->setInterval(10);
        QObject::connect(timer, &QTimer::timeout, qApp, [timer, text, accept]() {
            for (QWidget *widget : QApplication::topLevelWidgets())
            {
                auto *dialog = qobject_cast<QInputDialog*>(widget);
                if (!dialog || !dialog->isVisible())
                    continue;
                if (accept)
                {
                    dialog->setTextValue(text);
                    dialog->accept();
                }
                else
                {
                    dialog->reject();
                }
                timer->stop();
                timer->deleteLater();
                return;
            }
        });
        timer->start();
    };
    const auto dismissMessageBox = []() {
        auto *timer = new QTimer(qApp);
        timer->setInterval(10);
        QObject::connect(timer, &QTimer::timeout, qApp, [timer]() {
            for (QWidget *widget : QApplication::topLevelWidgets())
            {
                auto *dialog = qobject_cast<QMessageBox*>(widget);
                if (!dialog || !dialog->isVisible())
                    continue;
                dialog->accept();
                timer->stop();
                timer->deleteLater();
                return;
            }
        });
        timer->start();
    };

    QVector<Severity> overrideSeverities = {Severity::high, Severity::medium, Severity::low};
    overrideSeverities.removeAll(baselineSeverity);
    for (const Severity overrideSeverity : overrideSeverities)
    {
        const QString justification = QStringLiteral("QA override to ") + GetSeverity(overrideSeverity);
        respondToInputDialog(justification, true);
        severity->setCurrentText(GetSeverity(overrideSeverity));
        assetView->FlushPendingChanges();
        selected = db.GetCKLCheck(selected);
        QCOMPARE(selected.severityOverride, overrideSeverity);
        QCOMPARE(selected.severityJustification, justification);
    }

    const Severity retainedOverride = selected.severityOverride;
    const QString retainedJustification = selected.severityJustification;
    const Severity cancelledSeverity = overrideSeverities.first() == retainedOverride
        ? overrideSeverities.last() : overrideSeverities.first();
    respondToInputDialog(QString(), false);
    severity->setCurrentText(GetSeverity(cancelledSeverity));
    QCOMPARE(GetSeverity(severity->currentText()), retainedOverride);
    selected = db.GetCKLCheck(selected);
    QCOMPARE(selected.severityOverride, retainedOverride);
    QCOMPARE(selected.severityJustification, retainedJustification);

    severity->setCurrentText(GetSeverity(baselineSeverity));
    assetView->FlushPendingChanges();
    selected = db.GetCKLCheck(selected);
    QCOMPARE(selected.severityOverride, Severity::none);
    QVERIFY(selected.severityJustification.isEmpty());

    dismissMessageBox();
    severity->setCurrentText(GetSeverity(Severity::none));
    assetView->FlushPendingChanges();
    selected = db.GetCKLCheck(selected);
    QCOMPARE(selected.severityOverride, Severity::none);
    QCOMPARE(GetSeverity(severity->currentText()), baselineSeverity);

    // Multi-selection status updates must affect every selected rule while
    // keeping fields that cannot be safely bulk-edited disabled.
    checks->setCurrentRow(0, QItemSelectionModel::ClearAndSelect);
    checks->item(1)->setSelected(true);
    QApplication::processEvents();
    QVERIFY(!comments->isEnabled());
    QVERIFY(!findingDetails->isEnabled());
    const CKLCheck bulkFirst = checks->item(0)->data(Qt::UserRole).value<CKLCheck>();
    const CKLCheck bulkSecond = checks->item(1)->data(Qt::UserRole).value<CKLCheck>();
    status->setCurrentText(GetStatus(Status::Open));
    assetView->FlushPendingChanges();
    QCOMPARE(db.GetCKLCheck(bulkFirst).status, Status::Open);
    QCOMPARE(db.GetCKLCheck(bulkSecond).status, Status::Open);

    // Exercise every filter option and a combined case, comparing each result
    // to the database's effective status and severity for this asset.
    struct FilterValue
    {
        Status status;
        Severity severity;
    };
    QVector<FilterValue> filterValues;
    const QVector<CKLCheck> allChecks = db.GetCKLChecks(asset);
    filterValues.reserve(allChecks.count());
    for (const CKLCheck &check : allChecks)
        filterValues.append({check.status, check.GetSeverity()});
    const auto verifyFilters = [&]()
    {
        QApplication::processEvents();
        int expected = 0;
        for (const FilterValue &check : filterValues)
        {
            const bool statusMatches = statusFilter->currentIndex() == 0 ||
                check.status == GetStatus(statusFilter->currentText());
            const bool severityMatches = severityFilter->currentIndex() == 0 ||
                check.severity == GetSeverity(severityFilter->currentText());
            if (statusMatches && severityMatches)
                ++expected;
        }
        QCOMPARE(checks->count(), expected);
    };
    severityFilter->setCurrentIndex(0);
    for (int statusIndex = 0; statusIndex < statusFilter->count(); ++statusIndex)
    {
        statusFilter->setCurrentIndex(statusIndex);
        verifyFilters();
    }
    statusFilter->setCurrentIndex(0);
    for (int severityIndex = 0; severityIndex < severityFilter->count(); ++severityIndex)
    {
        severityFilter->setCurrentIndex(severityIndex);
        verifyFilters();
    }
    statusFilter->setCurrentIndex(statusFilter->findData(static_cast<int>(Status::Open)));
    severityFilter->setCurrentIndex(severityFilter->findData(static_cast<int>(Severity::high)));
    verifyFilters();
    statusFilter->setCurrentIndex(0);
    severityFilter->setCurrentIndex(0);

    // Asset identity/marking fields use the same debounced save path.
    ip->setText(QStringLiteral("192.0.2.25"));
    mac->setText(QStringLiteral("02:00:00:00:00:25"));
    fqdn->setText(QStringLiteral("qa.example.test"));
    marking->setText(QStringLiteral("CUI"));
    assetView->FlushPendingChanges();
    const Asset savedAsset = db.GetAsset(asset);
    QCOMPARE(savedAsset.hostIP, ip->text());
    QCOMPARE(savedAsset.hostMAC, mac->text());
    QCOMPARE(savedAsset.hostFQDN, fqdn->text());
    QCOMPARE(savedAsset.marking, marking->text());
}

void TestSTIGQter::test04d_RunInterface()
{
    w->RunTests4();
    procEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04e_RunInterface()
{
    w->RunTests5();
    procEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04f_Escalation()
{
    DbManager db;
    QVector<Asset> assets = db.GetAssets();
    QVERIFY(!assets.isEmpty());

    auto *topBanner = w->findChild<QLabel*>(QStringLiteral("lblClassificationTop"));
    auto *bottomBanner = w->findChild<QLabel*>(QStringLiteral("lblClassificationBottom"));
    QVERIFY(topBanner && bottomBanner);

    //Normal-side banner verification covers UNCLASSIFIED and CUI only.
    db.UpdateVariable(QStringLiteral("systemMarking"), QStringLiteral("UNCLASSIFIED"));
    for (Asset asset : assets)
    {
        asset.marking = QStringLiteral("UNCLASSIFIED");
        db.UpdateAsset(asset);
    }
    w->RefreshClassificationBanner();
    procEvents();
    QCOMPARE(topBanner->text(), QStringLiteral("UNCLASSIFIED"));
    QCOMPARE(bottomBanner->text(), QStringLiteral("UNCLASSIFIED"));

    Asset a = assets.first();
    a.marking = QStringLiteral("CUI");
    db.UpdateAsset(a);

    //the system marking auto-escalates to the highest asset marking
    w->RefreshClassificationBanner();
    procEvents();
    QCOMPARE(GetClassification(db.GetVariable(QStringLiteral("systemMarking"))), Classification::classCUI);
    QCOMPARE(topBanner->text(), QStringLiteral("CUI"));
    QCOMPARE(bottomBanner->text(), QStringLiteral("CUI"));
}

void TestSTIGQter::test05_DeleteAndHash()
{
    {
        WorkerAssetDelete wd;
        DbManager db;
        QVector<Asset> toDelete = db.GetAssets();
        wd.AddAssets(toDelete);
        for (auto asset : toDelete)
        {
            for (auto stig : asset.GetSTIGs())
            {
                WorkerSTIGDelete wsd;
                wsd.AddId(stig.id);
                wsd.process();
                QApplication::processEvents();
            }
            wd.AddAsset(asset);
        }
        wd.process();
        QApplication::processEvents();
    }

    {
        DbManager db;
        auto hashInfo = db.HashDB();
        QVERIFY(!hashInfo.isNull() && !hashInfo.isEmpty());
        QApplication::processEvents();
    }

    {
        WorkerSTIGDelete wd;
        DbManager db;
        for (auto stig : db.GetSTIGs())
        {
            wd.AddId(stig.id);
        }
        wd.process();
        QApplication::processEvents();
    }
}

void TestSTIGQter::test06_CKLImport()
{
    QDirIterator it(QStringLiteral("tests"));
    WorkerCKLImport wc;
    while (it.hasNext())
    {
        QFile f(it.next());
        if (f.fileName().endsWith(QStringLiteral(".ckl"), Qt::CaseInsensitive))
        {
            if (f.fileName().endsWith(QStringLiteral("monolithic.ckl"), Qt::CaseInsensitive))
                continue;
            QFileInfo fi(f);
            wc.AddCKLs({fi.filePath()});
        }
    }
    wc.process();
    QApplication::processEvents();
}

void TestSTIGQter::test07_Cleanup()
{
    QMetaObject::invokeMethod(w, "DeleteEmass", Qt::DirectConnection);
    procEvents();

    QMetaObject::invokeMethod(w, "DeleteCCIs", Qt::DirectConnection);
    procEvents();

    QMetaObject::invokeMethod(w, "DeleteAssets", Qt::DirectConnection);
    procEvents();

    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::cleanupTestCase()
{
    w->close();
    delete w;
    w = nullptr;
}

QTEST_MAIN(TestSTIGQter)
