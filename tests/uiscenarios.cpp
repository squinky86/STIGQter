// SPDX-License-Identifier: GPL-3.0-or-later
#include "uiscenarios.h"
#include "common.h"
#include "stigqter.h"
#include "assetview.h"
#include "stigedit.h"
#include "workerstigadd.h"
#include "ui_stigqter.h"
#include "ui_assetview.h"
#include "ui_stigedit.h"
#include <QTest>
#include <QApplication>

int UiScenarios::step = 0;
bool UiScenarios::wait(STIGQter *window)
{
    const bool ready = QTest::qWaitFor([window] { return window->isProcessingEnabled(); }, 120000);
    QApplication::processEvents();
    return ready;
}
void UiScenarios::runTab(TabViewWidget *tab, STIGQter *window)
{
    if (auto *asset = qobject_cast<AssetView*>(tab)) runAssetView(asset, window);
    else if (auto *stig = qobject_cast<STIGEdit*>(tab)) runSTIGEdit(stig, window);
}

void UiScenarios::phase1(STIGQter *window)
{
    auto *ui = window->ui;
    step = 0;

    // Phase 1: refresh STIG catalog before performing mutation tests.
    qDebug("STIGQter test %d: Refresh STIGs", step++);
    window->UpdateSTIGs();
    QVERIFY2(wait(window), "Background operation timed out");

    // Phase 2: deterministically keep the first 5 STIGs and delete the remainder.
    qDebug("STIGQter test %d: Deleting Some STIGs", step++);
    {
        int size = ui->lstSTIGs->count();
        if (size > 5)
        {
            ui->lstSTIGs->selectAll();
            QVERIFY2(wait(window), "Background operation timed out");
            auto stigs = ui->lstSTIGs->selectedItems();
            for (int i = 0; i < 5; i++)
            {
                stigs.at(i)->setSelected(false);
            }
            QVERIFY2(wait(window), "Background operation timed out");
            window->DeleteSTIGs();
            QVERIFY2(wait(window), "Background operation timed out");
        }
    }

    qDebug("STIGQter test %d: Old ASD STIG", step++);
    {
        WorkerSTIGAdd s;
        s.AddSTIGs({QStringLiteral("tests/U_ASD_V5R1_STIG.zip"), QStringLiteral("tests/U_ASD_V5R2_STIG.zip")});
        s.SetEnableSupplements(false);
        s.process();
    }

    qDebug("STIGQter test %d: Filter", step++);
    ui->txtSTIGSearch->setText(QStringLiteral("Windows"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Clear Filter", step++);
    ui->txtSTIGSearch->setText(QString());
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: System Classification Marking", step++);
    ui->txtSystemMarking->setText(QStringLiteral("CUI"));
    window->SaveMarking();
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Message Handling", step++);
    QMessageLogContext c("test.cpp", 1, "TestFunc", "TestCat");
    MessageHandler(QtMsgType::QtDebugMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtInfoMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtWarningMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtCriticalMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtFatalMsg, c, QStringLiteral("Test Message"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Import eMASS Results", step++);
    window->ImportEMASS(QStringLiteral("tests/emassTRImport.xlsx"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Remapping Unmapped to CM-6", step++);
    ui->cbRemapCM6->setChecked(true);
    QVERIFY2(wait(window), "Background operation timed out");
    window->MapUnmapped(true);
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Creating Asset \"TEST\"", step++);
    ui->lstSTIGs->clearSelection();
    for (int j = 0; j < ui->lstSTIGs->count(); j++)
    {
        auto *li = ui->lstSTIGs->item(j);
        if (li->data(Qt::UserRole).value<STIG>().fileName.compare(QStringLiteral("U_ASD_STIG_V5R1_Manual-xccdf.xml")) == 0)
        {
            li->setSelected(true);
        }
    }
    window->AddAsset(QStringLiteral("TEST"));
    QVERIFY2(wait(window), "Background operation timed out");
}

void UiScenarios::phase2(STIGQter *window)
{
    auto *ui = window->ui;
    qDebug("STIGQter test %d: Opening STIGs", step++);
    window->EditSTIG();
    QVERIFY2(wait(window), "Background operation timed out");

    for (int j = 1; j < ui->tabDB->count(); j++)
    {
        auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(j));

        if (tmpTabView)
            tmpTabView->SetTabIndex(j);

        QVERIFY2(wait(window), "Background operation timed out");

        qDebug("STIGQter test %d: Running STIG Editing", step++);
        if (tmpTabView)
        {
            runTab(tmpTabView, window);
        }
        QVERIFY2(wait(window), "Background operation timed out");
    }
}

void UiScenarios::phase3(STIGQter *window)
{
    auto *ui = window->ui;
    DbManager db;

    qDebug("STIGQter test %d: Severity Override", step++);
    {
        int checkIndex = 0;
        const QVector<Status> statuses = {
            Status::Open, Status::NotAFinding, Status::NotReviewed, Status::NotApplicable
        };
        const QVector<Severity> severities = {
            Severity::high, Severity::medium, Severity::low
        };
        for (auto cklCheck : db.GetCKLChecks())
        {
            cklCheck.status = statuses.at(checkIndex % statuses.count());
            if (checkIndex % 4 == 0)
            {
                cklCheck.severityOverride = Severity::none;
                cklCheck.severityJustification.clear();
            }
            else
            {
                Severity overrideSeverity = severities.at(checkIndex % severities.count());
                if (overrideSeverity == cklCheck.GetSTIGCheck().severity)
                    overrideSeverity = severities.at((checkIndex + 1) % severities.count());
                cklCheck.severityOverride = overrideSeverity;
                cklCheck.severityJustification = QStringLiteral("Deterministic test override to %1.")
                                                     .arg(GetSeverity(overrideSeverity));
            }
            db.UpdateCKLCheck(cklCheck);
            ++checkIndex;
        }
        QVERIFY2(wait(window), "Background operation timed out");
    }

    qDebug("STIGQter test %d: Selecting Asset \"TEST\"", step++);
    ui->lstAssets->selectAll();
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Exporting CKL files", step++);
    window->ExportCKLs(QStringLiteral("tests"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Exporting Monolithic CKL files", step++);
    window->ExportCKLsMonolithic(QStringLiteral("tests"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Saving .stigqter file", step++);
    window->SaveAs(QStringLiteral("tests/test.stigqter"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Loading .stigqter file", step++);
    window->Load(QStringLiteral("tests/test.stigqter"));
    QVERIFY2(wait(window), "Background operation timed out");
}

void UiScenarios::phase4(STIGQter *window)
{
    auto *ui = window->ui;
    qDebug("STIGQter test %d: Opening Assets", step++);
    {
        ui->lstAssets->clearSelection();
        QVERIFY2(wait(window), "Background operation timed out");
        ui->lstAssets->selectAll();
        QVERIFY2(wait(window), "Background operation timed out");

        for (int i = 0; i < ui->lstAssets->count(); i++)
        {
            auto a = ui->lstAssets->item(i);
            if (!a->isSelected())
                a->setSelected(true);
        }

        QVERIFY2(wait(window), "Background operation timed out");

        window->OpenCKL();
        QVERIFY2(wait(window), "Background operation timed out");

        for (int j = 1; j < ui->tabDB->count(); j++)
        {
            auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(j));

            if (tmpTabView)
                tmpTabView->SetTabIndex(j);

            QVERIFY2(wait(window), "Background operation timed out");

            qDebug("STIGQter test %d: Running Tab Tests", step++);
            if (tmpTabView)
            {
                runTab(tmpTabView, window);
            }
            QVERIFY2(wait(window), "Background operation timed out");
        }
    }
}

void UiScenarios::phase5(STIGQter *window)
{
    qDebug("STIGQter test %d: Reopen Asset", step++);
    window->ImportCKLs({QStringLiteral("tests/monolithic.ckl")});
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Findings Report", step++);
    window->FindingsReport(QStringLiteral("tests/DFR.xlsx"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: POAM Report", step++);
    window->POAMTemplate(QStringLiteral("tests/POAM.xlsx"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: HTML Checklists", step++);
    window->ExportHTML(QStringLiteral("tests"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Export CMRS", step++);
    window->ExportCMRS(QStringLiteral("tests/cmrs.xml"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Export eMASS TR", step++);
    window->ExportEMASS(QStringLiteral("tests/emass.xlsx"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGQter test %d: Help Screen", step++);
    {
        auto a = window->About();
        QVERIFY2(wait(window), "Background operation timed out");
        a->close();
        QVERIFY2(wait(window), "Background operation timed out");
    }
}

void UiScenarios::runAssetView(QPointer<AssetView> subject, STIGQter *window)
{
    auto *ui = subject->ui;
    int onTest = 0;
    qDebug("AssetView test %d: Filter", onTest++);
    ui->txtSTIGFilter->setText(QStringLiteral("Windows"));

    qDebug("AssetView test %d: Clear Filter", onTest++);
    ui->txtSTIGFilter->setText(QString());

    qDebug("AssetView test %d: View CKLs", onTest++);
    {
        DbManager db;
        for (const CKLCheck &cklCheck : db.GetCKLChecks())
        {
            subject->UpdateCKLCheck(cklCheck);
        }
    }

    qDebug("AssetView test %d: Change Check Selection", onTest++);
    ui->lstChecks->selectAll();

    qDebug("AssetView test %d: Change Findings Status", onTest++);
    subject->KeyShortcutCtrlN();
    QVERIFY2(wait(window), "Background operation timed out");
    subject->KeyShortcutCtrlO();
    QVERIFY2(wait(window), "Background operation timed out");
    subject->KeyShortcutCtrlR();
    QVERIFY2(wait(window), "Background operation timed out");
    subject->KeyShortcutCtrlX();
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("AssetView test %d: Change Asset", onTest++);
    ui->txtFQDN->setText(QStringLiteral("test.example.org"));
    ui->txtIP->setText(QStringLiteral("127.0.0.1"));
    ui->txtMAC->setText(QStringLiteral("00:00:00:00:00:00"));
    ui->txtMarking->setText(QStringLiteral("PUBLIC RELEASE"));

    qDebug("AssetView test %d: Save Monolithic CKL", onTest++);
    subject->SaveCKL(QStringLiteral("tests/monolithic.ckl"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("AssetView test %d: Save Individual CKLs", onTest++);
    subject->SaveCKLs(QStringLiteral("tests/"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("AssetView test %d: Count Checks", onTest++);
    subject->UpdateChecks();

    qDebug("AssetView test %d: Import XCCDF", onTest++);
    QList<int> selectedGuides;
    for (auto *item : ui->lstSTIGs->selectedItems()) selectedGuides.append(item->data(Qt::UserRole).value<STIG>().id);
    subject->ImportXCCDF(QStringLiteral("tests/xccdf_lol.xml"));
    QVERIFY2(wait(window), "Background operation timed out");
    QList<int> reloadedGuides;
    for (auto *item : ui->lstSTIGs->selectedItems()) reloadedGuides.append(item->data(Qt::UserRole).value<STIG>().id);
    QCOMPARE(reloadedGuides, selectedGuides);

    qDebug("AssetView test %d: Rename Asset", onTest++);
    subject->RenameAsset(QStringLiteral("TEST2"));
    subject->RenameAsset(QStringLiteral("TEST"));

    qDebug("AssetView test %d: Upgrade ASD STIG", onTest++);
    ui->lstChecks->clearSelection();
    QVERIFY2(wait(window), "Background operation timed out");
    for (int j = 0; j < ui->lstChecks->count(); j++)
    {
        CKLCheck cc = ui->lstChecks->item(j)->data(Qt::UserRole).value<CKLCheck>();
        if (cc.GetSTIGCheck().GetSTIG().fileName.compare(QStringLiteral("U_ASD_STIG_V5R1_Manual-xccdf.xml")) == 0)
        {
            ui->lstChecks->item(j)->setSelected(true);
            QVERIFY2(wait(window), "Background operation timed out");
            break;
        }
    }
    subject->UpgradeCKL();
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("AssetView test %d: Delete Asset", onTest++);
    if (subject) subject->DeleteAsset(true);
}

void UiScenarios::runSTIGEdit(STIGEdit * subject, STIGQter *window)
{
    auto *ui = subject->ui;
    int onTest = 0;

    for (int i = 0; (i < ui->lstChecks->count()) && (i < 10); ++i)
    {
        qDebug("STIGEdit test %d: Select STIGCheck %d", onTest++, i);
        ui->lstChecks->item(i)->setSelected(true);
        QVERIFY2(wait(window), "Background operation timed out");

        qDebug("STIGEdit test %d: Change STIGCheck", onTest++);
        ui->txtFix->setText(QStringLiteral("FIX IT"));
        ui->txtCheckTitle->setText(ui->txtCheckTitle->text() + QStringLiteral(" (edited)"));
        subject->UpdateCheck();
        QVERIFY2(wait(window), "Background operation timed out");

        qDebug("STIGEdit test %d: Change severity/documentable", onTest++);
        ui->cboBoxSeverity->setCurrentIndex((ui->cboBoxSeverity->currentIndex() + 1) % ui->cboBoxSeverity->count());
        ui->cbDocumentable->setChecked(!ui->cbDocumentable->isChecked());
        QVERIFY2(wait(window), "Background operation timed out");

        qDebug("STIGEdit test %d: Add and remove a CCI (net-zero)", onTest++);
        int cciCount = ui->lstCCIs->count();
        subject->AddCCI();
        QVERIFY2(wait(window), "Background operation timed out");
        if (ui->lstCCIs->count() > cciCount)
        {
            //remove the CCI just added so the check's mapping is left intact
            ui->lstCCIs->item(ui->lstCCIs->count() - 1)->setSelected(true);
            subject->DeleteCCI();
            QVERIFY2(wait(window), "Background operation timed out");
        }
    }

    qDebug("STIGEdit test %d: Add a new check", onTest++);
    int checkCount = ui->lstChecks->count();
    subject->AddCheck();
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGEdit test %d: Delete the new check", onTest++);
    if (ui->lstChecks->count() > checkCount)
    {
        ui->lstChecks->setCurrentRow(ui->lstChecks->count() - 1);
        QVERIFY2(wait(window), "Background operation timed out");
        subject->DeleteCheck();
        QVERIFY2(wait(window), "Background operation timed out");
    }

    qDebug("STIGEdit test %d: Edit STIG title", onTest++);
    ui->txtTitle->setText(ui->txtTitle->text() + QStringLiteral(" (edited)"));
    QVERIFY2(wait(window), "Background operation timed out");

    qDebug("STIGEdit test %d: Export STIG to zip", onTest++);
    subject->SaveSTIG(QStringLiteral("tests/exported_stig.zip"));
    QVERIFY2(wait(window), "Background operation timed out");

    Q_EMIT subject->CloseTab(window->ui->tabDB->indexOf(subject));
}
