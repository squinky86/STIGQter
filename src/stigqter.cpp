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

#include "assetview.h"
#include "common.h"
#include "help.h"
#include "stigqter.h"
#include "workerassetadd.h"
#include "workercciadd.h"
#include "workerccidelete.h"
#include "workercmrsexport.h"
#include "workercklexport.h"
#include "workercklimport.h"
#include "workeremassreport.h"
#include "workerfindingsreport.h"
#include "workerimportemass.h"
#include "workermapunmapped.h"
#include "workerstigadd.h"
#include "workerstigdelete.h"
#include "workerstigdownload.h"

#include "ui_stigqter.h"
#include "workercheckversion.h"
#include "workerhtml.h"

#include <QCryptographicHash>
#include <QCloseEvent>
#include <QFileDialog>
#include <QHostInfo>
#include <QInputDialog>
#include <QMessageBox>
#include <QProcess>
#include <QStandardPaths>
#include <QThread>

#include <iostream>

/**
 * @class STIGQter
 * @brief @a STIGQter is an open-source STIG Viewer alternative
 * capable of generating findings reports and eMASS-compatible
 * resources.
 *
 * The original goal of STIGQter was to help familiarize the original
 * developer (Jon Hood) with the latest Qt framework (5.12) after
 * leaving the Qt world after version 3.1.
 *
 * After building a STIG Viewer-like, Asset-based interface, members
 * of certain Army SCA-V teams began requesting new features.
 * STIGQter incorporated those features in a faster, open way than
 * DISA's STIG Viewer, and the first beta of the product was released
 * on github.
 *
 * STIGQter now supports eMASS Test Result (TR) imports and exports,
 * and it automates several of the validation tasks in the self-
 * assessment and validation roles of the Army's Risk Management
 * Framework (RMF) process.
 */

/**
 * @brief STIGQter::STIGQter
 * @param parent
 *
 * Main constructor for the main GUI.
 */
STIGQter::STIGQter(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::STIGQter),
    _updatedAssets(false),
    _updatedCCIs(false),
    _updatedSTIGs(false),
    _isFiltered(false)
{
    //log software startup as required by SV-84041r1_rule
    Warning("System is Starting", QHostInfo::localHostName(), true, 4);

    ui->setupUi(this);

    //set the title bar
    this->setWindowTitle(QStringLiteral("STIGQter ") + VERSION);

    //make sure that the initial data are populated and active
    EnableInput();
    DisplayCCIs();
    DisplaySTIGs();
    DisplayAssets();

    //remove the close button on the main DB tab.
    ui->tabDB->tabBar()->tabButton(0, QTabBar::RightSide)->resize(0, 0);

    //set keyboard shortcuts
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_S), this, SLOT(Save())));

    //display path to database file
    DbManager db;
    ui->lblDBLoc->setText(QStringLiteral("DB: ") + db.GetDBPath());

    //check version number
    auto *t = new QThread;
    auto *c = new WorkerCheckVersion();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(c, SIGNAL(ThrowWarning(QString, QString)), this, SLOT(ShowMessage(QString, QString)));
    threads.append(t);
    workers.append(c);

    t->start(); //WorkerCheckVersion()
}

/**
 * @brief STIGQter::~STIGQter
 *
 * Destructor.
 */
STIGQter::~STIGQter()
{
    CleanThreads();
    delete ui;
    Q_FOREACH (QShortcut *shortcut, _shortcuts)
        delete shortcut;
    _shortcuts.clear();
    //log software shutdown as required by SV-84041r1_rule
    Warning("System is Shutting Down", QHostInfo::localHostName(), true, 4);
}

/**
 * @brief STIGQter::isProcessingEnabled
 * @return true when quit button is disabled; otherwise, false
 */
bool STIGQter::isProcessingEnabled()
{
    return ui->btnQuit->isEnabled();
}

#ifdef USE_TESTS
/**
 * @brief STIGQter::RunTests
 * Test functionality
 */
void STIGQter::RunTests()
{
    DbManager db;

    //step 0 - create asset
    std::cout << "\tCreating Asset \"TEST\"" << std::endl;
    ui->lstSTIGs->selectAll();
    AddAsset("TEST");
    while (!isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }

    //step 1 - map unmapped STIGs
    std::cout << "\tRemapping unmapped STIGs" << std::endl;
    MapUnmapped(true);
    while (!isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }

    //step 1 - open all assets
    std::cout << "\tOpening Assets" << std::endl;
    {
        Q_FOREACH(Asset asset, db.GetAssets())
        {
            Warning("On Asset", PrintAsset(asset));

            //filter STIGs
            ui->txtSTIGSearch->setText(QStringLiteral("Windows"));

            //open tab
            AssetView av(asset, this);
            connect(&av, SIGNAL(CloseTab(int)), this, SLOT(CloseTab(int)));
            int index = ui->tabDB->addTab(&av, asset.hostName);
            av.SetTabIndex(index);
            ui->tabDB->setCurrentIndex(index);

            //step 2 - run AssetView tests
            std::cout << "\tRunning Asset Tests" << std::endl;
            av.RunTests(); //will delete asset
        }
    }

    //step 2 - reopen assets
    std::cout << "\tReopening Assets" << std::endl;
    {
        ui->lstAssets->selectAll();
        OpenCKL();
    }
}
#endif

/**
 * @brief STIGQter::UpdateCCIs
 *
 * Start a thread to update the @a Family, @a Control, and @a CCI
 * information from the NIST and IASE websites. A @a WorkerCCIAdd
 * instance is created.
 */
void STIGQter::UpdateCCIs()
{
    DisableInput();
    _updatedCCIs = true;

    //Create thread to download CCIs and keep GUI active
    auto *t = new QThread;
    auto *c = new WorkerCCIAdd();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

/**
 * @brief STIGQter::OpenCKL
 *
 * Opens the selected @a Asset in a new tab.
 */
void STIGQter::OpenCKL()
{
    Q_FOREACH(QListWidgetItem *i, ui->lstAssets->selectedItems())
    {
        auto a = i->data(Qt::UserRole).value<Asset>();
        QString assetName = PrintAsset(a);
        for (int j = 0; j < ui->tabDB->count(); j++)
        {
             if (ui->tabDB->tabText(j) == assetName)
             {
                 ui->tabDB->setCurrentIndex(j);
                 return;
             }
        }
        auto *av = new AssetView(a, this);
        connect(av, SIGNAL(CloseTab(int)), this, SLOT(CloseTab(int)));
        int index = ui->tabDB->addTab(av, assetName);
        av->SetTabIndex(index);
        ui->tabDB->setCurrentIndex(index);
    }
}

/**
 * @brief STIGQter::Reset
 * @param checkOnly
 *
 * Check if the .stigqter file has been saved before closing the
 * database. If it has not, give the user an opportunity to save it.
 */
bool STIGQter::Reset(bool checkOnly)
{
    if (lastSaveLocation.isNull() || lastSaveLocation.isEmpty())
    {
        if (checkOnly)
            return true; // database is not saved externally

        QMessageBox::StandardButton reply = QMessageBox::question(this, QStringLiteral("Unsaved Changes"), QStringLiteral("The data have not been saved. Really close?"), QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes)
        {
            DbManager db;
            db.DeleteDB();
            qApp->quit();
            QProcess::startDetached(qApp->arguments()[0], qApp->arguments());
        }
    }
    else
    {
        //check if saved database is up-to-date
        QFile dest(lastSaveLocation);
        dest.open(QFile::ReadOnly);
        QByteArray destHash = QCryptographicHash::hash(dest.readAll(), QCryptographicHash::Sha3_256);
        dest.close();
        DbManager db;
        if (destHash == db.HashDB())
        {
            //database was saved without changes; reset application.
            if (checkOnly)
                return true;
            db.DeleteDB();
            qApp->quit();
            QProcess::startDetached(qApp->arguments()[0], qApp->arguments());
        }
        else
        {
            //there are unsaved changes; verify closing the DB
            QMessageBox::StandardButton reply = QMessageBox::question(this, QStringLiteral("Unsaved Changes"), QStringLiteral("There are unsaved changes to the file you wrote. Really close?"), QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::Yes)
            {
                if (checkOnly)
                    return true;
                db.DeleteDB();
                qApp->quit();
                QProcess::startDetached(qApp->arguments()[0], qApp->arguments());
            }
        }
    }
    return false;
}

/**
 * @brief STIGQter::Save
 *
 * Override the last saved .stigqter file or prompt the user for
 * where to save a new one.
 */
void STIGQter::Save()
{
    if (lastSaveLocation.isNull() || lastSaveLocation.isEmpty())
        SaveAs();

    if (!lastSaveLocation.isNull() && !lastSaveLocation.isEmpty())
    {
        DbManager db;
        db.SaveDB(lastSaveLocation);
    }
}

/**
 * @brief STIGQter::SaveAs
 *
 * Prompt the user for where to save the .stigqter file
 */
void STIGQter::SaveAs()
{
    DbManager db;
    QString fileName = QFileDialog::getSaveFileName(this,
        QStringLiteral("Save STIGQter Database"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIGQter Save File (*.stigqter)"));

    if (!fileName.isNull() && !fileName.isEmpty())
    {
        lastSaveLocation = fileName;
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
        Save();
    }
}

/**
 * @brief STIGQter::SelectAsset
 *
 * Show the @a STIGs associated with the selected @a Asset.
 */
void STIGQter::SelectAsset()
{
    UpdateSTIGs();
    EnableInput();
}

/**
 * @brief STIGQter::closeEvent
 * @param event
 *
 * Overrides the close event to make sure the database has been saved.
 */
void STIGQter::closeEvent(QCloseEvent *event)
{
    event->setAccepted(Reset(true));
}

/**
 * @brief STIGQter::CleanThreads
 * When the program closes, wait on all background threads to finish
 * processing.
 */
void STIGQter::CleanThreads()
{
    while (!threads.isEmpty())
    {
        QThread *t = threads.takeFirst();
        t->wait();
        delete t;
    }
    Q_FOREACH (const QObject *o, workers)
    {
        delete o;
    }
    workers.clear();
}

/**
 * @brief STIGQter::CompletedThread
 *
 * When a background thread completes, this function is signaled to
 * update UI elements with the new data.
 */
void STIGQter::CompletedThread()
{
    EnableInput();
    CleanThreads();
    if (_updatedCCIs)
    {
        DisplayCCIs();
        _updatedCCIs = false;
    }
    if (_updatedSTIGs)
    {
        DisplaySTIGs();
        _updatedSTIGs = false;
    }
    if (_updatedAssets)
    {
        DisplayAssets();
        _updatedAssets = false;
    }
    //when maximum <= 0, the progress bar loops
    if (ui->progressBar->maximum() <= 0)
        ui->progressBar->setMaximum(1);
    ui->progressBar->setValue(ui->progressBar->maximum());
}

/**
 * @brief STIGQter::About
 *
 * Display an About @a Help screen.
 */
void STIGQter::About()
{
    Help *h = new Help();
    h->setAttribute(Qt::WA_DeleteOnClose); //clean up after itself (no explicit "delete" needed)
    h->show();
}

/**
 * @brief STIGQter::AddAsset
 *
 * Create a new @a Asset with the selected \a STIGs associated with it.
 */
void STIGQter::AddAsset(const QString &name)
{
    bool ok = true;
    QString asset = !name.isEmpty() ? name : QInputDialog::getText(this, tr("Enter Asset Name"),
                                          tr("Asset:"), QLineEdit::Normal,
                                          QDir::home().dirName(), &ok);
    if (ok)
    {
        DisableInput();
        _updatedAssets = true;
        auto *t = new QThread;
        auto *a = new WorkerAssetAdd();
        a->moveToThread(t);
        Asset tmpAsset;
        tmpAsset.hostName = asset;
        Q_FOREACH(QListWidgetItem *i, ui->lstSTIGs->selectedItems())
        {
            a->AddSTIG(i->data(Qt::UserRole).value<STIG>());
        }
        a->AddAsset(tmpAsset);
        connect(t, SIGNAL(started()), a, SLOT(process()));
        connect(a, SIGNAL(finished()), t, SLOT(quit()));
        connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
        connect(a, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
        connect(a, SIGNAL(progress(int)), this, SLOT(Progress(int)));
        connect(a, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
        threads.append(t);
        workers.append(a);

        t->start();
    }
}

/**
 * @brief STIGQter::AddSTIGs
 *
 * Adds @a STIG checklists to the database. See
 * @l {https://iase.disa.mil/stigs/Pages/a-z.aspx} for more details.
 */
void STIGQter::AddSTIGs()
{
    DbManager db;
    QStringList fileNames = QFileDialog::getOpenFileNames(this,
        QStringLiteral("Open STIG"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Compressed STIG (*.zip)"));

    if (fileNames.count() <= 0)
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileNames[0]).absolutePath());

    DisableInput();
    _updatedSTIGs = true;
    auto *t = new QThread;
    auto *s = new WorkerSTIGAdd();
    s->moveToThread(t);
    s->AddSTIGs(fileNames);
    connect(t, SIGNAL(started()), s, SLOT(process()));
    connect(s, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(s, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(s, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(s, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(s);

    t->start();
}

/**
 * @brief STIGQter::CloseTab
 * @param i
 *
 * Close the tab with the identified index.
 */
void STIGQter::CloseTab(int index)
{
    if (ui->tabDB->count() > index)
        ui->tabDB->removeTab(index);
    for (int j = 1; j < ui->tabDB->count(); j++)
    {
        //reset the tab indices for the tabs that were not closed
        auto *tmpAssetView = dynamic_cast<AssetView*>(ui->tabDB->widget(j));
        if (tmpAssetView)
            tmpAssetView->SetTabIndex(j);
    }
    DisplayAssets();
}

/**
 * @brief STIGQter::DeleteCCIs
 *
 * Clear the database of initial NIST and DISA information.
 */
void STIGQter::DeleteCCIs()
{
    DisableInput();
    _updatedCCIs = true;

    //Create thread to download CCIs and keep GUI active
    auto *t = new QThread;
    auto *c = new WorkerCCIDelete();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

/**
 * @brief STIGQter::DeleteEmass
 *
 * Remove eMASS Test Results (TR) from the database.
 */
void STIGQter::DeleteEmass()
{
    DbManager db;
    db.DeleteEmassImport();
    EnableInput();
}

/**
 * @brief STIGQter::DeleteSTIGs
 *
 * Remove the selected @a STIGs from the database after making sure
 * that no @a Asset is using them.
 */
void STIGQter::DeleteSTIGs()
{
    DisableInput();
    _updatedSTIGs = true;

    auto *t = new QThread;
    auto *s = new WorkerSTIGDelete();
    s->moveToThread(t);
    Q_FOREACH (QListWidgetItem *i, ui->lstSTIGs->selectedItems())
    {
        STIG stig = i->data(Qt::UserRole).value<STIG>();
        s->AddId(stig.id);
    }
    connect(t, SIGNAL(started()), s, SLOT(process()));
    connect(s, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(s, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(s, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(s, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(s);

    t->start();
}

/**
 * @brief STIGQter::DownloadSTIGs
 *
 * Download the latest unclassified STIG release from cyber.mil
 * and process the new STIGs
 */
void STIGQter::DownloadSTIGs()
{
    DisableInput();
    _updatedSTIGs = true;

    //Create thread to download CCIs and keep GUI active
    auto *t = new QThread;
    auto *s = new WorkerSTIGDownload();

    s->moveToThread(t);
    connect(t, SIGNAL(started()), s, SLOT(process()));
    connect(s, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(s, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(s, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(s, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(s);

    t->start();
}

/**
 * @brief STIGQter::ExportCKLs
 *
 * Export all possible .ckl files into the selected directory.
 */
void STIGQter::ExportCKLs()
{
    DbManager db;
    QString dirName = QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *t = new QThread;
        auto *f = new WorkerCKLExport();
        f->moveToThread(t);
        f->SetExportDir(dirName);
        connect(t, SIGNAL(started()), f, SLOT(process()));
        connect(f, SIGNAL(finished()), t, SLOT(quit()));
        connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
        connect(f, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
        connect(f, SIGNAL(progress(int)), this, SLOT(Progress(int)));
        connect(f, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
        threads.append(t);
        workers.append(f);

        t->start();
    }
}

/**
 * @brief STIGQter::ExportCMRS
 *
 * Generate a CMRS report of the findings.
 */
void STIGQter::ExportCMRS()
{
    DbManager db;
    QString fileName = QFileDialog::getSaveFileName(this, QStringLiteral("Save CMRS Report"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("CMRS XML (*.xml)"));

    if (fileName.isNull() || fileName.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
    auto *t = new QThread;
    auto *f = new WorkerCMRSExport();
    f->moveToThread(t);
    f->SetExportPath(fileName);
    connect(t, SIGNAL(started()), f, SLOT(process()));
    connect(f, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(f, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(f, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(f, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(f);

    t->start();
}

/**
 * @brief STIGQter::ExportEMASS
 *
 * Create an eMASS Test Result Import workbook.
 */
void STIGQter::ExportEMASS()
{
    DbManager db;
    QString fileName = QFileDialog::getSaveFileName(this, QStringLiteral("Save eMASS Report"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Microsoft Excel (*.xlsx)"));

    if (fileName.isNull() || fileName.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
    auto *t = new QThread;
    auto *f = new WorkerEMASSReport();
    f->moveToThread(t);
    f->SetReportName(fileName);
    connect(t, SIGNAL(started()), f, SLOT(process()));
    connect(f, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(f, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(f, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(f, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(f);

    t->start();
}

/**
 * @brief STIGQter::ExportHTML
 *
 * Instantiates an instance of WorkerHTML to export the HTML
 * templates for the manual STIG lists.
 */
void STIGQter::ExportHTML()
{
    DbManager db;
    QString dirName = QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *t = new QThread;
        auto *f = new WorkerHTML();
        f->moveToThread(t);
        f->SetDir(dirName);
        connect(t, SIGNAL(started()), f, SLOT(process()));
        connect(f, SIGNAL(finished()), t, SLOT(quit()));
        connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
        connect(f, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
        connect(f, SIGNAL(progress(int)), this, SLOT(Progress(int)));
        connect(f, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
        threads.append(t);
        workers.append(f);

        t->start();
    }
}

/**
 * @brief STIGQter::FilterSTIGs
 * @param text
 *
 * Filter the STIG list based on search text
 */
void STIGQter::FilterSTIGs(const QString &text)
{
    if (text.length() > 2)
    {
        _isFiltered = true;
        DisplaySTIGs(text);
    }
    else if (_isFiltered)
    {
        _isFiltered = false;
        DisplaySTIGs();
    }
}

/**
 * @brief STIGQter::FindingsReport
 *
 * Create a detailed findings report to make the findings data more
 * human-readable.
 */
void STIGQter::FindingsReport()
{
    DbManager db;
    QString fileName = QFileDialog::getSaveFileName(this,
        QStringLiteral("Save Detailed Findings"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Microsoft Excel (*.xlsx)"));

    if (fileName.isNull() || fileName.isEmpty())
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
    DisableInput();
    auto *t = new QThread;
    auto *f = new WorkerFindingsReport();
    f->moveToThread(t);
    f->SetReportName(fileName);
    connect(t, SIGNAL(started()), f, SLOT(process()));
    connect(f, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(f, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(f, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(f, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(f);

    t->start();
}

/**
 * @brief STIGQter::ImportCKLs
 *
 * Import existing CKL files (potentially from STIG Viewer or old
 * versions of STIG Qter).
 */
void STIGQter::ImportCKLs()
{
    DbManager db;
    QStringList fileNames = QFileDialog::getOpenFileNames(this,
        QStringLiteral("Import CKL(s)"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIG Checklist (*.ckl)"));

    if (fileNames.count() <= 0)
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileNames[0]).absolutePath());
    DisableInput();
    _updatedAssets = true;
    auto *t = new QThread();
    auto *c = new WorkerCKLImport();
    c->moveToThread(t);
    c->AddCKLs(fileNames);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

/**
 * @brief STIGQter::ImportEMASS
 *
 * Import an existing Test Result Import spreadsheet.
 */
void STIGQter::ImportEMASS()
{
    DbManager db;
    QString fileName = QFileDialog::getOpenFileName(this,
        QStringLiteral("Import eMASS TRExport"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Excel Spreadsheet (*.xlsx)"));

    if (fileName.isNull() || fileName.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
    auto *t = new QThread;
    auto *c = new WorkerImportEMASS();
    c->SetReportName(fileName);
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

/**
 * @brief STIGQter::Load
 *
 * The user is prompted for the *.stigqter file to load.
 */
void STIGQter::Load()
{
    DbManager db;
    QString fileName = QFileDialog::getOpenFileName(this,
        QStringLiteral("Open STIGQter Save File"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIGQter Save File (*.stigqter)"));

    if (!fileName.isNull() && !fileName.isEmpty())
    {
        while (ui->tabDB->count() > 1)
            ui->tabDB->removeTab(1);
        db.LoadDB(fileName);
        EnableInput();
        DisplayCCIs();
        DisplaySTIGs();
        DisplayAssets();
        lastSaveLocation = fileName;
    }
}

/**
 * @brief STIGQter::UpdateCCIs
 *
 * Start a thread to update the @a Family, @a Control, and @a CCI
 * information from the NIST and IASE websites. A @a WorkerCCIAdd
 * instance is created.
 */
void STIGQter::MapUnmapped(bool confirm)
{
    QMessageBox::StandardButton reply = confirm ? QMessageBox::Yes : QMessageBox::question(this, QStringLiteral("Non-Standard CKLs"), QStringLiteral("This feature will map all unmapped STIG checks, STIG checks from other system categorizations, and incorrectly mapped STIG checks to CM-6, CCI-366. CKL files generated will no longer be consistent with STIGViewer and other tools. Are you sure you want to proceed?"), QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DisableInput();
        _updatedCCIs = true;

        //Create thread to download CCIs and keep GUI active
        auto *t = new QThread;
        auto *c = new WorkerMapUnmapped();
        c->moveToThread(t);
        connect(t, SIGNAL(started()), c, SLOT(process()));
        connect(c, SIGNAL(finished()), t, SLOT(quit()));
        connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
        connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
        connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
        connect(c, SIGNAL(updateStatus(QString)), this, SLOT(StatusChange(QString)));
        threads.append(t);
        workers.append(c);

        t->start();
    }
}

/**
 * @brief STIGQter::SelectSTIG
 *
 * This function is triggered when the @a STIG selection changes.
 */
void STIGQter::SelectSTIG()
{
    //select STIGs to create checklists
    ui->btnCreateCKL->setEnabled(ui->lstSTIGs->selectedItems().count() > 0);
}

/**
 * @brief STIGQter::StatusChange
 * @param status
 *
 * Show status updates
 */
void STIGQter::StatusChange(const QString &status)
{
    ui->lblStatus->setText(status);
#ifdef USE_TESTS
    std::cout << "\t" << status.toStdString() << std::endl;
#endif
}

/**
 * @brief STIGQter::ShowMessage
 * @param title
 * @param message
 *
 * Display a message on the main thread.
 */
void STIGQter::ShowMessage(const QString &title, const QString &message)
{
    Warning(title, message);
}

/**
 * @brief STIGQter::EnableInput
 *
 * At the end of several background workers' processing task, the
 * EnableInput() routine will allow the GUI elements to interact with
 * the user. This function is used in conjunction with
 * @a DisableInput().
 */
void STIGQter::EnableInput()
{
    DbManager db;
    QList<Family> f = db.GetFamilies();
    QList<STIG> s = db.GetSTIGs();
    bool stigsNotImported = s.count() <= 0;
    bool isImport = db.IsEmassImport();

    ui->btnImportEmass->setEnabled(!isImport);

    if (f.count() > 0)
    {
        //disable deleting CCIs if STIGs have been imported
        ui->btnClearCCIs->setEnabled(stigsNotImported);
        ui->btnDownloadSTIGs->setEnabled(stigsNotImported);
        ui->btnImportCCIs->setEnabled(false);
        ui->btnImportSTIGs->setEnabled(true);
    }
    else
    {
        ui->btnClearCCIs->setEnabled(false);
        ui->btnDownloadSTIGs->setEnabled(false);
        ui->btnImportEmass->setEnabled(false);
        ui->btnImportCCIs->setEnabled(true);
        ui->btnImportSTIGs->setEnabled(false);
    }
    ui->btnClearSTIGs->setEnabled(true);
    ui->btnCreateCKL->setEnabled(true);
    ui->btnDeleteEmassImport->setEnabled(isImport);
    ui->btnImportCKL->setEnabled(true);
    ui->btnMapUnmapped->setEnabled(isImport);
    ui->btnOpenCKL->setEnabled(ui->lstAssets->selectedItems().count() > 0);
    ui->btnQuit->setEnabled(true);
    ui->menubar->setEnabled(true);
    ui->txtSTIGSearch->setEnabled(true);
    ui->tabDB->setEnabled(true);
    for (int i = 1; i < ui->tabDB->count(); i++)
    {
        auto *tmpAssetView = dynamic_cast<AssetView*>(ui->tabDB->widget(i));
        tmpAssetView->EnableInput();
    }
    SelectSTIG();
}

/**
 * @brief STIGQter::UpdateSTIGs
 *
 * Update the display of STIGs available in the database.
 */
void STIGQter::UpdateSTIGs()
{
    ui->lstCKLs->clear();
    Q_FOREACH (QListWidgetItem *i, ui->lstAssets->selectedItems())
    {
        auto a = i->data(Qt::UserRole).value<Asset>();
        Q_FOREACH (const STIG &s, a.GetSTIGs())
        {
            ui->lstCKLs->addItem(PrintSTIG(s));
        }
    }
}

/**
 * @brief STIGQter::Initialize
 * @param max
 * @param val
 *
 * Initializes the progress bar so that it has @a max steps and is
 * currently at step @a val.
 */
void STIGQter::Initialize(int max, int val)
{
    ui->progressBar->reset();
    ui->progressBar->setMaximum(max);
    ui->progressBar->setValue(val);
}

/**
 * @brief STIGQter::Progress
 * @param val
 *
 * Sets the progress bar to display that it is at step @a val. If a
 * negative number is given, it increments the progress bar by one
 * step.
 */
void STIGQter::Progress(int val)
{
    if (val < 0)
    {
        ui->progressBar->setValue(ui->progressBar->value() + 1);
    }
    else
        ui->progressBar->setValue(val);
}

/**
 * @brief STIGQter::DisableInput
 *
 * Prevent user interaction while background processes are busy.
 */
void STIGQter::DisableInput()
{
    ui->btnClearCCIs->setEnabled(false);
    ui->btnClearSTIGs->setEnabled(false);
    ui->btnCreateCKL->setEnabled(false);
    ui->btnDeleteEmassImport->setEnabled(false);
    ui->btnDownloadSTIGs->setEnabled(false);
    ui->btnImportCCIs->setEnabled(false);
    ui->btnImportCKL->setEnabled(false);
    ui->btnImportEmass->setEnabled(false);
    ui->btnImportSTIGs->setEnabled(false);
    ui->btnMapUnmapped->setEnabled(false);
    ui->btnOpenCKL->setEnabled(false);
    ui->btnQuit->setEnabled(false);
    ui->menubar->setEnabled(false);
    ui->txtSTIGSearch->setEnabled(false);
    ui->tabDB->setEnabled(false);
    for (int i = 1; i < ui->tabDB->count(); i++)
    {
        auto *tmpAssetView = dynamic_cast<AssetView*>(ui->tabDB->widget(i));
        tmpAssetView->DisableInput();
    }
}

/**
 * @brief STIGQter::DisplayAssets
 *
 * Show the list of @a Assets to the user.
 */
void STIGQter::DisplayAssets()
{
    ui->lstAssets->clear();
    DbManager db;
    Q_FOREACH(const Asset &a, db.GetAssets())
    {
        auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstAssets container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<Asset>(a));
        tmpItem->setText(PrintAsset(a));
        ui->lstAssets->addItem(tmpItem);
    }
}

/**
 * @brief STIGQter::DisplayCCIs
 *
 * Show the list of @a CCIs to the user.
 */
void STIGQter::DisplayCCIs()
{
    ui->lstCCIs->clear();
    DbManager db;
    Q_FOREACH(const CCI &c, db.GetCCIs())
    {
        auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstCCIs container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<CCI>(c));
        tmpItem->setText(PrintCCI(c));
        ui->lstCCIs->addItem(tmpItem);
    }
}

/**
 * @brief STIGQter::DisplaySTIGs
 * @param search
 *
 * Show the list of @a STIGs to the user. This represents the global
 * @a STIG list in the database representing all @a STIGs that have
 * been imported, not only the @a STIGs for a particular @a Asset.
 */
void STIGQter::DisplaySTIGs(const QString &search)
{
    ui->lstSTIGs->clear();
    DbManager db;
    Q_FOREACH(const STIG &s, db.GetSTIGs())
    {
        //check to see if the filter is applied
        if (!search.isEmpty())
        {
            if (!s.title.contains(search, Qt::CaseInsensitive))
                continue;
        }

        auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstSTIGs container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        tmpItem->setText(PrintSTIG(s));
        ui->lstSTIGs->addItem(tmpItem);
    }
}
