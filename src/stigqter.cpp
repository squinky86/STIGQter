/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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
#include "stigedit.h"
#include "stigqter.h"
#include "workerassetadd.h"
#include "workerassetdelete.h"
#include "workercciadd.h"
#include "workerccidelete.h"
#include "workercmrsexport.h"
#include "workercklexport.h"
#include "workercklimport.h"
#include "workeremassreport.h"
#include "workerfindingsreport.h"
#include "workerimportemass.h"
#include "workerimportemasscontrol.h"
#include "workermapunmapped.h"
#include "workerpoamreport.h"
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
    Warning(QStringLiteral("System is Starting"), QHostInfo::localHostName(), true, 4);

    ui->setupUi(this);

    //set the title bar
    this->setWindowTitle(QStringLiteral("STIGQter ") + VERSION);

    //make sure that the initial data are populated and active
    Display();

    //remove the close button on the main DB tab.
    ui->tabDB->tabBar()->tabButton(0, QTabBar::RightSide)->resize(0, 0);

    //set keyboard shortcuts
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_S), this, SLOT(Save())));

    //display path to database file
    DbManager db;
    ui->lblDBLoc->setText(QStringLiteral("DB: ") + db.GetDBPath());

    //display classification marking
    ui->txtMarking->setText(db.GetVariable("marking"));

    //remember if we're indexing STIG checks
    ui->cbIncludeSupplements->setChecked(db.GetVariable("indexSupplements").startsWith(QStringLiteral("y"), Qt::CaseInsensitive));
    ui->cbRemapCM6->setChecked(db.GetVariable("remapCM6").startsWith(QStringLiteral("y"), Qt::CaseInsensitive));
    UpdateRemapButton();

    //check version number
    QTimer::singleShot(0, this, SLOT(CheckVersion()));
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
    Warning(QStringLiteral("System is Shutting Down"), QHostInfo::localHostName(), true, 4);
}

/**
 * @brief STIGQter::isProcessingEnabled
 * @return true when quit button is disabled; otherwise, false
 */
bool STIGQter::isProcessingEnabled()
{
    return ui->btnQuit->isEnabled();
}

/**
 * @brief STIGQter::ConnectThreads
 * @param worker
 * @param blocking
 *
 * Connect STIGQter input/output to the worker and its thread
 */
QThread* STIGQter::ConnectThreads(Worker *worker, bool blocking)
{
    if (blocking)
        DisableInput();

    auto *t = worker->ConnectThreads(this, blocking);

    threads.append(t);
    workers.append(worker);

    return t;
}

#ifdef USE_TESTS
#include <algorithm>
#include <random>

/**
 * @brief STIGQter::RunTests
 * Test functionality
 */
void STIGQter::ProcEvents()
{
    while (!isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }
    QApplication::processEvents();
}

void STIGQter::RunTests()
{
    DbManager db;
    int step = 0;

    std::random_device rd;
    std::default_random_engine g(rd());

    // refresh STIGs
    std::cout << "\tTest " << step++ << ": Refresh STIGs" << std::endl;
    UpdateSTIGs();
    ProcEvents();

    // delete random STIGs (required to finish travis-ci build)
    std::cout << "\tTest " << step++ << ": Deleting Some STIGs" << std::endl;
    {
        int size = ui->lstSTIGs->count();
        if (size > 5)
        {
            ui->lstSTIGs->selectAll();
            ProcEvents();
            auto stigs = ui->lstSTIGs->selectedItems();
            std::shuffle(stigs.begin(), stigs.end(), g);
            for (int i = 0; i < 5; i++)
            {
                stigs.at(i)->setSelected(false);
            }
            ProcEvents();
            DeleteSTIGs();
            ProcEvents();
        }
    }

    // filter STIGs
    std::cout << "\t\tTest " << step++ << ": Filter" << std::endl;
    ui->txtSTIGSearch->setText(QStringLiteral("Windows"));
    ProcEvents();

    // unfilter STIGs
    std::cout << "\t\tTest " << step++ << ": Clear Filter" << std::endl;
    ui->txtSTIGSearch->setText(QString());
    ProcEvents();

    // message handler
    std::cout << "\t\tTest " << step++ << ": Message Handling" << std::endl;
    QMessageLogContext c("test.cpp", 1, "TestFunc", "TestCat");
    MessageHandler(QtMsgType::QtDebugMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtInfoMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtWarningMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtCriticalMsg, c, QStringLiteral("Test Message"));
    MessageHandler(QtMsgType::QtFatalMsg, c, QStringLiteral("Test Message"));
    ProcEvents();

    // import eMASS results
    std::cout << "\tTest " << step++ << ": Import eMASS Results" << std::endl;
    ImportEMASS(QStringLiteral("tests/emassTRImport.xlsx"));
    ProcEvents();

    // remap unmapped to CM-6
    std::cout << "\tTest " << step++ << ": Remapping Unmapped to CM-6" << std::endl;
    ui->cbRemapCM6->setChecked(true);
    ProcEvents();
    MapUnmapped(true);
    ProcEvents();

    // create asset
    std::cout << "\tTest " << step++ << ": Creating Asset \"TEST\"" << std::endl;
    ui->lstSTIGs->selectAll();
    AddAsset(QStringLiteral("TEST"));
    ProcEvents();

    // open STIGs
    std::cout << "\tTest " << step++ << ": Opening STIGs" << std::endl;
    EditSTIG();
    ProcEvents();

    for (int j = 1; j < ui->tabDB->count(); j++)
    {
        auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(j));

        if (tmpTabView)
            tmpTabView->SetTabIndex(j);

        ProcEvents();

        //run STIGEdit tests
        std::cout << "\tTest " << step++ << ": Running STIG Editing" << std::endl;
        if (tmpTabView)
        {
            tmpTabView->RunTests(); //will delete tab
        }
        ProcEvents();
    }

    // severity override
    {
        std::cout << "Test " << step++ << ": Severity Override" << std::endl;
        Q_FOREACH(auto cklCheck, db.GetCKLChecks())
        {
            switch (std::uniform_int_distribution<>{0, 3}(g))
            {
            case 0:
                cklCheck.status = Status::Open;
                break;
            case 1:
                cklCheck.status = Status::NotAFinding;
                break;
            case 2:
                cklCheck.status = Status::NotReviewed;
                break;
            case 3:
                cklCheck.status = Status::NotApplicable;
                break;
            default:
                continue;
            }

            //override checks' severity pseudorandomly
            switch (std::uniform_int_distribution<>{0, 3}(g))
            {
            case 0:
                if (cklCheck.GetSeverity() == Severity::none)
                    continue;
                cklCheck.severityOverride = Severity::none;
                cklCheck.severityJustification = QStringLiteral("Overridden to none.");
                break;
            case 1:
                if (cklCheck.GetSeverity() == Severity::low)
                    continue;
                cklCheck.severityOverride = Severity::low;
                cklCheck.severityJustification = QStringLiteral("Overridden to low.");
                break;
            case 2:
                if (cklCheck.GetSeverity() == Severity::medium)
                    continue;
                cklCheck.severityOverride = Severity::medium;
                cklCheck.severityJustification = QStringLiteral("Overridden to medium.");
                break;
            case 3:
                if (cklCheck.GetSeverity() == Severity::high)
                    continue;
                cklCheck.severityOverride = Severity::high;
                cklCheck.severityJustification = QStringLiteral("Overridden to high.");
                break;
            default:
                continue;
            }
            db.UpdateCKLCheck(cklCheck);
        }
        ProcEvents();
    }

    // select the asset
    std::cout << "\tTest " << step++ << ": Selecting Asset \"TEST\"" << std::endl;
    ui->lstAssets->selectAll();
    ProcEvents();

    // build CKL files
    std::cout << "\tTest " << step++ << ": Exporting CKL files" << std::endl;
    ExportCKLs(QStringLiteral("tests"));
    while (!isProcessingEnabled())
    {
        QThread::sleep(1);
        ProcEvents();
    }

    // build monolithic CKL files
    std::cout << "\tTest " << step++ << ": Exporting Monolithic CKL files" << std::endl;
    ExportCKLsMonolithic(QStringLiteral("tests"));
    while (!isProcessingEnabled())
    {
        QThread::sleep(1);
        ProcEvents();
    }

    // save .stigqter file
    std::cout << "\tTest " << step++ << ": Saving .stigqter file" << std::endl;
    SaveAs(QStringLiteral("tests/test.stigqter"));
    ProcEvents();

    //load .stigqter file
    std::cout << "\tTest " << step++ << ": Loading .stigqter file" << std::endl;
    Load(QStringLiteral("tests/test.stigqter"));
    ProcEvents();

    // open all assets
    std::cout << "\tTest " << step++ << ": Opening Assets" << std::endl;
    {
        // reopen assets
        {
            ui->lstAssets->clearSelection();
            ProcEvents();
            ui->lstAssets->selectAll();
            ProcEvents();

            for (int i = 0; i < ui->lstAssets->count(); i++)
            {
                auto a = ui->lstAssets->item(i);
                if (!a->isSelected())
                    a->setSelected(true);
            }

            ProcEvents();

            OpenCKL();
            ProcEvents();
        }

        for (int j = 1; j < ui->tabDB->count(); j++)
        {
            auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(j));

            if (tmpTabView)
                tmpTabView->SetTabIndex(j);

            ProcEvents();

            //run AssetView tests
            std::cout << "\tTest " << step++ << ": Running Tab Tests" << std::endl;
            if (tmpTabView)
            {
                tmpTabView->RunTests(); //will delete tab
            }
            ProcEvents();
        }
    }

    // reopen asset
    std::cout << "\tTest " << step++ << ": Reopen Asset" << std::endl;
    ImportCKLs({QStringLiteral("tests/monolithic.ckl")});
    ProcEvents();

    // export Findings Report
    std::cout << "\tTest " << step++ << ": Findings Report" << std::endl;
    FindingsReport(QStringLiteral("tests/DFR.xlsx"));
    ProcEvents();

    // export POAM Report
    std::cout << "\tTest " << step++ << ": POAM Report" << std::endl;
    POAMTemplate(QStringLiteral("tests/POAM.xlsx"));
    ProcEvents();

    // export HTML
    std::cout << "\tTest " << step++ << ": HTML Checklists" << std::endl;
    ExportHTML(QStringLiteral("tests"));
    ProcEvents();

    // export CMRS
    std::cout << "\tTest " << step++ << ": Export CMRS" << std::endl;
    ExportCMRS(QStringLiteral("tests/cmrs.xml"));
    ProcEvents();

    // export eMASS
    std::cout << "\tTest " << step++ << ": Export eMASS TR" << std::endl;
    ExportEMASS(QStringLiteral("tests/emass.xlsx"));
    ProcEvents();

    // change classification
    std::cout << "\tTest " << step++ << ": Changing Classification Marking" << std::endl;
    ui->txtMarking->setText("PUBLIC RELEASE");
    ProcEvents();

    // help screen
    std::cout << "\tTest " << step++ << ": Help Screen" << std::endl;
    {
        auto a = About();
        ProcEvents();
        a->close();
        ProcEvents();
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
    _updatedCCIs = true;

    //Create thread to download CCIs and keep GUI active
    auto *c = new WorkerCCIAdd();

    ConnectThreads(c)->start();
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
        int index = ui->tabDB->addTab(av, assetName);
        av->SetTabIndex(index);
        ui->tabDB->setCurrentIndex(index);
    }
}

/**
 * @brief STIGQter::POAMTemplate
 *
 * Create a POA&M template at the CCI/APNum level or Control level
 */
void STIGQter::POAMTemplate(const QString &fileName, bool APNumLevel)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getSaveFileName(this,
        QStringLiteral("Save POA&M Template"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Microsoft Excel (*.xlsx)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    DisableInput();
    auto *f = new WorkerPOAMReport();
    f->SetReportName(fn);
    f->SetAPNums(APNumLevel);

    ConnectThreads(f)->start();
}

/**
 * @brief STIGQter::POAMTemplateControl
 *
 * Create a POA&M template at the Control level
 */
void STIGQter::POAMTemplateControl(const QString &fileName)
{
    POAMTemplate(fileName, false);
}

/**
 * @brief STIGQter::RemapChanged
 * @param checkState
 *
 * Change whether the user wants to remap to CCI-366 or all CM-6
 */
void STIGQter::RemapChanged(int checkState)
{
    DbManager db;
    db.UpdateVariable(QStringLiteral("remapCM6"), checkState == Qt::Checked ? QStringLiteral("y") : QStringLiteral("n"));
    UpdateRemapButton();
}

/**
 * @brief STIGQter::RenameTab
 * @param index
 * @param title
 *
 * Signal to indicate that a tab wishes to rename itself.
 */
void STIGQter::RenameTab(int index, const QString &title)
{
    //make sure we're not rename to itself
    if (QString::compare(ui->tabDB->tabText(index), title) == 0)
        return;

    //make sure another tab doesn't already exist
    for (int i = 1; i < ui->tabDB->count(); ++i)
    {
        if (i == index)
            continue;
        if (QString::compare(ui->tabDB->tabText(index), title) == 0)
        {
            CloseTab(index);
            return;
        }
    }

    //rename the tab
    ui->tabDB->setTabText(index, title);
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
            auto args = qApp->arguments();
            if (!args.isEmpty())
                QProcess::startDetached(args[0], args);
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
            auto args = qApp->arguments();
            if (!args.isEmpty())
                QProcess::startDetached(args[0], args);
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
                auto args = qApp->arguments();
                if (!args.isEmpty())
                    QProcess::startDetached(args[0], args);
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
 * @param fileName
 *
 * Prompt the user for where to save the .stigqter file
 */
void STIGQter::SaveAs(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getSaveFileName(this,
        QStringLiteral("Save STIGQter Database"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIGQter Save File (*.stigqter)"));

    if (!fn.isNull() && !fn.isEmpty())
    {
        lastSaveLocation = fn;
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
        Save();
    }
}

/**
 * @brief STIGQter::SaveMarking
 *
 * Change the marking of the STIGs
 */
void STIGQter::SaveMarking()
{
    DbManager db;
    db.UpdateVariable(QStringLiteral("marking"), ui->txtMarking->text());
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
    Q_FOREACH (auto *o, workers)
    {
        auto *t = o->thread();

        if (t->isRunning())
            continue;

        t->wait();

        QString connName = o->GetThreadId();
        if (!connName.isNull() && !connName.isEmpty())
        {
            if (QSqlDatabase::connectionNames().contains(connName))
                QSqlDatabase::removeDatabase(connName);
        }

        workers.removeOne(o);
        threads.removeOne(t);
        delete o;
        delete t;
    }
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
 * @brief STIGQter::CompletedThreadUnblocked
 *
 * Clean up threads, but don't update interface.
 */
void STIGQter::CompletedThreadUnblocked()
{
    CleanThreads();
}

/**
 * @brief STIGQter::About
 *
 * Display an About @a Help screen.
 */
Help* STIGQter::About()
{
    Help *h = new Help();
    h->setAttribute(Qt::WA_DeleteOnClose); //clean up after itself (no explicit "delete" needed)
    h->show();
    return h;
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
        auto *a = new WorkerAssetAdd();
        Asset tmpAsset;
        tmpAsset.hostName = asset;
        Q_FOREACH(QListWidgetItem *i, ui->lstSTIGs->selectedItems())
        {
            a->AddSTIG(i->data(Qt::UserRole).value<STIG>());
        }
        a->AddAsset(tmpAsset);

        ConnectThreads(a)->start();
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

    if (fileNames.isEmpty())
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileNames[0]).absolutePath());

    DisableInput();
    _updatedSTIGs = true;
    auto *s = new WorkerSTIGAdd();
    s->AddSTIGs(fileNames);
    s->SetEnableSupplements(ui->cbIncludeSupplements->isChecked());

    ConnectThreads(s)->start();
}

/**
 * @brief STIGQter::CheckVersion
 *
 * Check for latest version of STIGQter
 */
void STIGQter::CheckVersion()
{
    auto *c = new WorkerCheckVersion();
    ConnectThreads(c, false)->start(); //WorkerCheckVersion()
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
        auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(j));
        if (tmpTabView)
            tmpTabView->SetTabIndex(j);
    }
    DisplayAssets();
}

/**
 * @brief STIGQter::DeleteAssets
 *
 * Deletes the selected @a Asset and closes its tab.
 */
void STIGQter::DeleteAssets()
{
    QList<int> toClose;
    QVector<Asset> toDelete;
    _updatedAssets = true;
    Q_FOREACH(QListWidgetItem *i, ui->lstAssets->selectedItems())
    {
        auto a = i->data(Qt::UserRole).value<Asset>();
        toDelete.append(a);
        QString assetName = PrintAsset(a);
        for (int j = 0; j < ui->tabDB->count(); j++)
        {
             if (ui->tabDB->tabText(j) == assetName)
             {
                 toClose.append(j);
             }
        }
    }
    QList<int>::const_iterator it = toClose.constEnd();
    while (it != toClose.constBegin())
    {
        --it;
        ui->tabDB->removeTab(*it);
    }

    auto *s = new WorkerAssetDelete();
    s->AddAssets(toDelete);

    ConnectThreads(s)->start();
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
    auto *c = new WorkerCCIDelete();

    ConnectThreads(c)->start();
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

    auto *s = new WorkerSTIGDelete();
    Q_FOREACH (QListWidgetItem *i, ui->lstSTIGs->selectedItems())
    {
        STIG stig = i->data(Qt::UserRole).value<STIG>();
        s->AddId(stig.id);
    }

    ConnectThreads(s)->start();
}

/**
 * @brief STIGQter::Display
 *
 * Trigger updating the data elements on the page.
 */
void STIGQter::Display()
{
    EnableInput();
    DisplayCCIs();
    DisplaySTIGs();
    DisplayAssets();
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
    auto *s = new WorkerSTIGDownload();
    s->SetEnableSupplements(ui->cbIncludeSupplements->isChecked());

    ConnectThreads(s)->start();
}

/**
 * @brief STIGQter::EditSTIG
 *
 * Opens the selected STIG(s) for editing
 */
void STIGQter::EditSTIG()
{
    //set the index to the last STIG opened, or remain on main screen if none opened
    int currentIndex = ui->tabDB->currentIndex();

    //buffer the STIGs before opening them
    QVector<STIG> stigs;
    Q_FOREACH(QListWidgetItem *i, ui->lstSTIGs->selectedItems())
    {
        stigs.append(i->data(Qt::UserRole).value<STIG>());
    }

    //open each buffered STIG
    Q_FOREACH(STIG s, stigs)
    {
        QString stigName = PrintSTIG(s);
        for (int j = 0; j < ui->tabDB->count(); j++)
        {
             if (ui->tabDB->tabText(j) == stigName)
             {
                 ui->tabDB->setCurrentIndex(j);
                 return;
             }
        }
        auto *se = new STIGEdit(s, this);
        int index = ui->tabDB->addTab(se, stigName);
        se->SetTabIndex(index);
        currentIndex = index;
    }

    //open the last created tab to edit
    ui->tabDB->setCurrentIndex(currentIndex);
}

/**
 * @brief STIGQter::ExportCKLs
 * @param dir
 *
 * Export all possible .ckl files into the selected directory.
 */
void STIGQter::ExportCKLs(const QString &dir)
{
    DbManager db;
    QString dirName = !dir.isEmpty() ? dir : QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *f = new WorkerCKLExport();
        f->SetExportDir(dirName);
        f->SetMonolithic(false);

        ConnectThreads(f)->start();
    }
}

/**
 * @brief STIGQter::ExportCKLsMonolithic
 * @param dir
 *
 * Export all possible .ckl files into the selected directory.
 */
void STIGQter::ExportCKLsMonolithic(const QString &dir)
{
    DbManager db;
    QString dirName = !dir.isEmpty() ? dir : QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *f = new WorkerCKLExport();
        f->SetExportDir(dirName);
        f->SetMonolithic(true);

        ConnectThreads(f)->start();
    }
}

/**
 * @brief STIGQter::ExportCMRS
 *
 * Generate a CMRS report of the findings.
 */
void STIGQter::ExportCMRS(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getSaveFileName(this, QStringLiteral("Save CMRS Report"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("CMRS XML (*.xml)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    auto *f = new WorkerCMRSExport();
    f->SetExportPath(fn);

    ConnectThreads(f)->start();
}

/**
 * @brief STIGQter::ExportEMASS
 *
 * Create an eMASS Test Result Import workbook.
 */
void STIGQter::ExportEMASS(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getSaveFileName(this, QStringLiteral("Save eMASS Report"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Microsoft Excel (*.xlsx)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    auto *f = new WorkerEMASSReport();
    f->SetReportName(fn);

    ConnectThreads(f)->start();
}

/**
 * @brief STIGQter::ExportHTML
 *
 * Instantiates an instance of WorkerHTML to export the HTML
 * templates for the manual STIG lists.
 */
void STIGQter::ExportHTML(const QString &dir)
{
    DbManager db;
    QString dirName = !dir.isNull() ? dir : QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *f = new WorkerHTML();
        f->SetDir(dirName);

        ConnectThreads(f)->start();
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
void STIGQter::FindingsReport(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getSaveFileName(this,
        QStringLiteral("Save Detailed Findings"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Microsoft Excel (*.xlsx)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    DisableInput();
    auto *f = new WorkerFindingsReport();
    f->SetReportName(fn);

    ConnectThreads(f)->start();
}

/**
 * @brief STIGQter::ImportCKLs
 *
 * Import existing CKL files (potentially from STIG Viewer or old
 * versions of STIG Qter).
 */
void STIGQter::ImportCKLs(const QStringList &fileNames)
{
    DbManager db;
    QStringList fn = !fileNames.isEmpty() ? fileNames : QFileDialog::getOpenFileNames(this,
        QStringLiteral("Import CKL(s)"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIG Checklist (*.ckl)"));

    if (fn.isEmpty())
        return; // cancel button pressed

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn[0]).absolutePath());
    DisableInput();
    _updatedSTIGs = true;
    _updatedAssets = true;
    auto *c = new WorkerCKLImport();
    c->AddCKLs(fn);

    ConnectThreads(c)->start();
}

/**
 * @brief STIGQter::ImportEMASS
 *
 * Import an existing Test Result Import spreadsheet.
 */
void STIGQter::ImportEMASS(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getOpenFileName(this,
        QStringLiteral("Import eMASS TRExport"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Excel Spreadsheet (*.xlsx)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    auto *c = new WorkerImportEMASS();
    c->SetReportName(fn);

    ConnectThreads(c)->start();
}

/**
 * @brief STIGQter::ImportEmassControl
 *
 * Import an existing Test Result Import spreadsheet.
 */
void STIGQter::ImportEmassControl(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getOpenFileName(this,
        QStringLiteral("Import eMASS ControlInfoExport"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("Excel Spreadsheet (*.xlsx)"));

    if (fn.isNull() || fn.isEmpty())
        return; // cancel button pressed

    DisableInput();
    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());
    auto *c = new WorkerImportEMASSControl();
    c->SetReportName(fn);

    ConnectThreads(c)->start();
}

/**
 * @brief STIGQter::Load
 *
 * The user is prompted for the *.stigqter file to load.
 */
void STIGQter::Load(const QString &fileName)
{
    DbManager db;
    QString fn = !fileName.isEmpty() ? fileName : QFileDialog::getOpenFileName(this,
        QStringLiteral("Open STIGQter Save File"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIGQter Save File (*.stigqter)"));

    if (!fn.isNull() && !fn.isEmpty())
    {
        while (ui->tabDB->count() > 1)
            ui->tabDB->removeTab(1);
        db.LoadDB(fn);
        EnableInput();
        DisplayCCIs();
        DisplaySTIGs();
        DisplayAssets();
        lastSaveLocation = fn;
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
    DbManager db;
    QVector<CCI> ccis = db.GetRemapCCIs();
    QString cciStr = QString();
    Q_FOREACH (CCI c, ccis)
    {
        if (!cciStr.isEmpty())
            cciStr = cciStr + ", ";
        cciStr = cciStr + PrintCCI(c);
    }
    QMessageBox::StandardButton reply = confirm ? QMessageBox::Yes : QMessageBox::question(this, QStringLiteral("Non-Standard CKLs"), QStringLiteral("This feature will map all unmapped STIG checks, STIG checks from other system categorizations, and incorrectly mapped STIG checks to ") + cciStr + QStringLiteral(". CKL files generated will no longer be consistent with STIGViewer and other tools. Are you sure you want to proceed?"), QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DisableInput();
        _updatedCCIs = true;

        //Create thread to download CCIs and keep GUI active
        auto *c = new WorkerMapUnmapped();

        ConnectThreads(c)->start();
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
    ui->btnCreateCKL->setEnabled(!ui->lstSTIGs->selectedItems().isEmpty());
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
 * @brief STIGQter::SupplementsChanged
 * @param checkState
 *
 * Handle when the user wants to index STIG supplementary data or not
 */
void STIGQter::SupplementsChanged(int checkState)
{
    DbManager db;
    db.UpdateVariable(QStringLiteral("indexSupplements"), checkState == Qt::Checked ? QStringLiteral("y") : QStringLiteral("n"));
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
    QVector<Family> f = db.GetFamilies();
    QVector<STIG> s = db.GetSTIGs();
    bool stigsNotImported = s.isEmpty();
    bool isImport = db.IsEmassImport();

    ui->btnImportEmass->setEnabled(!isImport);
    ui->txtMarking->setEnabled(true);

    if (f.isEmpty())
    {
        ui->btnClearCCIs->setEnabled(false);
        ui->btnDownloadSTIGs->setEnabled(false);
        ui->btnImportEmass->setEnabled(false);
        ui->btnImportCCIs->setEnabled(true);
        ui->btnImportSTIGs->setEnabled(false);
        ui->btnImportEmassControl->setEnabled(false);
    }
    else
    {
        //disable deleting CCIs if STIGs have been imported
        ui->btnClearCCIs->setEnabled(stigsNotImported);
        ui->btnDownloadSTIGs->setEnabled(stigsNotImported);
        ui->btnImportCCIs->setEnabled(false);
        ui->btnImportSTIGs->setEnabled(true);
        ui->btnImportEmassControl->setEnabled(true);
    }

    ui->btnClearSTIGs->setEnabled(true);
    ui->btnEditSTIG->setEnabled(true);
    ui->btnCreateCKL->setEnabled(true);
    ui->btnDeleteEmassImport->setEnabled(isImport);
    ui->btnImportCKL->setEnabled(true);
    ui->btnMapUnmapped->setEnabled(isImport);
    ui->cbIncludeSupplements->setEnabled(true);
    ui->cbRemapCM6->setEnabled(true);
    ui->btnOpenCKL->setEnabled(!ui->lstAssets->selectedItems().isEmpty());
    ui->btnQuit->setEnabled(true);
    ui->menubar->setEnabled(true);
    ui->txtSTIGSearch->setEnabled(true);
    ui->tabDB->setEnabled(true);
    for (int i = 1; i < ui->tabDB->count(); i++)
    {
        auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(i));
        if (tmpTabView)
            tmpTabView->EnableInput();
    }
    SelectSTIG();
}

/**
 * @brief STIGQter::UpdateRemapButton
 *
 * Change the text of the remap button to reflect if STIG checks are being
 * remapped to CM-6 or CCI-366.
 */
void STIGQter::UpdateRemapButton()
{
    ui->btnMapUnmapped->setText(ui->cbRemapCM6->isChecked() ? QStringLiteral("Remap CM-6") : QStringLiteral("Remap CCI-366"));
    ui->btnMapUnmapped->setToolTip(ui->btnMapUnmapped->text());
}

/**
 * @brief STIGQter::UpdateSTIGs
 *
 * Update the display of STIGs available in the database.
 */
void STIGQter::UpdateSTIGs()
{
    ui->lstCKLs->clear();
    QList<STIG> addedStigs;
    Q_FOREACH (QListWidgetItem *i, ui->lstAssets->selectedItems())
    {
        auto a = i->data(Qt::UserRole).value<Asset>();
        Q_FOREACH (const STIG &s, a.GetSTIGs())
        {
            if (!addedStigs.contains(s))
            {
                ui->lstCKLs->addItem(PrintSTIG(s));
                addedStigs.append(s);
            }
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
    ui->txtMarking->setEnabled(false);
    ui->btnClearCCIs->setEnabled(false);
    ui->btnClearSTIGs->setEnabled(false);
    ui->btnCreateCKL->setEnabled(false);
    ui->btnDeleteEmassImport->setEnabled(false);
    ui->btnDownloadSTIGs->setEnabled(false);
    ui->btnEditSTIG->setEnabled(false);
    ui->btnImportCCIs->setEnabled(false);
    ui->btnImportCKL->setEnabled(false);
    ui->btnImportEmass->setEnabled(false);
    ui->btnImportEmassControl->setEnabled(false);
    ui->btnImportSTIGs->setEnabled(false);
    ui->btnMapUnmapped->setEnabled(false);
    ui->cbIncludeSupplements->setEnabled(false);
    ui->cbRemapCM6->setEnabled(false);
    ui->btnOpenCKL->setEnabled(false);
    ui->btnQuit->setEnabled(false);
    ui->menubar->setEnabled(false);
    ui->txtSTIGSearch->setEnabled(false);
    ui->tabDB->setEnabled(false);
    for (int i = 1; i < ui->tabDB->count(); i++)
    {
        auto *tmpTabView = dynamic_cast<TabViewWidget*>(ui->tabDB->widget(i));
        if (tmpTabView)
            tmpTabView->DisableInput();
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
        tmpItem->setText(PrintControl(c.GetControl()).leftJustified(10, ' ') + PrintCCI(c));
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
