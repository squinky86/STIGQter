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

#include "common.h"
#include "stigqter.h"
#include "workercciadd.h"
#include "workerccidelete.h"
#include "ui_stigqter.h"
#include "help.h"
#include "workerstigadd.h"
#include "workerstigdelete.h"
#include "workerassetadd.h"
#include "workercklimport.h"

#include <QThread>
#include <QDebug>
#include <QFileDialog>
#include <QInputDialog>

STIGQter::STIGQter(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::STIGQter),
    db(new DbManager),
    _updatedAssets(false),
    _updatedCCIs(false),
    _updatedSTIGs(false)
{
    ui->setupUi(this);
    this->setWindowTitle(QString("STIGQter ") + QString(VERSION));
    EnableInput();
    DisplayCCIs();
    DisplaySTIGs();
    DisplayAssets();
}

STIGQter::~STIGQter()
{
    CleanThreads();
    delete db;
    delete ui;

}

void STIGQter::UpdateCCIs()
{
    DisableInput();
    _updatedCCIs = true;

    //Create thread to download CCIs and keep GUI active
    QThread* t = new QThread;
    WorkerCCIAdd *c = new WorkerCCIAdd();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

void STIGQter::CleanThreads()
{
    while (!threads.isEmpty())
    {
        QThread *t = threads.takeFirst();
        t->wait();
        delete t;
    }
    foreach (const QObject *o, workers)
    {
        delete o;
    }
    workers.clear();
}

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

void STIGQter::About()
{
    Help *h = new Help();
    h->setAttribute(Qt::WA_DeleteOnClose); //clean up after itself (no explicit "delete" needed)
    h->show();
}

void STIGQter::AddAsset()
{
    bool ok;
    QString asset = QInputDialog::getText(this, tr("Enter Asset Name"),
                                          tr("Asset:"), QLineEdit::Normal,
                                          QDir::home().dirName(), &ok);
    if (ok)
    {
        DisableInput();
        _updatedAssets = true;
        QThread* t = new QThread;
        WorkerAssetAdd *a = new WorkerAssetAdd();
        Asset tmpAsset;
        tmpAsset.hostName = asset;
        foreach(QListWidgetItem *i, ui->lstSTIGs->selectedItems())
        {
            a->AddSTIG(i->data(Qt::UserRole).value<STIG>());
        }
        a->AddAsset(tmpAsset);
        connect(t, SIGNAL(started()), a, SLOT(process()));
        connect(a, SIGNAL(finished()), t, SLOT(quit()));
        connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
        connect(a, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
        connect(a, SIGNAL(progress(int)), this, SLOT(Progress(int)));
        connect(a, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
        threads.append(t);
        workers.append(a);

        t->start();
    }
}

void STIGQter::AddSTIGs()
{
    QStringList fileNames = QFileDialog::getOpenFileNames(this,
        "Open STIG", QDir::home().dirName(), "Compressed STIG (*.zip)");
    DisableInput();
    _updatedSTIGs = true;
    QThread* t = new QThread;
    WorkerSTIGAdd *s = new WorkerSTIGAdd();
    s->AddSTIGs(fileNames);
    connect(t, SIGNAL(started()), s, SLOT(process()));
    connect(s, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(s, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(s, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(s, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
    threads.append(t);
    workers.append(s);

    t->start();
}

void STIGQter::DeleteCCIs()
{
    DisableInput();
    _updatedCCIs = true;

    //Create thread to download CCIs and keep GUI active
    QThread* t = new QThread;
    WorkerCCIDelete *c = new WorkerCCIDelete();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

void STIGQter::DeleteSTIGs()
{
    DisableInput();
    _updatedSTIGs = true;

    //Create thread to download CCIs and keep GUI active
    QThread* t = new QThread;
    WorkerSTIGDelete *s = new WorkerSTIGDelete();
    foreach (QListWidgetItem *i, ui->lstSTIGs->selectedItems())
    {
        STIG s = i->data(Qt::UserRole).value<STIG>();
        db->DeleteSTIG(s);
    }
    s->moveToThread(t);
    connect(t, SIGNAL(started()), s, SLOT(process()));
    connect(s, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(s, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(s, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(s, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
    threads.append(t);
    workers.append(s);

    t->start();
}

void STIGQter::ImportCKLs()
{
    QStringList fileNames = QFileDialog::getOpenFileNames(this,
        "Import CKL(s)", QDir::home().dirName(), "STIG Checklist (*.ckl)");
    DisableInput();
    _updatedAssets = true;
    QThread* t = new QThread;
    WorkerCKLImport *c = new WorkerCKLImport();
    c->AddCKLs(fileNames);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(c, SIGNAL(finished()), t, SLOT(quit()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    connect(c, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString)));
    threads.append(t);
    workers.append(c);

    t->start();
}

void STIGQter::SelectSTIG()
{
    //select STIGs to create checklists
    ui->btnCreateCKL->setEnabled(ui->lstSTIGs->selectedItems().count() > 0);
}

void STIGQter::EnableInput()
{
    QList<Family> f = db->GetFamilies();
    QList<STIG> s = db->GetSTIGs();
    if (f.count() > 0)
    {
        //disable deleting CCIs if STIGs have been imported
        ui->btnClearCCIs->setEnabled(s.count() <= 0);
        ui->btnImportCCIs->setEnabled(false);
    }
    else
    {
        ui->btnClearCCIs->setEnabled(false);
        ui->btnImportCCIs->setEnabled(true);
    }
    ui->btnClearSTIGs->setEnabled(true);
    ui->btnCreateCKL->setEnabled(true);
    ui->btnFindingsReport->setEnabled(true);
    ui->btnImportCKL->setEnabled(true);
    ui->btnImportSTIGs->setEnabled(true);
    ui->btnOpenCKL->setEnabled(true);
    ui->btnQuit->setEnabled(true);
    ui->menubar->setEnabled(true);
    SelectSTIG();
}

void STIGQter::Initialize(int max, int val)
{
    ui->progressBar->reset();
    ui->progressBar->setMaximum(max);
    ui->progressBar->setValue(val);
}

void STIGQter::Progress(int val)
{
    if (val < 0)
    {
        ui->progressBar->setValue(ui->progressBar->value() + 1);
    }
    else
        ui->progressBar->setValue(val);
}

void STIGQter::DisableInput()
{
    ui->btnClearCCIs->setEnabled(false);
    ui->btnClearSTIGs->setEnabled(false);
    ui->btnCreateCKL->setEnabled(false);
    ui->btnFindingsReport->setEnabled(false);
    ui->btnImportCCIs->setEnabled(false);
    ui->btnImportCKL->setEnabled(false);
    ui->btnImportSTIGs->setEnabled(false);
    ui->btnOpenCKL->setEnabled(false);
    ui->btnQuit->setEnabled(false);
    ui->menubar->setEnabled(false);
}

void STIGQter::DisplayAssets()
{
    ui->lstAssets->clear();
    foreach(const Asset &a, db->GetAssets())
    {
        QListWidgetItem *tmpItem = new QListWidgetItem(); //memory managed by ui->lstAssets container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<Asset>(a));
        tmpItem->setText(PrintAsset(a));
        ui->lstAssets->addItem(tmpItem);
    }
}

void STIGQter::DisplayCCIs()
{
    ui->lstCCIs->clear();
    foreach(const CCI &c, db->GetCCIs())
    {
        CCI tmpCci = c;
        QListWidgetItem *tmpItem = new QListWidgetItem(); //memory managed by ui->lstCCIs container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<CCI>(tmpCci));
        tmpItem->setText(PrintControl(tmpCci.Control()) + " " + PrintCCI(tmpCci));
        ui->lstCCIs->addItem(tmpItem);
    }
}

void STIGQter::DisplaySTIGs()
{
    ui->lstSTIGs->clear();
    foreach(const STIG &s, db->GetSTIGs())
    {
        QListWidgetItem *tmpItem = new QListWidgetItem(); //memory managed by ui->lstSTIGs container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        tmpItem->setText(PrintSTIG(s));
        ui->lstSTIGs->addItem(tmpItem);
    }
}
