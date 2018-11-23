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

#include <QThread>
#include <QDebug>

STIGQter::STIGQter(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::STIGQter),
    db(new DbManager)
{
    ui->setupUi(this);
    this->setWindowTitle(QString("STIGQter ") + QString(VERSION));
    EnableInput();
}

STIGQter::~STIGQter()
{
    CleanThreads();
    if (db)
    {
        delete db;
    }
    if (ui)
        delete ui;

}

void STIGQter::UpdateCCIs()
{
    DisableInput();

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
    ui->progressBar->setValue(ui->progressBar->maximum());
}

void STIGQter::About()
{
    Help *h = new Help();
    h->setAttribute(Qt::WA_DeleteOnClose); //clean up after itself (no explicit "delete" needed)
    h->show();
}

void STIGQter::DeleteCCIs()
{
    DisableInput();

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

void STIGQter::EnableInput()
{
    QList<Family> f = db->GetFamilies();
    if (f.count() > 0)
    {
        ui->btnClearCCIs->setEnabled(true);
        ui->btnImportCCIs->setEnabled(false);
    }
    else
    {
        ui->btnClearCCIs->setEnabled(false);
        ui->btnImportCCIs->setEnabled(true);
    }
    ui->btnClearSTIGs->setEnabled(true);
    ui->btnCreateCKL->setEnabled(true);
    ui->btnDeleteCKL->setEnabled(true);
    ui->btnFindingsReport->setEnabled(true);
    ui->btnImportCKL->setEnabled(true);
    ui->btnImportSTIGs->setEnabled(true);
    ui->btnOpenCKL->setEnabled(true);
    ui->btnQuit->setEnabled(true);
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
    ui->btnDeleteCKL->setEnabled(false);
    ui->btnFindingsReport->setEnabled(false);
    ui->btnImportCCIs->setEnabled(false);
    ui->btnImportCKL->setEnabled(false);
    ui->btnImportSTIGs->setEnabled(false);
    ui->btnOpenCKL->setEnabled(false);
    ui->btnQuit->setEnabled(false);
}
