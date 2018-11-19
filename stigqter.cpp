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

#include "cciworker.h"
#include "stigqter.h"
#include "ui_stigqter.h"

#include <QThread>
#include <QDebug>

STIGQter::STIGQter(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::STIGQter),
    db(new DbManager)
{
    ui->setupUi(this);
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
    CCIWorker *c = new CCIWorker();
    c->moveToThread(t);
    connect(t, SIGNAL(started()), c, SLOT(process()));
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
    connect(c, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int)));
    connect(c, SIGNAL(progress(int)), this, SLOT(Progress(int)));
    threads.append(t);

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
}

void STIGQter::CompletedThread()
{
    EnableInput();
    CleanThreads();
}

void STIGQter::EnableInput()
{
    ui->btnClearCCIs->setEnabled(true);
    ui->btnClearSTIGs->setEnabled(true);
    ui->btnCreateCKL->setEnabled(true);
    ui->btnFindingsReport->setEnabled(true);
    ui->btnImportCCIs->setEnabled(true);
    ui->btnImportCKL->setEnabled(true);
    ui->btnImportSTIGs->setEnabled(true);
    ui->btnOpenCKL->setEnabled(true);
    ui->btnQuit->setEnabled(true);
}

void STIGQter::Initialize(int max, int val)
{
    qDebug() << "Got here " << max << ", " << val;
    ui->progressBar->setMaximum(max);
    ui->progressBar->reset();
    ui->progressBar->setValue(val);
}

void STIGQter::Progress(int val)
{
    qDebug() << "Got here 2 " << val << "(" << ui->progressBar->minimum() << "," << ui->progressBar->maximum() << "," << ui->progressBar->value() << ")";
    if (val < 0)
    {
        ui->progressBar->setValue(ui->progressBar->value() + 1);
    qDebug() << "Got here 3 " << ui->progressBar->value();
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
}
