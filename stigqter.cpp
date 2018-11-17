#include "ccithread.h"
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
    CCIThread *t = new CCIThread(db);
    connect(t, SIGNAL(finished()), this, SLOT(CompletedThread()));
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
