#include "workerstigadd.h"
#include "dbmanager.h"

WorkerSTIGAdd::WorkerSTIGAdd(QObject *parent) : QObject(parent)
{

}

void WorkerSTIGAdd::AddSTIGs(QStringList stigs)
{
    _todo = stigs;
}

void WorkerSTIGAdd::process()
{
    emit initialize(_todo.count(), 0);
    foreach(const QString s, _todo)
    {
        updateStatus("Extracting " + s + "…");
        //TODO: extract zip
        updateStatus("Parsing " + s + "…");
        //TODO: parse extracted XML
        emit progress(-1);
    }
    emit updateStatus("Done!");
    emit finished();
}
