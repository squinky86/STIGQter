#include "dbmanager.h"
#include "workerstigdelete.h"

WorkerSTIGDelete::WorkerSTIGDelete(QObject *parent) : QObject(parent)
{

}

void WorkerSTIGDelete::AddId(int id)
{
    _ids.append(id);
}

void WorkerSTIGDelete::process()
{
    //open database in this thread
    emit initialize(2 + _ids.count(), 1);
    DbManager db;

    emit updateStatus("Clearing DB of selected STIG information…");
    foreach (int i, _ids)
    {
        db.DeleteSTIG(i);
    }
    emit progress(-1);

    //complete
    emit updateStatus("Done!");
    emit finished();
}
