#ifndef CCITHREAD_H
#define CCITHREAD_H

#include <QThread>
#include "dbmanager.h"

class CCIThread : public QThread
{
public:
    CCIThread(DbManager *db);

private:
    DbManager *_db;
    void run();
};

#endif // CCITHREAD_H
