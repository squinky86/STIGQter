#ifndef WORKERSTIGDELETE_H
#define WORKERSTIGDELETE_H

#include <QObject>

class WorkerSTIGDelete : public QObject
{
    Q_OBJECT

private:
    QList<int> _ids;

public:
    explicit WorkerSTIGDelete(QObject *parent = nullptr);
    void AddId(int id);

public slots:
    void process();

signals:
    void initialize(int, int);
    void progress(int);
    void updateStatus(QString);
    void finished();
};

#endif // WORKERSTIGDELETE_H
