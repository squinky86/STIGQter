#ifndef WORKERSTIGADD_H
#define WORKERSTIGADD_H

#include <QObject>

class WorkerSTIGAdd : public QObject
{
    Q_OBJECT

private:
    QStringList _todo;

public:
    explicit WorkerSTIGAdd(QObject *parent = nullptr);
    void AddSTIGs(QStringList stigs);

public slots:
    void process();

signals:
    void initialize(int, int);
    void progress(int);
    void updateStatus(QString);
    void finished();
};

#endif // WORKERSTIGADD_H
