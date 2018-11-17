#ifndef STIGQTER_H
#define STIGQTER_H

#include <QMainWindow>

#include "dbmanager.h"

namespace Ui {
class STIGQter;
}

class STIGQter : public QMainWindow
{
    Q_OBJECT

public:
    explicit STIGQter(QWidget *parent = nullptr);
    ~STIGQter();

private slots:
    void UpdateCCIs();
    void CompletedThread();

private:
    Ui::STIGQter *ui;
    DbManager *db;
    QList<QThread *> threads;
    void CleanThreads();
    void DisableInput();
    void EnableInput();
};

#endif // STIGQTER_H
