#include "stigqter.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    STIGQter w;
    w.show();

    return a.exec();
}
