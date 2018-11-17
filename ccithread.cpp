#include "ccithread.h"
#include "common.h"

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

CCIThread::CCIThread(DbManager *db) : _db(db)
{
}

void CCIThread::run()
{
    //populate CCIs
    QUrl nist("https://nvd.nist.gov/800-53/Rev4/");
    //TODO: download Families
    QString rmf = DownloadPage(nist);

    //read the families into "rmf"
    qDebug() << QDir::currentPath();
    qDebug() << rmf;

    //TODO: download Controls
    //TODO: download CCIs
    //complete
}
