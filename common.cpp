#include "common.h"

#include <QEventLoop>
#include <QtNetwork>

QString DownloadPage(QUrl u)
{
    QNetworkAccessManager manager;
    QNetworkReply *response = manager.get(QNetworkRequest(QUrl(u)));
    QEventLoop event;
    QObject::connect(response,SIGNAL(finished()),&event,SLOT(quit()));
    event.exec();
    QString html = response->readAll();
    return html;
}
