/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "tidy.h"
#include "tidybuffio.h"

#include <zip.h>

#include <QEventLoop>
#include <QString>
#include <QtNetwork>

QString CleanXML(QString s, bool isXml)
{
    TidyBuffer output = {nullptr};
    TidyBuffer err = {nullptr};

    int rc = -1;
    TidyDoc tdoc = tidyCreate();
    bool ok = tidyOptSetBool(tdoc, TidyXmlOut, yes);

    if (isXml)
        ok = ok && tidyOptSetBool(tdoc, TidyXmlTags, yes);
    if (ok)
        rc = tidySetErrorBuffer(tdoc, &err);
    if (rc >= 0)
        rc = tidyParseString(tdoc, s.toStdString().c_str());
    if (rc >= 0)
        rc = tidyCleanAndRepair(tdoc);
    if (rc >= 0)
        rc = tidyRunDiagnostics(tdoc);
    if (rc > 1)
        rc = (tidyOptSetBool(tdoc, TidyForceOutput, yes) ? rc : -1);
    if (rc >= 0)
        rc = tidySaveBuffer(tdoc, &output);
    if (rc >= 0 && (output.bp))
    {
        s = QString::fromUtf8(reinterpret_cast<char*>(output.bp));
    }
    else
        qDebug() << "A severe error (" << rc << ") occurred.";

    tidyBufFree(&output);
    tidyBufFree(&err);
    tidyRelease(tdoc);

    QString ret(s);
    ret = ret.replace("&nbsp;", " ");
    return ret;
}

bool DownloadFile(const QUrl &u, QFile *f)
{
    bool close = false;
    if (!f->isOpen())
    {
        f->open(QIODevice::WriteOnly);
        if (!f->isOpen())
            return false;
        close = true;
    }
    QNetworkAccessManager manager;
    QNetworkRequest req = QNetworkRequest(u);
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QString userAgent = QString("STIGQter/") + VERSION;
    req.setRawHeader("User-Agent", userAgent.toStdString().c_str());
    QNetworkReply *response = manager.get(req);
    QEventLoop event;
    QObject::connect(response,SIGNAL(finished()),&event,SLOT(quit()));
    event.exec();
    QByteArray tmpArray = response->readAll();
    f->write(tmpArray, tmpArray.size());
    f->flush();
    delete response;

    if (close)
        f->close();
    else
        f->seek(0);
    return true;
}

QString DownloadPage(const QUrl &u)
{
    QNetworkAccessManager manager;
    QNetworkRequest req = QNetworkRequest(QUrl(u));
    QString userAgent = QString("STIGQter/") + VERSION;
    req.setRawHeader("User-Agent", userAgent.toStdString().c_str());
    QNetworkReply *response = manager.get(req);
    QEventLoop event;
    QObject::connect(response,SIGNAL(finished()),&event,SLOT(quit()));
    event.exec();
    QString html = response->readAll();
    delete response;
    return html;
}

//extract a .zip file and store the contents in memory
//fileNameFilter is a case-insensitive end-of-filename search
QMap<QString, QByteArray> GetFilesFromZip(const QString &fileName, QString fileNameFilter)
{
    QMap<QString, QByteArray> ret;
    struct zip *za;
    int err;
    struct zip_stat sb;
    zip_stat_init(&sb); //initializes sb
    za = zip_open(fileName.toStdString().c_str(), 0, &err);
    if (za != nullptr)
    {
        for (unsigned int i = 0; i < zip_get_num_entries(za, 0); i++)
        {
            if (zip_stat_index(za, i, 0, &sb) == 0)
            {
                QString name(sb.name);
                if (!fileNameFilter.isNull() && !fileNameFilter.isEmpty())
                {
                    if (!name.endsWith(fileNameFilter, Qt::CaseInsensitive))
                    {
                        continue;
                    }
                }

                QString zipName(name);
                QByteArray todo;
                struct zip_file *zf = zip_fopen_index(za, i, 0);
                if (zf)
                {
                    unsigned int sum = 0;
                    while (sum < sb.size)
                    {
                        char buf[1024];
                        zip_int64_t len = zip_fread(zf, static_cast<void*>(buf), 1024);
                        if (len > 0)
                        {
                            todo.append(static_cast<const char*>(buf), static_cast<int>(len));
                            sum += len;
                        }
                    }
                    zip_fclose(zf);
                }
                ret.insert(zipName, todo);
            }
        }
        zip_close(za);
    }
    return ret;
}

int GetCCINumber(QString cci)
{
    cci = cci.trimmed();
    if (cci.startsWith("CCI-"))
        cci = cci.right(cci.length() - 4);
    return cci.toInt();
}

QString Excelify(const QString &s)
{
    //Excel is limited to 32,767 characters per-cell
    QString ret = s.left(32767);
    return ret;
}

QString PrintTrueFalse(bool tf)
{
    return tf ? "true" : "false";
}

QString TrimFileName(const QString &fileName)
{
    QString tmpFileName(fileName);
    if (tmpFileName.contains('/'))
    {
        tmpFileName = tmpFileName.right(tmpFileName.length() - tmpFileName.lastIndexOf('/') - 1);
    }
    return tmpFileName;
}
