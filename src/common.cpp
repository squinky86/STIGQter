/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
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
#include "dbmanager.h"
#include "tidy.h"
#include "tidybuffio.h"

#include <zip.h>

#include <QApplication>
#include <QDebug>
#include <QEventLoop>
#include <QtGlobal>
#include <QMessageBox>
#include <QString>
#include <QtNetwork>

/**
 * @brief MessageHandler
 * @param type
 * @param context
 * @param msg
 *
 * Logging of Qt messages occurs here. Set the LogLevel to 6 for full
 * debugging. Default is LogLevel 5.
 */
void MessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    int severity = 0;
    switch (type)
    {
    case QtDebugMsg:
        severity = 5;
        break;
    case QtInfoMsg:
        severity = 4;
        break;
    case QtWarningMsg:
        severity = 3;
        break;
    case QtCriticalMsg:
        severity = 2;
        break;
    case QtFatalMsg:
        severity = 1;
        break;
    //should not be any other types; "default" is for scenarios where new types are added later.
    //[[unlikely]] - uncomment when moving to >=Qt 5.14 and C++20
    default:
        severity = 0;
        break;
    }
    DbManager db;
    db.Log(severity, context.file + QStringLiteral(":") + QString::number(context.line) + QStringLiteral(" ") + context.function, msg);
}

/**
 * @brief CleanXML
 * @param s
 * @param isXml
 * @return The Tidy'd, well-formed XML.
 *
 * This function comes from Tidy's documentation and has been
 * slightly modified. For more information, see
 * @l {http://api.html-tidy.org/tidy/tidylib_api_5.1.25/group__Basic.html#details} {Tidy's documentation}
 */
QString CleanXML(QString s, bool isXml)
{
    TidyBuffer output;
    tidyBufInit(&output);
    TidyBuffer err;
    tidyBufInit(&err);

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
        qDebug() << "A severe error (" << rc << ") occurred in tidying the XML.";

    tidyBufFree(&output);
    tidyBufFree(&err);
    tidyRelease(tdoc);

    QString ret(s);
    ret = ret.replace(QStringLiteral("&nbsp;"), QStringLiteral(" "));
    return ret;
}

/**
 * @brief DownloadFile
 * @param url
 * @param file
 * @return @c True when the file is successfully downloaded.
 * Otherwise, @c false.
 *
 * Given a @a url, the contents of that URL are written to the handle
 * supplied in the @a file parameter.
 */
bool DownloadFile(const QUrl &url, QFile *file)
{
    bool close = false;

    //check if the file is currently open
    if (!file->isOpen())
    {
        file->open(QIODevice::WriteOnly);
        if (!file->isOpen())
            return false;
        close = true;
    }
    QNetworkAccessManager manager;
    QNetworkRequest req = QNetworkRequest(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    //set the User-Agent so that this program appears in logs correctly
    QString userAgent = GetUserAgent();
    req.setRawHeader("User-Agent", userAgent.toStdString().c_str());

    auto addresses = QHostInfo::fromName(url.host()).addresses();
    if (addresses.count() > 0)
    {
        //log HTTP headers, STIG Rule SV-83997r1_rule
        //log IP address, STIG Rule SV-84045r1_rule
        Warning(QStringLiteral("Downloading File"), "Downloading " + url.toString() + " (ip address " + addresses.first().toString() + ") with header User-Agent: " + userAgent, true);

        //clean up the socket event when the response is finished reading
        QNetworkReply *response = manager.get(req);
        QEventLoop event;
        QObject::connect(response,SIGNAL(finished()),&event,SLOT(quit()));
        event.exec();

        //read entire contents to memory before saving it to the file
        QByteArray tmpArray = response->readAll();

        //save contents of the response to the file
        file->write(tmpArray, tmpArray.size());
        file->flush();
        delete response;

        /*
         * If the file was already open, seek back to the beginning of
         * the file. Otherwise, close it. This preserves the state of the
         * file before this function ran.
         */
        if (close)
            file->close();
        else
            file->seek(0);

        return true;
    }

    if (close)
        file->close();
    else
        file->seek(0);

    return false;
}

/**
 * @brief DownloadPage
 * @param url
 * @return A string of the downloaded page.
 *
 * Downloads the text from the requested @a url.
 */
QString DownloadPage(const QUrl &url)
{
    QNetworkAccessManager manager;
    QNetworkRequest req = QNetworkRequest(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    //set the User-Agent so that this program appears in logs correctly
    QString userAgent = GetUserAgent();
    req.setRawHeader("User-Agent", userAgent.toStdString().c_str());

    auto addresses = QHostInfo::fromName(url.host()).addresses();
    if (addresses.count() > 0)
    {
        //log HTTP headers, STIG Rule SV-222447r508029_rule
        //log IP address, STIG Rule SV-222448r508029_rule
        Warning(QStringLiteral("Downloading Page"), "Downloading " + url.toString() + " (ip address " + addresses.first().toString() + ") with header User-Agent: " + userAgent, true);

        //send request and get response
        QNetworkReply *response = manager.get(req);

        //clean up the socket event when the response is finished reading
        QEventLoop event;
        QObject::connect(response,SIGNAL(finished()),&event,SLOT(quit()));
        event.exec();

        //read the response and return its contents
        QString html = QString::fromLatin1(response->readAll());
        delete response;
        return html;
    }
    return QString(); // unable to download
}

/**
 * @brief GetCCINumber
 * @param cci
 * @return The numeric value of the CCI.
 *
 * Converts a string "CCI-######" to its integral format.
 */
int GetCCINumber(QString cci)
{
    cci = cci.trimmed();
    if (cci.startsWith(QStringLiteral("CCI-")))
        cci = cci.right(cci.length() - 4);
    return cci.toInt();
}

/**
 * @brief GetFilesFromZip
 * @param fileName
 * @param fileNameFilter
 * @return A map of the extracted files in the zip.
 *
 * Extracts a zip file and stores the contents in memory.
 *
 * When fileNameFilter is set, only the files that end with the
 * provided filter are extracted and returned (case-insensitive).
 */
QMap<QString, QByteArray> GetFilesFromZip(const QString &fileName, const QString &fileNameFilter)
{
    //map to return
    QMap<QString, QByteArray> ret;

    //open the zip with libzip
    struct zip *za;
    int err;
    struct zip_stat sb;
    zip_stat_init(&sb); //initializes sb
    za = zip_open(fileName.toStdString().c_str(), 0, &err);
    if (za != nullptr)
    {
        //cycle through each zip file entry
        for (unsigned int i = 0; i < zip_get_num_entries(za, 0); i++)
        {
            if (zip_stat_index(za, i, 0, &sb) == 0)
            {
                //zip bomb protection
                //if file is > 1GB extracted, do not read it
                if (sb.size > 4294967295)
                    continue;

                QString name(QString::fromLatin1(sb.name));
                if (!fileNameFilter.isNull() && !fileNameFilter.isEmpty() && !name.endsWith(fileNameFilter, Qt::CaseInsensitive))
                {
                    continue;
                }

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
                ret.insert(name, todo);
            }
        }
        zip_close(za);
    }
    return ret;
}

/**
 * @brief GetReleaseNumber
 * @param release
 * @return The release number from a STIG release string
 */
int GetReleaseNumber(const QString &release)
{
    int ret = -1;
    QStringList rel = release.split(' ');
    if (rel.size() > 1)
    {
        return rel[1].toInt();
    }
    return ret;
}

/**
 * @brief GetUserAgent
 * @return The User-Agent to use when making web requests.
 */
QString GetUserAgent()
{
    return QString(QStringLiteral("STIGQter/")) + VERSION;
}

/**
 * @brief Excelify
 * @param s
 * @return The string @a s formatted in a way that Excel can
 * understand.
 */
QString Excelify(const QString &s)
{
    //Excel is limited to 32,767 characters per-cell
    QString ret = s.left(32767);
    return ret;
}

/**
 * @brief Pluralize
 * @param count
 * @param plural
 * @param singular
 * @return @c @a plural when @a count indicates that plural usage is
 * appropriate. Otherwise, @c @a singular.
 */
QString Pluralize(const int count, const QString &plural, const QString &singular)
{
    return (count == 1) ? singular : plural;
}

/**
 * @brief PrintTrueFalse
 * @param tf
 * @return human-readable boolean.
 */
QString PrintTrueFalse(bool tf)
{
    return tf ? QStringLiteral("true") : QStringLiteral("false");
}

QString Sanitize(QString s)
{
    s = s.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    s = s.replace(QStringLiteral("\n"), QStringLiteral(" "));
    return s;
}

QString SanitizeFile(QString s)
{
    //UTF replacements have trouble with QStrings
    s = s.replace(QStringLiteral("/"), QStringLiteral(" ̸"));
    s = s.replace(QStringLiteral("\\"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("?"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("*"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("\""), QStringLiteral("-"));
    s = s.replace(QStringLiteral("<"), QStringLiteral("-"));
    s = s.replace(QStringLiteral(">"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("|"), QStringLiteral("-"));
    s = s.replace(QStringLiteral(":"), QStringLiteral("-"));
    return s;
}

/**
 * @brief TrimFileName
 * @param fileName
 * @return The fileName without any leading directory structure.
 */
QString TrimFileName(const QString &fileName)
{
    QString tmpFileName(fileName);
    if (tmpFileName.contains('/'))
    {
        tmpFileName = tmpFileName.right(tmpFileName.length() - tmpFileName.lastIndexOf('/') - 1);
    }
    return tmpFileName;
}

/**
 * @brief Warning
 * @param title
 * @param message
 * @param quiet
 * @param level
 *
 * When @a quiet is not @c true, displays a warning box with the
 * provided @a title and @a message. The title and message are always
 * printed on the console/debug log.
 */
void Warning(const QString &title, const QString &message, const bool quiet, const int level)
{
    DbManager db;
    db.Log(level, QString(), title + ": " + message);
    if (!IgnoreWarnings && !quiet && (QThread::currentThread() == QApplication::instance()->thread())) //make sure we're in the GUI thread before popping a message box
    {
        int ret = QMessageBox::warning(nullptr, title, message, QMessageBox::Ignore | QMessageBox::Ok);
        //if ignoring messages, move to quiet mode
        if (ret == QMessageBox::Ignore)
        {
            IgnoreWarnings = true;
        }
    }
}
