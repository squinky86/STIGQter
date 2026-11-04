/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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

bool IgnoreWarnings = false;


#include <QApplication>
#include <QDebug>
#include <QFileInfo>
#include <QtGlobal>
#include <QMessageBox>
#include <QRegularExpression>
#include <QString>
#include <QThread>

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
 * @brief GetReleaseNumber
 * @param release
 * @return The release number from a STIG release string
 */
int GetReleaseNumber(const QString &release)
{
    static const QRegularExpression releasePattern(
        QStringLiteral("(?:^|\\b)(?:release\\s*:?|r)\\s*(\\d+)\\b"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = releasePattern.match(release);
    if (!match.hasMatch())
        return -1;

    bool ok = false;
    const int releaseNumber = match.captured(1).toInt(&ok);
    return ok ? releaseNumber : -1;
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
    //STIG Rule SV-222447r508029_rule - Prevent CSV Injection
    if (ret.startsWith('=') || ret.startsWith('+') || ret.startsWith('-') || ret.startsWith('@'))
    {
        ret.prepend('\'');
    }
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
    s = s.replace(QStringLiteral("#"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("%"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("$"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("!"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("{"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("}"), QStringLiteral("-"));
    s = s.replace(QStringLiteral("@"), QStringLiteral("-"));
    return s;
}

/**
 * @brief TrimFileName
 * @param fileName
 * @return The fileName without any leading directory structure.
 */
QString TrimFileName(const QString &fileName)
{
    QFileInfo fi(fileName);
    return fi.fileName();
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
