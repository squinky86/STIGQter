/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef COMMON_H
#define COMMON_H

#include <QByteArrayList>
#include <QFile>
#include <QNetworkReply>

#define VERSION QStringLiteral("1.2.2")

[[maybe_unused]] extern bool IgnoreWarnings;

void MessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);
bool DownloadFile(const QUrl &url, QFile *file);
QString DownloadPage(const QUrl &url);
QString Excelify(const QString &s);
int GetCCINumber(QString cci);
QMap<QString, QByteArray> GetFilesFromZip(const QString &fileName, const QString &fileNameFilter = QLatin1String(""));
int GetReleaseNumber(const QString &release);
QString GetUserAgent();
QString Pluralize(const int count, const QString &plural = QStringLiteral("s"), const QString &singular = QLatin1String(""));
QString PrintTrueFalse(bool tf);
QString Sanitize(QString s);
QString SanitizeFile(QString s);
QString TrimFileName(const QString &fileName);
void Warning(const QString &title, const QString &message, const bool quiet = false, const int level = 5);

#endif // COMMON_H
