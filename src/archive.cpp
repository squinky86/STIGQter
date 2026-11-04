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
#include <zip.h>
#include <QThread>
#include <memory>

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
    QMap<QString, QByteArray> files;
    int error = 0;
    std::unique_ptr<zip_t, decltype(&zip_discard)> archive(
        zip_open(fileName.toUtf8().constData(), ZIP_RDONLY, &error), zip_discard);
    if (!archive) return {};
    const zip_int64_t count = zip_get_num_entries(archive.get(), 0);
    if (count < 0 || count > 100000) return {};
    // Bound aggregate extraction as well as each member. Quarterly ZIPs contain
    // compressed child archives; individual XCCDF packages are much smaller.
    constexpr quint64 budget = 1024ULL * 1024 * 1024;
    quint64 total = 0;
    for (zip_int64_t i = 0; i < count; ++i)
    {
        if (QThread::currentThread()->isInterruptionRequested()) return {};
        zip_stat_t stat;
        zip_stat_init(&stat);
        if (zip_stat_index(archive.get(), i, 0, &stat) != 0) return {};
        const QString name = QString::fromUtf8(stat.name);
        if (!fileNameFilter.isEmpty() && !name.endsWith(fileNameFilter, Qt::CaseInsensitive)) continue;
        if (name.endsWith(QLatin1Char('/'))) continue;
        if (stat.size > budget - total || files.contains(name)) return {};
        total += stat.size;
        std::unique_ptr<zip_file_t, decltype(&zip_fclose)> member(
            zip_fopen_index(archive.get(), i, 0), zip_fclose);
        if (!member) return {};
        QByteArray data;
        data.reserve(static_cast<qsizetype>(stat.size));
        char buffer[65536];
        while (static_cast<quint64>(data.size()) < stat.size)
        {
            const zip_int64_t length = zip_fread(member.get(), buffer, sizeof buffer);
            if (length <= 0 || static_cast<quint64>(data.size() + length) > stat.size) return {};
            data.append(buffer, length);
        }
        // Ask for EOF to surface a CRC/decompression failure, even for an empty file.
        if (zip_fread(member.get(), buffer, 1) != 0) return {};
        files.insert(name, data);
    }
    return files;
}

/**
 * @brief CreateZip
 * @param fileName
 * @param files
 * @return @c true when the archive was written successfully.
 *
 * Writes an in-memory set of files (keyed by their path inside the
 * archive) to a new zip archive at @a fileName using libzip. Any
 * existing archive at that path is truncated first.
 *
 * The @a files map is passed by const reference and must outlive this
 * call: zip_source_buffer() does not copy the supplied bytes, so the
 * QByteArrays are kept alive until zip_close() has flushed them.
 */
bool CreateZip(const QString &fileName, const QMap<QString, QByteArray> &files)
{
    int err = 0;
    struct zip *za = zip_open(fileName.toStdString().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (za == nullptr)
        return false;

    bool ret = true;
    for (auto i = files.constBegin(); i != files.constEnd(); ++i)
    {
        const QByteArray &contents = i.value();
        //the buffer is not copied by libzip; the const-ref map keeps it alive until zip_close()
        struct zip_source *zs = zip_source_buffer(za, contents.constData(), static_cast<zip_uint64_t>(contents.size()), 0);
        if (zs == nullptr)
        {
            ret = false;
            continue;
        }
        if (zip_file_add(za, i.key().toStdString().c_str(), zs, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE) < 0)
        {
            zip_source_free(zs);
            ret = false;
        }
    }

    if (zip_close(za) < 0)
    {
        zip_discard(za);
        ret = false;
    }

    return ret;
}
