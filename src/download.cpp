// SPDX-License-Identifier: GPL-3.0-or-later
#include "download.h"
#include "common.h"

#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QThread>
#include <QTimer>
#include <QTemporaryFile>

Downloads::Result Downloads::fetch(const QUrl &url, QIODevice *destination,
                                  qint64 maximumBytes, int timeoutMs)
{
    Result result;
    result.finalUrl = url;
    qint64 received = 0;
    const auto consume = [&](const QByteArray &bytes) {
        if (bytes.size() > maximumBytes - received) {
            result.error = QStringLiteral("The download exceeds its size limit.");
            return false;
        }
        received += bytes.size();
        if (destination) {
            if (destination->write(bytes) != bytes.size()) {
                result.error = QStringLiteral("Unable to write the downloaded file.");
                return false;
            }
        } else {
            result.data.append(bytes);
        }
        return true;
    };

    if (!url.isValid() || url.isEmpty() || maximumBytes <= 0 || timeoutMs <= 0) {
        result.error = QStringLiteral("Invalid download request.");
        return result;
    }
    if (url.isLocalFile()) {
        QFile source(url.toLocalFile());
        if (!source.open(QIODevice::ReadOnly)) {
            result.error = source.errorString();
            return result;
        }
        while (!source.atEnd()) {
            const QByteArray bytes = source.read(64 * 1024);
            if (source.error() != QFile::NoError || !consume(bytes)) {
                if (result.error.isEmpty()) result.error = source.errorString();
                return result;
            }
        }
        result.ok = true;
        return result;
    }
    if (url.scheme() != QStringLiteral("https") && url.scheme() != QStringLiteral("http")) {
        result.error = QStringLiteral("Only HTTP, HTTPS and local files are supported.");
        return result;
    }

    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setMaximumRedirectsAllowed(5);
    request.setTransferTimeout(qMin(timeoutMs, 30000));
    const QByteArray userAgent = GetUserAgent().toUtf8();
    request.setRawHeader("User-Agent", userAgent);
    // Preserve the download audit without a blocking, unbounded DNS lookup.
    QHostInfo::lookupHost(url.host(), &manager, [url, userAgent](const QHostInfo &host) {
        const QString address = host.addresses().isEmpty() ? QStringLiteral("unresolved")
                                                          : host.addresses().first().toString();
        Warning(QStringLiteral("Downloading"), QStringLiteral("%1 (IP %2), User-Agent: %3")
                .arg(url.toDisplayString(QUrl::RemovePassword), address, QString::fromUtf8(userAgent)), true);
    });
    QNetworkReply *reply = manager.get(request);
    reply->setReadBufferSize(64 * 1024);
    QEventLoop loop;
    QTimer deadline;
    deadline.setSingleShot(true);
    QObject::connect(&deadline, &QTimer::timeout, reply, [&] {
        result.error = QStringLiteral("The download timed out.");
        reply->abort();
    });
    QTimer cancellation;
    QObject::connect(&cancellation, &QTimer::timeout, reply, [&] {
        if (QThread::currentThread()->isInterruptionRequested()) {
            result.error = QStringLiteral("The download was cancelled.");
            reply->abort();
        }
    });
    QObject::connect(reply, &QNetworkReply::readyRead, reply, [&] {
        if (result.error.isEmpty() && !consume(reply->readAll())) reply->abort();
    });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    deadline.start(timeoutMs);
    cancellation.start(100);
    if (!reply->isFinished()) loop.exec();
    deadline.stop();
    cancellation.stop();
    result.finalUrl = reply->url();
    result.httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (result.error.isEmpty() && reply->error() != QNetworkReply::NoError)
        result.error = reply->errorString();
    if (result.error.isEmpty() && (result.httpStatus < 200 || result.httpStatus >= 300))
        result.error = QStringLiteral("HTTP %1").arg(result.httpStatus);
    if (result.error.isEmpty()) consume(reply->readAll());
    result.ok = result.error.isEmpty();
    if (!result.ok) result.data.clear();
    delete reply;
    return result;
}

bool DownloadFile(const QUrl &url, QFile *file)
{
    if (!file || (file->isOpen() && !file->isWritable())) return false;
    QTemporaryFile staged;
    if (!staged.open()) return false;
    const auto result = Downloads::fetch(url, &staged, 2LL * 1024 * 1024 * 1024, 10 * 60 * 1000);
    if (!result.ok || !staged.flush() || !staged.seek(0)) {
        Warning(QStringLiteral("Download failed"), result.error, true);
        return false;
    }
    const bool wasOpen = file->isOpen();
    if (!wasOpen && !file->open(QIODevice::WriteOnly)) return false;
    bool ok = file->resize(0) && file->seek(0);
    while (ok && !staged.atEnd()) {
        const auto bytes = staged.read(64 * 1024);
        ok = staged.error() == QFile::NoError && file->write(bytes) == bytes.size();
    }
    ok = file->flush() && ok;
    if (!ok) file->resize(0);
    if (wasOpen) file->seek(0);
    else file->close();
    return ok;
}

QString DownloadPage(const QUrl &url)
{
    const auto result = Downloads::fetch(url);
    return result.ok ? QString::fromUtf8(result.data) : QString();
}
