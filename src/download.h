// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QByteArray>
#include <QIODevice>
#include <QString>
#include <QUrl>

namespace Downloads {
struct Result {
    bool ok = false;
    QByteArray data;
    QString error;
    QUrl finalUrl;
    int httpStatus = 0;
};

// Call from a worker thread. Without a destination, returns bounded UTF-8/JSON bytes.
Result fetch(const QUrl &url, QIODevice *destination = nullptr,
             qint64 maximumBytes = 8 * 1024 * 1024, int timeoutMs = 30000);
}
