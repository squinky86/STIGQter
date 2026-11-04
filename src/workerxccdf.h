// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "worker.h"
class WorkerXccdf : public Worker {
    Q_OBJECT
public:
    WorkerXccdf(int assetId, const QStringList &files) : _assetId(assetId), _files(files) {}
public Q_SLOTS:
    void process() override;
Q_SIGNALS:
    void assetUpdated();
private:
    int _assetId;
    QStringList _files;
};
