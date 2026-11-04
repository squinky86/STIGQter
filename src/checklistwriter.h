// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "asset.h"
#include "stig.h"
#include <QIODevice>
#include <functional>

// Serialization runs in the caller's worker thread; domain lookups retain that
// thread's DbManager connection. Workers own files and completion/error signals.
using ChecklistProgress = std::function<void(int, const QString &)>;
bool WriteCkl(QIODevice *output, const Asset &asset, const QList<STIG> &stigs, const ChecklistProgress &progress);
bool WriteCklb(QIODevice *output, const Asset &asset, const QList<STIG> &stigs, const ChecklistProgress &progress);
