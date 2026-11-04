// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "cklcheck.h"
#include <QIODevice>

struct XccdfResults {
    struct Rule { QString id; Status status; };
    QString ip, mac, fqdn;
    QVector<Rule> rules;
};
bool ParseXccdfResults(QIODevice *input, XccdfResults &results, QString &error);
