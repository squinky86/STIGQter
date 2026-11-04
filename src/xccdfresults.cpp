// SPDX-License-Identifier: GPL-3.0-or-later
#include "xccdfresults.h"
#include <QXmlStreamReader>

bool ParseXccdfResults(QIODevice *input, XccdfResults &results, QString &error)
{
    results = {};
    if (!input || input->size() > 64 * 1024 * 1024) {
        error = QStringLiteral("XCCDF results exceed the 64 MiB limit.");
        return false;
    }
    XccdfResults parsed;
    QXmlStreamReader xml(input);
    xml.setEntityExpansionLimit(4096);
    QString rule;
    bool inResult = false, foundResult = false;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isEndElement()) {
            if (xml.name() == QStringLiteral("TestResult")) inResult = false;
            if (xml.name() == QStringLiteral("rule-result")) rule.clear();
        }
        if (!xml.isStartElement()) continue;
        if (xml.name() == QStringLiteral("TestResult")) { inResult = true; foundResult = true; }
        if (!inResult) continue;
        if (xml.name() == QStringLiteral("fact")) {
            const QString name = xml.attributes().value(QStringLiteral("name")).toString();
            const QString value = xml.readElementText();
            if (value.isEmpty()) continue;
            if (name.endsWith(QStringLiteral("ipv4"), Qt::CaseInsensitive)) parsed.ip = value;
            else if (name.endsWith(QStringLiteral("mac"), Qt::CaseInsensitive)) parsed.mac = value;
            else if (name.endsWith(QStringLiteral("fqdn"), Qt::CaseInsensitive)) parsed.fqdn = value;
        } else if (xml.name() == QStringLiteral("rule-result")) {
            rule = xml.attributes().value(QStringLiteral("idref")).toString();
            const auto start = rule.indexOf(QStringLiteral("SV"));
            if (start > 0) rule = rule.mid(start);
        } else if (xml.name() == QStringLiteral("result") && !rule.isEmpty()) {
            const QString value = xml.readElementText().trimmed();
            if (value.startsWith(QStringLiteral("pass"), Qt::CaseInsensitive)) parsed.rules.append({rule, Status::NotAFinding});
            else if (value.startsWith(QStringLiteral("notapplicable"), Qt::CaseInsensitive)) parsed.rules.append({rule, Status::NotApplicable});
            else if (value.startsWith(QStringLiteral("fail"), Qt::CaseInsensitive)) parsed.rules.append({rule, Status::Open});
        }
    }
    if (xml.hasError() || !foundResult) {
        error = xml.hasError() ? xml.errorString() : QStringLiteral("No XCCDF TestResult was found.");
        return false;
    }
    results = parsed;
    error.clear();
    return true;
}
