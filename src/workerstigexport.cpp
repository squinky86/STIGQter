/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2026 Jon Hood, http://www.hoodsecurity.com/
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
#include "cci.h"
#include "stigcheck.h"
#include "supplement.h"
#include "workerstigexport.h"

#include <QFileInfo>
#include <QRegularExpression>
#include <QXmlStreamWriter>

/**
 * @class WorkerSTIGExport
 * @brief Export an edited @a STIG back out as a DISA-style XCCDF
 * benchmark packaged in a @c .zip archive.
 *
 * The archive produced here is re-importable by @a WorkerSTIGAdd: the
 * XCCDF entry is named with a recognized suffix, the benchmark metadata
 * and per-@a STIGCheck rules are emitted in the structure the importer
 * parses, and any supplementary files stored with the STIG are written
 * back verbatim.
 */

/**
 * @brief WorkerSTIGExport::WorkerSTIGExport
 * @param parent
 *
 * Default constructor.
 */
WorkerSTIGExport::WorkerSTIGExport(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerSTIGExport::SetSTIG
 * @param stig
 *
 * Set the @a STIG to export.
 */
void WorkerSTIGExport::SetSTIG(const STIG &stig)
{
    _stig = stig;
}

/**
 * @brief WorkerSTIGExport::SetExportPath
 * @param fileName
 *
 * Set the output @c .zip file to write the STIG to.
 */
void WorkerSTIGExport::SetExportPath(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief BuildVulnDescription
 * @param check
 * @return The DISA @c <description> blob for a @a STIGCheck.
 *
 * Concatenates the discrete vulnerability fields into the pseudo-tagged
 * blob DISA embeds inside the XCCDF @c <description> element. The raw
 * field values are inserted verbatim; QXmlStreamWriter escapes the whole
 * blob when it is written, which is exactly what the importer's
 * readElementText()/XMLVulnFix() round-trip expects.
 */
static QString BuildVulnDescription(const STIGCheck &check)
{
    return QStringLiteral("<VulnDiscussion>") + check.vulnDiscussion + QStringLiteral("</VulnDiscussion>") +
           QStringLiteral("<FalsePositives>") + check.falsePositives + QStringLiteral("</FalsePositives>") +
           QStringLiteral("<FalseNegatives>") + check.falseNegatives + QStringLiteral("</FalseNegatives>") +
           QStringLiteral("<Documentable>") + (check.documentable ? QStringLiteral("true") : QStringLiteral("false")) + QStringLiteral("</Documentable>") +
           QStringLiteral("<Mitigations>") + check.mitigations + QStringLiteral("</Mitigations>") +
           QStringLiteral("<SeverityOverrideGuidance>") + check.severityOverrideGuidance + QStringLiteral("</SeverityOverrideGuidance>") +
           QStringLiteral("<PotentialImpacts>") + check.potentialImpact + QStringLiteral("</PotentialImpacts>") +
           QStringLiteral("<ThirdPartyTools>") + check.thirdPartyTools + QStringLiteral("</ThirdPartyTools>") +
           QStringLiteral("<MitigationControl>") + check.mitigationControl + QStringLiteral("</MitigationControl>") +
           QStringLiteral("<Responsibility>") + check.responsibility + QStringLiteral("</Responsibility>") +
           QStringLiteral("<IAControls>") + check.iaControls + QStringLiteral("</IAControls>");
}

/**
 * @brief WorkerSTIGExport::process
 *
 * Build the XCCDF benchmark for the configured @a STIG, package it (with
 * its supplements) into a @c .zip archive at the configured path, and
 * report progress.
 */
void WorkerSTIGExport::process()
{
    Worker::process();

    QVector<STIGCheck> checks = _stig.GetSTIGChecks();
    Q_EMIT initialize(checks.count() + 1, 0);
    Q_EMIT updateStatus(QStringLiteral("Building XCCDF…"));

    //build the XCCDF benchmark XML in memory
    QByteArray xccdf;
    QXmlStreamWriter stream(&xccdf);
    stream.setAutoFormatting(true);
    stream.writeStartDocument(QStringLiteral("1.0"));
    stream.writeComment("STIGQter :: " + VERSION);
    stream.writeStartElement(QStringLiteral("Benchmark"));
    stream.writeAttribute(QStringLiteral("id"), _stig.benchmarkId);
    stream.writeTextElement(QStringLiteral("title"), _stig.title);
    stream.writeTextElement(QStringLiteral("description"), _stig.description);
    stream.writeStartElement(QStringLiteral("plain-text"));
    stream.writeAttribute(QStringLiteral("id"), QStringLiteral("release-info"));
    stream.writeCharacters(_stig.release);
    stream.writeEndElement(); //plain-text
    stream.writeTextElement(QStringLiteral("version"), QString::number(_stig.version));

    for (const STIGCheck &check : checks)
    {
        Q_EMIT updateStatus("Exporting " + PrintSTIGCheck(check) + "…");

        stream.writeStartElement(QStringLiteral("Group"));
        stream.writeAttribute(QStringLiteral("id"), check.vulnNum);
        stream.writeTextElement(QStringLiteral("title"), check.groupTitle);

        stream.writeStartElement(QStringLiteral("Rule"));
        stream.writeAttribute(QStringLiteral("id"), check.rule);
        stream.writeAttribute(QStringLiteral("severity"), GetSeverity(check.severity, false));
        stream.writeAttribute(QStringLiteral("weight"), QString::number(check.weight, 'f', 1));
        stream.writeTextElement(QStringLiteral("version"), check.ruleVersion);
        stream.writeTextElement(QStringLiteral("title"), check.title);
        stream.writeTextElement(QStringLiteral("description"), BuildVulnDescription(check));

        //CCI and legacy identifiers
        for (const CCI &cci : check.GetCCIs())
        {
            stream.writeStartElement(QStringLiteral("ident"));
            stream.writeAttribute(QStringLiteral("system"), QStringLiteral("http://cyber.mil/cci"));
            stream.writeCharacters(PrintCCI(cci));
            stream.writeEndElement(); //ident
        }
        for (const QString &legacyId : check.legacyIds)
        {
            stream.writeStartElement(QStringLiteral("ident"));
            stream.writeAttribute(QStringLiteral("system"), QStringLiteral("http://cyber.mil/legacy"));
            stream.writeCharacters(legacyId);
            stream.writeEndElement(); //ident
        }

        stream.writeTextElement(QStringLiteral("fixtext"), check.fix);

        stream.writeStartElement(QStringLiteral("check"));
        stream.writeStartElement(QStringLiteral("check-content-ref"));
        stream.writeAttribute(QStringLiteral("name"), check.checkContentRef);
        stream.writeEndElement(); //check-content-ref
        stream.writeTextElement(QStringLiteral("check-content"), check.check);
        stream.writeEndElement(); //check

        stream.writeEndElement(); //Rule
        stream.writeEndElement(); //Group

        Q_EMIT progress(-1);
    }

    stream.writeEndElement(); //Benchmark
    stream.writeEndDocument();

    //choose an XCCDF entry name the importer will recognize
    QString xccdfName = _stig.fileName;
    if (!(xccdfName.endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive) ||
          xccdfName.endsWith(QStringLiteral("Manual_STIG.xml"), Qt::CaseInsensitive) ||
          xccdfName.endsWith(QStringLiteral("Manual_xccdf.xml"), Qt::CaseInsensitive)))
    {
        QString base = _stig.benchmarkId.isEmpty() ? _stig.title : _stig.benchmarkId;
        base.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9_.-]")), QStringLiteral("_"));
        if (base.isEmpty())
            base = QStringLiteral("STIG");
        xccdfName = base + QStringLiteral("_Manual_xccdf.xml");
    }

    //assemble the archive contents: the XCCDF plus every stored supplement
    QMap<QString, QByteArray> files;
    files.insert(xccdfName, xccdf);
    for (const Supplement &supplement : _stig.GetSupplements())
    {
        //never let a supplement clobber the benchmark entry
        if (supplement.path != xccdfName)
            files.insert(supplement.path, supplement.contents);
    }

    Q_EMIT updateStatus(QStringLiteral("Writing archive…"));
    if (!CreateZip(_fileName, files))
    {
        Q_EMIT ThrowWarning(QStringLiteral("Unable to Export STIG"),
                            "The STIG could not be written to \"" + _fileName + "\".");
    }
    Q_EMIT progress(-1);

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
