/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019-2020 Jon Hood, http://www.hoodsecurity.com/
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

#include "asset.h"
#include "common.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "workercmrsexport.h"

#include <QDateTime>
#include <QFile>
#include <QXmlStreamWriter>

/**
 * @class WorkerCMRSExport
 * @brief Export a CMRS file of the results of the system.
 *
 * Continuous Monitoring and Risk Scoring (CMRS) formats foster
 * compliance with the continuous monitoring stage of RMF systems.
 */

/**
 * @brief WorkerCMRSExport::WorkerCMRSExport
 * @param parent
 *
 * Default constructor.
 */
WorkerCMRSExport::WorkerCMRSExport(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCMRSExport::SetExportPath
 * @param dir
 *
 * Set the output file to writ ethe CMRS data to.
 */
void WorkerCMRSExport::SetExportPath(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerCMRSExport::process
 *
 * Using the provided output directory of SetExportDir(), generate
 * every combination of @a Asset ↔ @a STIG mapping stored in the
 * database and build the CKL file for that mapping.
 */
void WorkerCMRSExport::process()
{
    DbManager db;
    QList<Asset> assets = db.GetAssets();
    Q_EMIT initialize(assets.count(), 0);

    Q_EMIT updateStatus(QStringLiteral("Preparing Data…"));

    QFile file(_fileName); //open the output file
    if (file.open(QIODevice::WriteOnly))
    {
        QXmlStreamWriter stream(&file); //write to the stream as an XML file
        stream.writeStartDocument(QStringLiteral("1.0"));
        stream.writeComment("STIGQter :: " + VERSION);
        stream.writeStartElement(QStringLiteral("IMPORT_FILE"));
        stream.writeAttribute(QStringLiteral("xmlns"), QStringLiteral("urn:FindingImport"));

        QString curDate = QDateTime::currentDateTime().toTimeSpec(Qt::OffsetFromUTC).toString(Qt::ISODate); //current UTC time
        QString elementKey = QStringLiteral("0"); //doesn't make sense for target keys to be at this level

        Q_FOREACH (Asset a, assets)
        {
            Q_EMIT updateStatus("Adding " + PrintAsset(a));

            stream.writeStartElement(QStringLiteral("ASSET"));

            stream.writeStartElement(QStringLiteral("ASSET_TS"));
            stream.writeCharacters(curDate); //current UTC time
            stream.writeEndElement(); //ASSET_TS

            stream.writeStartElement(QStringLiteral("ASSET_ID")); //(ASSET NAME)
            stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("ASSET NAME"));
            stream.writeCharacters(a.hostName);
            stream.writeEndElement(); //ASSET_ID (ASSET NAME)

            stream.writeStartElement(QStringLiteral("ASSET_ID")); //(MAC ADDRESS)
            stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("MAC ADDRESS"));
            stream.writeCharacters(a.hostMAC);
            stream.writeEndElement(); //ASSET_ID (MAC ADDRESS)

            stream.writeStartElement(QStringLiteral("ASSET_ID")); //(IP ADDRESS)
            stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("IP ADDRESS"));
            stream.writeCharacters(a.hostIP);
            stream.writeEndElement(); //ASSET_ID (IP ADDRESS)

            stream.writeStartElement(QStringLiteral("ASSET_ID")); //(FQDN)
            stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("FQDN"));
            stream.writeCharacters(a.hostFQDN);
            stream.writeEndElement(); //ASSET_ID (FQDN)

            stream.writeStartElement(QStringLiteral("ASSET_ID")); //(TechArea)
            stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("TechArea"));
            stream.writeCharacters(a.techArea);
            stream.writeEndElement(); //ASSET_ID (TechArea)

            stream.writeStartElement(QStringLiteral("ASSET_TYPE"));

            stream.writeStartElement(QStringLiteral("ASSET_TYPE_KEY"));
            stream.writeCharacters(a.assetType.startsWith(QStringLiteral("Computing")) ? QStringLiteral("1") : QStringLiteral("2"));
            stream.writeEndElement(); //ASSET_TYPE_KEY

            stream.writeEndElement(); //ASSET_TYPE

            stream.writeStartElement(QStringLiteral("ELEMENT"));

            stream.writeStartElement(QStringLiteral("ELEMENT_KEY"));
            stream.writeCharacters(elementKey);
            stream.writeEndElement(); //ELEMENT_KEY

            stream.writeEndElement(); //ELEMENT

            Q_FOREACH (STIG s, a.GetSTIGs())
            {
                stream.writeStartElement(QStringLiteral("TARGET"));

                stream.writeStartElement(QStringLiteral("TARGET_ID"));
                stream.writeCharacters(s.benchmarkId);
                stream.writeEndElement(); //TARGET_ID

                stream.writeStartElement(QStringLiteral("TARGET_KEY"));
                stream.writeCharacters(elementKey);
                stream.writeEndElement(); //TARGET_KEY

                Q_FOREACH (CKLCheck c, a.GetCKLChecks(&s))
                {
                    STIGCheck sc = c.GetSTIGCheck();

                    stream.writeStartElement(QStringLiteral("FINDING"));

                    stream.writeStartElement(QStringLiteral("FINDING_ID"));
                    stream.writeAttribute(QStringLiteral("TYPE"), QStringLiteral("VK"));
                    stream.writeAttribute(QStringLiteral("ID"), sc.rule);
                    stream.writeCharacters(PrintCMRSVulnId(sc));
                    stream.writeEndElement(); //FINDING_ID

                    stream.writeStartElement(QStringLiteral("FINDING_STATUS"));
                    stream.writeCharacters(GetCMRSStatus(c.status));
                    stream.writeEndElement(); //FINDING_STATUS

                    stream.writeStartElement(QStringLiteral("FINDING_DETAILS"));
                    stream.writeAttribute(QStringLiteral("OVERRIDE"), QStringLiteral("O"));
                    stream.writeCharacters(c.findingDetails);
                    stream.writeEndElement(); //FINDING_DETAILS

                    stream.writeStartElement(QStringLiteral("SCRIPT_RESULTS"));
                    stream.writeEndElement(); //SCRIPT_RESULTS

                    stream.writeStartElement(QStringLiteral("COMMENT"));
                    stream.writeCharacters(c.comments);
                    stream.writeEndElement(); //COMMENT

                    stream.writeStartElement(QStringLiteral("TOOL"));
                    stream.writeCharacters(QStringLiteral("STIGQter"));
                    stream.writeEndElement(); //TOOL

                    stream.writeStartElement(QStringLiteral("TOOL_VERSION"));
                    stream.writeCharacters(VERSION);
                    stream.writeEndElement(); //TOOL_VERSION

                    stream.writeStartElement(QStringLiteral("AUTHENTICATED_FINDING"));
                    stream.writeCharacters(QStringLiteral("true"));
                    stream.writeEndElement(); //AUTHENTICATED_FINDING

                    stream.writeEndElement(); //FINDING
                }

                stream.writeEndElement(); //TARGET
            }

            stream.writeEndElement(); //ASSET

            Q_EMIT progress(-1);
        }

        stream.writeEndElement(); //IMPORT_FILE
        stream.writeEndDocument();
    }

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
