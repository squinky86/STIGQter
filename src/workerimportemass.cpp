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

#include "common.h"
#include "dbmanager.h"
#include "workerimportemass.h"

#include <QXmlStreamReader>

/**
 * @class WorkerImportEMASS
 * @brief Imports an eMASS-generated Test Result Import spreadsheet.
 *
 * Including self-assessment data during a validation event allows
 * for faster vetting of results and understandig of the system's
 * categorization, tailoring, and inheritance relationships.
 */

/**
 * @brief WorkerImportEMASS::WorkerImportEMASS
 * @param parent
 *
 * Main constructor.
 */
WorkerImportEMASS::WorkerImportEMASS(QObject *parent) : Worker(parent), _fileName()
{
}

/**
 * @brief WorkerImportEMASS::SetReportName
 * @param fileName
 *
 * Before calling the processing function, set the filename to import.
 */
void WorkerImportEMASS::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerImportEMASS::process
 *
 * Perform the operations of this worker process.
 *
 * @example WorkerImportEMASS::process
 * @title WorkerImportEMASS::process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerImportEMASS *import = new WorkerImportEMASS();
 * html->SetReportName(file); // "file" is the path to the eMASS report to import.
 * connect(thread, SIGNAL(started()), html, SLOT(process())); // Start the worker when the new thread emits its started() signal.
 * connect(html, SIGNAL(finished()), thread, SLOT(quit())); // Kill the thread once the worker emits its finished() signal.
 * connect(thread, SIGNAL(finished()), this, SLOT(EndFunction()));  // execute some EndFunction() (custom code) when the thread is cleaned up.
 * connect(html, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int))); // If progress status is needed, connect a custom Initialize(int, int) function to the initialize slot.
 * connect(html, SIGNAL(progress(int)), this, SLOT(Progress(int))); // If progress status is needed, connect the progress slot to a custom Progress(int) function.
 * connect(html, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString))); // If progress status is needed, connect a human-readable display of the status to the updateStatus(QString) slot.
 * t->start(); // Start the thread
 *
 * //Don't forget to handle the *thread and *import cleanup!
 * @endcode
 */
void WorkerImportEMASS::process()
{
    DbManager db;

    Q_EMIT initialize(5, 0);

    Q_EMIT updateStatus(QStringLiteral("Opening xlsx file…"));
    QMap<QString, QByteArray> files = GetFilesFromZip(_fileName);
    Q_EMIT progress(-1);

    //First, create Shared Strings table
    Q_EMIT updateStatus(QStringLiteral("Reading Shared Strings Table…"));
    QStringList sst;
    if (files.contains(QStringLiteral("xl/sharedStrings.xml")))
    {
        //There is a sharedStrings table! Parse it:
        QString toAdd = QString();
        QXmlStreamReader xml(files[QStringLiteral("xl/sharedStrings.xml")]);
        while (!xml.atEnd() && !xml.hasError())
        {
            xml.readNext();
            if (xml.isStartElement())
            {
                if (xml.name() == "si")
                    toAdd = QString(); //new string
                else if (xml.name() == "t")
                    toAdd.append(xml.readElementText());
            }
            if (xml.isEndElement())
            {
                if (xml.name() == "si")
                    sst.append(toAdd); //end of shared string element; add it to the table
            }
        }
    }
    Q_EMIT progress(-1);

    //Second, get the list of sheet IDs from the workbook relationships
    Q_EMIT updateStatus(QStringLiteral("Getting Worksheet IDs…"));
    QMap<QString, QString> relationshipIds;
    if (files.contains(QStringLiteral("xl/_rels/workbook.xml.rels")))
    {
        //Get the IDs of the worksheets
        QXmlStreamReader xml(files[QStringLiteral("xl/_rels/workbook.xml.rels")]);
        while (!xml.atEnd() && !xml.hasError())
        {
            xml.readNext();
            if (xml.isStartElement())
            {
                if (xml.name() == "Relationship")
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("Id")) && xml.attributes().hasAttribute(QStringLiteral("Target")))
                    {
                        QString id = QString();
                        QString target = QString();
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml.attributes())
                        {
                            if (attr.name() == "Id")
                                id = attr.value().toString();
                            else if (attr.name() == "Target")
                                target = attr.value().toString();
                        }
                        relationshipIds.insert(id, target);
                    }
                }
            }
        }
    }
    Q_EMIT progress(-1);

    //Third, get the names of the sheets by relationship ID
    Q_EMIT updateStatus(QStringLiteral("Getting Worksheet Names…"));
    QMap<QString, QString> sheetNames;
    if (files.contains(QStringLiteral("xl/workbook.xml")))
    {
        //Get the Worksheets
        QXmlStreamReader xml(files[QStringLiteral("xl/workbook.xml")]);
        while (!xml.atEnd() && !xml.hasError())
        {
            xml.readNext();
            if (xml.isStartElement())
            {
                if (xml.name() == "sheet")
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("r:id")) && xml.attributes().hasAttribute(QStringLiteral("name")))
                    {
                        QString id = QString();
                        QString name = QString();
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml.attributes())
                        {
                            if (attr.name() == "id")
                                id = attr.value().toString();
                            else if (attr.name() == "name")
                                name = attr.value().toString();
                        }
                        sheetNames.insert(name, id);
                    }
                }
            }
        }
    }
    Q_EMIT progress(-1);

    //Fourth, find out if a worksheet is named "Test Result Import"
    if (sheetNames.contains(QStringLiteral("Test Result Import")) && relationshipIds.contains(sheetNames[QStringLiteral("Test Result Import")]) && files.contains("xl/" + relationshipIds[sheetNames[QStringLiteral("Test Result Import")]]))
    {
        //It does! Continue parsing.
        //Fifth, read the correct spreadsheet that has the needed data
        Q_EMIT updateStatus(QStringLiteral("Reading worksheet…"));
        QXmlStreamReader xml(files["xl/" + relationshipIds[sheetNames[QStringLiteral("Test Result Import")]]]);
        int onRow = 0;
        QString onCol = QString();
        bool isSharedString = false; //keep up with whether the current record is a shared string
        QStringList meaningfulCols = {QStringLiteral("C"), QStringLiteral("D"), QStringLiteral("E"), QStringLiteral("F"), QStringLiteral("G"), QStringLiteral("I"), QStringLiteral("J"), QStringLiteral("K"), QStringLiteral("L"), QStringLiteral("M"), QStringLiteral("N"), QStringLiteral("O"), QStringLiteral("P"), QStringLiteral("Q"), QStringLiteral("R"), QStringLiteral("S")};
        QString tempImportControlImplementationStatus = QString();
        QString tempImportSecurityControlDesignation = QString();
        QString tempImportApNum = QString();
        QString tempImportNarrative = QString();
        CCI curCCI;
        DbManager db;
        db.DelayCommit(true);
        while (!xml.atEnd() && !xml.hasError())
        {
            xml.readNext();
            if (xml.isStartElement())
            {
                //Get the dimensions of the sheet to set the progress bar
                if (xml.name() == "dimension")
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("ref")))
                    {
                        QStringRef ref = xml.attributes().value(QStringLiteral("ref"));
                        if (ref.contains(':'))
                        {
                            ref = ref.right(ref.length() - ref.lastIndexOf(':'));
                            QRegExp re(QStringLiteral("\\d*"));
                            while (!re.exactMatch(ref.toString()) && (ref.length() > 1))
                            {
                                ref = ref.right(ref.length() - 1);
                            }
                            if (re.exactMatch(ref.toString()))
                            {
                                Q_EMIT initialize(ref.toInt(), 5);
                            }
                        }
                    }
                }
                //read the next line
                else if (xml.name() == "row")
                {
                    onRow++;
                    Q_EMIT progress(-1);
                }
                else if (xml.name() == "c")
                {
                    isSharedString = false;
                    if (xml.attributes().hasAttribute(QStringLiteral("t")))
                    {
                        if (xml.attributes().value(QStringLiteral("t")) == "s")
                            isSharedString = true;
                    }
                    if (xml.attributes().hasAttribute(QStringLiteral("r")))
                    {
                        onCol = xml.attributes().value(QStringLiteral("r")).left(1).toString();
                    }
                }
                else if (xml.name() == "v" && meaningfulCols.contains(onCol))
                {
                    QString value = xml.readElementText();
                    if (isSharedString)
                    {
                        //read shared string table
                        int count = value.toInt();
                        if (count >= 0  && count < sst.size())
                        {
                            value = sst.at(count);
                        }
                    }
                    if (onRow > 6)
                    {
                        if (onCol == QStringLiteral("G"))
                        {
                            curCCI = db.GetCCIByCCI(value.toInt());
                            curCCI.importControlImplementationStatus = tempImportControlImplementationStatus;
                            curCCI.importSecurityControlDesignation = tempImportSecurityControlDesignation;
                            curCCI.importApNum = tempImportApNum;
			    curCCI.importNarrative = tempImportNarrative;
                            tempImportControlImplementationStatus = QString();
                            tempImportSecurityControlDesignation = QString();
                            tempImportApNum = QString();
                            tempImportNarrative = QString();
                        }
                        else if (onCol == QStringLiteral("C"))
                        {
                            tempImportControlImplementationStatus = value;
                        }
                        else if (onCol == QStringLiteral("D"))
                        {
                            tempImportSecurityControlDesignation = value;
                        }
                        else if (onCol == QStringLiteral("E"))
                        {
                            tempImportNarrative = value;
                        }
                        else if (onCol == QStringLiteral("F"))
                        {
                            tempImportApNum = value;
                        }
                        else {
                            if (onCol == QStringLiteral("I"))
                                curCCI.importImplementationGuidance = value;
                            else if (onCol == QStringLiteral("J"))
                                curCCI.importAssessmentProcedures = value;
                            else if (onCol == QStringLiteral("P"))
                                curCCI.importCompliance = value;
                            else if (onCol == QStringLiteral("Q"))
                                curCCI.importDateTested = value;
                            else if (onCol == QStringLiteral("R"))
                                curCCI.importTestedBy = value;
                            else if (onCol == QStringLiteral("S"))
                                curCCI.importTestResults = value;
                            else if (onCol == QStringLiteral("L"))
                                curCCI.importCompliance2 = value;
                            else if (onCol == QStringLiteral("M"))
                            {
                                curCCI.importDateTested2 = value;
                                //read value may be Excel serial date
                                /*bool ok = false;
                                int excelSerialDate = curCCI.importDateTested2.toInt(&ok);
                                if (ok && excelSerialDate > 0)
                                {
                                    QDate tempDate(1899, 12, 31);
                                    tempDate.addDays(excelSerialDate);
                                    curCCI.importDateTested2 = tempDate.to
                                }*/
                            }
                            else if (onCol == QStringLiteral("N"))
                                curCCI.importTestedBy2 = value;
                            else if (onCol == QStringLiteral("O"))
                                curCCI.importTestResults2 = value;
                            else if (onCol == QStringLiteral("K"))
                                curCCI.importInherited = value;

                            curCCI.isImport = true;
                            if (curCCI.id >= 0)
                            {
                                db.UpdateCCI(curCCI);
                            }
                            else
                            {
                                //A bad CCI was listed in the sheet
                                Warning(QStringLiteral("CCI Not Imported"), QStringLiteral("No CCI \"") + PrintCCI(curCCI) + QStringLiteral("\" exists in the database."));
                            }
                        }
                    }
                }
            }
        }
        db.DelayCommit(false);
    }
    else
    {
        //No "Test Result Import" sheet found
        Warning(QStringLiteral("Worksheet Not Found"), QStringLiteral("No sheet named \"Test Result Import\" found."));
    }

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
