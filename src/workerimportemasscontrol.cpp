/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2022–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "control.h"
#include "dbmanager.h"
#include "workerimportemasscontrol.h"

#include <QRegularExpression>
#include <QXmlStreamReader>

/**
 * @class WorkerImportEMASSControl
 * @brief Imports an eMASS-generated Control Information Export spreadsheet.
 *
 * Once a risk assessment has been performed at each control level, that risk
 * analysis can be imported (mostly for use in the generated POA&M).
 */

/**
 * @brief WorkerImportEMASSControl::WorkerImportEMASSControl
 * @param parent
 *
 * Main constructor.
 */
WorkerImportEMASSControl::WorkerImportEMASSControl(QObject *parent) : Worker(parent), _fileName()
{
}

/**
 * @brief WorkerImportEMASSControl::SetReportName
 * @param fileName
 *
 * Before calling the processing function, set the filename to import.
 */
void WorkerImportEMASSControl::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerImportEMASSControl::process
 *
 * Perform the operations of this worker process.
 *
 * @example WorkerImportEMASSControl::process
 * @title WorkerImportEMASSControl::process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerImportEMASSControl *import = new WorkerImportEMASSControl();
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
void WorkerImportEMASSControl::process()
{
    Worker::process();

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
                if (xml.name().compare(QStringLiteral("si")) == 0)
                    toAdd = QString(); //new string
                else if (xml.name().compare(QStringLiteral("t")) == 0)
                    toAdd.append(xml.readElementText());
            }
            if (xml.isEndElement())
            {
                if (xml.name().compare(QStringLiteral("si")) == 0)
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
                if (xml.name().compare(QStringLiteral("Relationship")) == 0)
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("Id")) && xml.attributes().hasAttribute(QStringLiteral("Target")))
                    {
                        QString id = QString();
                        QString target = QString();
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml.attributes())
                        {
                            if (attr.name().compare(QStringLiteral("Id")) == 0)
                                id = attr.value().toString();
                            else if (attr.name().compare(QStringLiteral("Target")) == 0)
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
                if (xml.name().compare(QStringLiteral("sheet")) == 0)
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("r:id")) && xml.attributes().hasAttribute(QStringLiteral("name")))
                    {
                        QString id = QString();
                        QString name = QString();
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml.attributes())
                        {
                            if (attr.name().compare(QStringLiteral("id")) == 0)
                                id = attr.value().toString();
                            else if (attr.name().compare(QStringLiteral("name")) == 0)
                                name = attr.value().toString();
                        }
                        sheetNames.insert(name, id);
                    }
                }
            }
        }
    }
    Q_EMIT progress(-1);

    //Fourth, find out if a worksheet is named "Template"
    if (sheetNames.contains(QStringLiteral("Template")) && relationshipIds.contains(sheetNames[QStringLiteral("Template")]) && files.contains("xl/" + relationshipIds[sheetNames[QStringLiteral("Template")]]))
    {
        //It does! Continue parsing.
        //Fifth, read the correct spreadsheet that has the needed data
        Q_EMIT updateStatus(QStringLiteral("Reading worksheet…"));
        QXmlStreamReader xml(files["xl/" + relationshipIds[sheetNames[QStringLiteral("Test Result Import")]]]);
        int onRow = 0;
        QString onCol = QString();
        bool isSharedString = false; //keep up with whether the current record is a shared string
        QStringList meaningfulCols = {
            QStringLiteral("A"),
            QStringLiteral("U"),
            QStringLiteral("V"),
            QStringLiteral("W"),
            QStringLiteral("X"),
            QStringLiteral("Y"),
            QStringLiteral("AA"),
            QStringLiteral("AB")
        };
        Control tmpControl;
        QString tempImportSeverity = QString();
        QString tempImportRelevanceOfThreat = QString();
        QString tempImportLikelihood = QString();
        QString tempImportImpact = QString();
        QString tempImportImpactDescription = QString();
        QString tempImportResidualRiskLevel = QString();
        QString tempImportRecommendations = QString();
        db.DelayCommit(true);
        while (!xml.atEnd() && !xml.hasError())
        {
            xml.readNext();
            if (xml.isStartElement())
            {
                //Get the dimensions of the sheet to set the progress bar
                if (xml.name().compare(QStringLiteral("dimension")) == 0)
                {
                    if (xml.attributes().hasAttribute(QStringLiteral("ref")))
                    {
                        QStringView ref = xml.attributes().value(QStringLiteral("ref"));
                        if (ref.toString().contains(':'))
                        {
                            ref = ref.right(ref.length() - ref.toString().lastIndexOf(':'));

                            bool isNumeric = false;
                            int size = 0;
                            for (size = ref.toString().toInt(&isNumeric); !isNumeric && ref.length() > 1; size = ref.toString().toInt(&isNumeric))
                            {
                                ref = ref.right(ref.length() - 1);
                            }

                            if (isNumeric)
                                Q_EMIT initialize(size, 5);
                        }
                    }
                }
                //read the next line
                else if (xml.name().compare(QStringLiteral("row")) == 0)
                {
                    onRow++;
                    Q_EMIT progress(-1);
                }
                else if (xml.name().compare(QStringLiteral("c")) == 0)
                {
                    isSharedString = false;
                    if (xml.attributes().hasAttribute(QStringLiteral("t")))
                    {
                        if (xml.attributes().value(QStringLiteral("t")).compare(QStringLiteral("s")) == 0)
                            isSharedString = true;
                    }
                    if (xml.attributes().hasAttribute(QStringLiteral("r")))
                    {
                        onCol = xml.attributes().value(QStringLiteral("r")).left(1).toString();
                    }
                }
                else if ((xml.name().compare(QStringLiteral("v")) == 0) && meaningfulCols.contains(onCol))
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
                        if (onCol == QStringLiteral("A"))
                        {
                            if (tmpControl.id > 0)
                                db.UpdateControl(tmpControl);

                            tmpControl = db.GetControl(value);
                        }
                        else if (tmpControl.id > 0)
                        {
                            if (onCol == QStringLiteral("U"))
                            {
                                tmpControl.importSeverity = value;
                            }
                            else if (onCol == QStringLiteral("V"))
                            {
                                tmpControl.importRelevanceOfThreat = value;
                            }
                            else if (onCol == QStringLiteral("W"))
                            {
                                tmpControl.importLikelihood = value;
                            }
                            else if (onCol == QStringLiteral("X"))
                            {
                                tmpControl.importImpact = value;
                            }
                            else if (onCol == QStringLiteral("Y"))
                            {
                                tmpControl.importResidualRiskLevel = value;
                            }
                            else if (onCol == QStringLiteral("AA"))
                            {
                                tmpControl.importImpactDescription = value;
                            }
                            else if (onCol == QStringLiteral("AB"))
                            {
                                tmpControl.importRecommendations = value;
                            }
                        }
                        else if (onCol == "U")
                        {
                            //A bad Control was listed in the sheet
                            Warning(QStringLiteral("Control Not Imported"), QStringLiteral("No Control \"") + PrintControl(tmpControl) + QStringLiteral("\" exists in the database."));
                        }
                    }
                }
            }
        }
        if (tmpControl.id > 0)
            db.UpdateControl(tmpControl);
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
