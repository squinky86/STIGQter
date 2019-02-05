/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019 Jon Hood, http://www.hoodsecurity.com/
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

WorkerImportEMASS::WorkerImportEMASS(QObject *parent) : QObject(parent), _fileName()
{
}

void WorkerImportEMASS::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

void WorkerImportEMASS::process()
{
    DbManager db;

    emit initialize(5, 0);

    emit updateStatus(QStringLiteral("Opening xlsx file…"));
    QMap<QString, QByteArray> files = GetFilesFromZip(_fileName);
    emit progress(-1);

    //First, create Shared Strings table
    emit updateStatus(QStringLiteral("Reading Shared Strings Table…"));
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
    emit progress(-1);

    //Second, get the list of sheet IDs from the workbook relationships
    emit updateStatus(QStringLiteral("Getting Worksheet IDs…"));
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
                        foreach (const QXmlStreamAttribute &attr, xml.attributes())
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
    emit progress(-1);

    //Third, get the names of the sheets by relationship ID
    emit updateStatus(QStringLiteral("Getting Worksheet Names…"));
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
                        foreach (const QXmlStreamAttribute &attr, xml.attributes())
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
    emit progress(-1);

    //Fourth, find out if a worksheet is named "Test Result Import"
    if (sheetNames.contains(QStringLiteral("Test Result Import")) && relationshipIds.contains(sheetNames[QStringLiteral("Test Result Import")]) && files.contains("xl/" + relationshipIds[sheetNames[QStringLiteral("Test Result Import")]]))
    {
        //It does! Continue parsing.
        //Fifth, read the correct spreadsheet that has the needed data
        emit updateStatus(QStringLiteral("Reading worksheet…"));
        QXmlStreamReader xml(files["xl/" + relationshipIds[sheetNames[QStringLiteral("Test Result Import")]]]);
        int onRow = 0;
        QString onCol = QString();
        bool isSharedString = false; //keep up with whether the current record is a shared string
        QStringList meaningfulCols = {QStringLiteral("D"), QStringLiteral("L"), QStringLiteral("M"), QStringLiteral("N"), QStringLiteral("O")};
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
                            QRegExp re("\\d*");
                            while (!re.exactMatch(ref.toString()) && (ref.length() > 1))
                            {
                                ref = ref.right(ref.length() - 1);
                            }
                            if (re.exactMatch(ref.toString()))
                            {
                                emit initialize(ref.toInt(), 5);
                            }
                        }
                    }
                }
                //read the next line
                else if (xml.name() == "row")
                {
                    onRow++;
                    emit progress(-1);
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
                        if (onCol == QStringLiteral("D"))
                        {
                            curCCI = db.GetCCIByCCI(value.toInt());
                        }
                        else {
                            if (onCol == QStringLiteral("L"))
                                curCCI.importCompliance = value;
                            else if (onCol == QStringLiteral("M"))
                                curCCI.importDateTested = value;
                            else if (onCol == QStringLiteral("N"))
                                curCCI.importTestedBy = value;
                            else if (onCol == QStringLiteral("O"))
                                curCCI.importTestResults = value;
                            curCCI.isImport = true;
                            db.UpdateCCI(curCCI);
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

    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
