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

    emit initialize(1, 0);

    emit updateStatus(QStringLiteral("Opening xlsx file…"));
    QMap<QString, QByteArray> files = GetFilesFromZip(_fileName, QStringLiteral(".xml"));

    //First, create Shared Strings table
    QStringList sst;
    if (files.keys().contains("xl/sharedStrings.xml"))
    {
        //There is a sharedStrings table! Parse it:
        QString toAdd = QString();
        QXmlStreamReader xml(files["xl/sharedStrings.xml"]);
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

    //TODO: parse sheets

    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
