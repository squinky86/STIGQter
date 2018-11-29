/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018 Jon Hood, http://www.hoodsecurity.com/
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
#include "workerstigadd.h"

#include <QXmlStreamReader>

void WorkerSTIGAdd::ParseSTIG(QByteArray stig)
{
    //should be the .xml file inside of the STIG .zip file here
    QXmlStreamReader *xml = new QXmlStreamReader(stig);
    //TODO: parse STIG XML
    delete xml;
}

WorkerSTIGAdd::WorkerSTIGAdd(QObject *parent) : QObject(parent)
{

}

void WorkerSTIGAdd::AddSTIGs(QStringList stigs)
{
    _todo = stigs;
}

void WorkerSTIGAdd::process()
{
    //get the list of STIG .zip files selected
    emit initialize(_todo.count(), 0);
    //loop through it and parse all XML files inside
    foreach(const QString s, _todo)
    {
        updateStatus("Extracting " + s + "…");
        //get the list of XML files inside the STIG
        QByteArrayList toParse = GetXMLFromZip(s.toStdString().c_str());
        updateStatus("Parsing " + s + "…");
        foreach(const QByteArray stig, toParse)
        {
            ParseSTIG(stig);
        }
        emit progress(-1);
    }
    emit updateStatus("Done!");
    emit finished();
}
