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

#include "workercciadd.h"
#include "common.h"
#include "cci.h"
#include "dbmanager.h"

#include <zip.h>

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTemporaryFile>
#include <QXmlStreamReader>

WorkerCCIAdd::WorkerCCIAdd(QObject *parent) : QObject(parent)
{
}

void WorkerCCIAdd::process()
{
    //open database in this thread
    emit initialize(1, 0);
    DbManager db;

    //populate CCIs

    //Step 1: download NIST Families
    emit updateStatus("Downloading Families…");
    QUrl nist("https://nvd.nist.gov");
    QString rmf = DownloadPage(nist.toString() + "/800-53/Rev4/");

    //Step 2: Convert NIST page to XML
    rmf = CleanXML(rmf);

    //Step 3: read the families
    QXmlStreamReader *xml = new QXmlStreamReader(rmf);
    QList<QString> todo;
    db.DelayCommit(true);
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isStartElement() && (xml->name() == "a"))
        {
            if (xml->attributes().hasAttribute("id") && xml->attributes().hasAttribute("href"))
            {
                QString id("");
                QString href("");
                foreach (const QXmlStreamAttribute &attr, xml->attributes())
                {
                    if (attr.name() == "id")
                        id = attr.value().toString();
                    else if (attr.name() == "href")
                        href = attr.value().toString();
                }
                if (id.endsWith("FamilyLink"))
                {
                    QString family(xml->readElementText().trimmed());
                    QString acronym(family.left(2));
                    QString familyName(family.right(family.length() - 5).trimmed());
                    emit updateStatus("Adding " + acronym + "—" + familyName + "…");
                    db.AddFamily(acronym, familyName);
                    todo.append(href);
                }
            }
        }
    }
    db.DelayCommit(false);
    emit initialize(todo.size() + 1, 1);
    delete xml;

    //Step 4: download all controls for each family
    QString rmfControls = DownloadPage(nist.toString() + "/static/feeds/xml/sp80053/rev4/800-53-controls.xml");
    xml = new QXmlStreamReader(rmfControls);
    QString control;
    QString title;
    QString description;
    bool inStatement = false;
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (xml->isStartElement())
        {
            if (inStatement)
            {
                if (xml->name() == "supplemental-guidance")
                {
                    inStatement = false;
                }
                else if (xml->name() == "description")
                {
                    description = xml->readElementText().trimmed();
                }
                else if (xml->name() == "control" || xml->name() == "control-enhancement")
                {
                    inStatement = false;
                    emit updateStatus("Adding " + control);
                    db.AddControl(control, title, description);
                    emit progress(-1);
                }
            }
            else
            {
                if (xml->name() == "statement")
                    inStatement = true;
                else if (xml->name() == "number")
                    control = xml->readElementText().trimmed();
                else if (xml->name() == "title")
                    title = xml->readElementText().trimmed();
                else if (xml->name() == "description")
                    description = xml->readElementText().trimmed();
                else if (xml->name() == "control" || xml->name() == "control-enhancement")
                {
                    emit updateStatus("Adding " + control);
                    db.AddControl(control, title, description);
                    emit progress(-1);
                }
            }
        }
    }
    if (!control.isEmpty())
        db.AddControl(control, title, description);

    //Step 6: download all CCIs
    QTemporaryFile tmpFile;
    QByteArrayList xmlFiles;
    db.DelayCommit(true);
    if (tmpFile.open())
    {
        QUrl ccis("http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip");
        emit updateStatus("Downloading " + ccis.toString() + "…");
        DownloadFile(ccis, &tmpFile);
        emit progress(-1);
        emit updateStatus("Extracting CCIs…");
        xmlFiles = GetXMLFromZip(tmpFile.fileName().toStdString().c_str());
        tmpFile.close();
    }

    //Step 7: Parse all CCIs
    emit updateStatus("Parsing CCIs…");
    QList<CCI> toAdd;
    foreach (const QByteArray &xmlFile, xmlFiles)
    {
        xml = new QXmlStreamReader(xmlFile);
        QString cci("");
        QString definition("");
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name() == "cci_item")
                {
                    if (xml->attributes().hasAttribute("id"))
                    {
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "id")
                                cci = attr.value().toString();
                        }
                    }
                }
                else if (xml->name() == "definition")
                {
                    definition = xml->readElementText();
                }
                else if (xml->name() == "reference")
                {
                    if (xml->attributes().hasAttribute("version") && xml->attributes().hasAttribute("index") && !cci.isEmpty())
                    {
                        QString version("");
                        QString index("");
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "version")
                                version = attr.value().toString();
                            else if (attr.name() == "index")
                                index = attr.value().toString();
                        }
                        if (!version.isEmpty() && !index.isEmpty() && (version == "4")) //Only Rev 4 supported
                        {
                            int cciInt = cci.rightRef(6).toInt();
                            QString control = index;
                            if (control.contains(' '))
                                control = control.left(control.indexOf(" "));
                            if (control.contains('.'))
                                control = control.left(control.indexOf("."));
                            if (index.contains('('))
                            {
                                int tmpInt = index.indexOf('(');
                                QStringRef enhancement(&index, tmpInt, index.indexOf(')') - tmpInt + 1);
                                control.append(enhancement);
                            }
                            CCI c;
                            c.cci = cciInt;
                            c.controlId = db.GetControl(control).id;
                            c.definition = definition;
                            toAdd.append(c);
                            //delayed add
                            //db.AddCCI(cciInt, control, definition);
                        }
                    }
                }
            }
        }
        delete xml;
    }
    QFile::remove(tmpFile.fileName());

    //Step 8: add CCIs
    emit initialize(toAdd.size() + 1, 1);
    db.DelayCommit(true);
    foreach (const CCI &c, toAdd)
    {
        CCI tmpCCI = c;
        emit updateStatus("Adding CCI-" + QString::number(c.cci) + "…");
        db.AddCCI(tmpCCI);
        emit progress(-1);
    }
    db.DelayCommit(false);

    //complete
    emit updateStatus("Done!");
    emit finished();
}
