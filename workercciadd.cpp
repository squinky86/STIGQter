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
    QList<QString> controls;
    db.DelayCommit(true);
    foreach (const QString &s, todo)
    {
        emit updateStatus("Indexing " + s + "…");
        QUrl family(nist.toString() + s);
        QString fam = DownloadPage(family);
        fam = CleanXML(fam);
        xml = new QXmlStreamReader(fam);
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement() && (xml->name() == "a"))
            {
                if (xml->attributes().hasAttribute("href"))
                {
                    QString href("");
                    foreach (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "href")
                            href = attr.value().toString();
                    }
                    if (href.contains("/control/") && !href.contains('?'))
                    {
                        controls.append(href);
                    }
                }
            }
        }
        delete xml;
        emit progress(-1);
    }
    db.DelayCommit(false);

    //Step 5: get all control and enhancement information
    emit initialize(controls.size() + 3, 1);
    db.DelayCommit(true);
    foreach (const QString &s, controls)
    {
        emit updateStatus("Indexing " + s + "…");
        QUrl control(nist.toString() + s);
        QString c = DownloadPage(control);
        c = CleanXML(c);

        xml = new QXmlStreamReader(c);
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement() && (xml->name() == "title"))
            {
                QString title(xml->readElementText().trimmed());
                QStringRef control(&title, 16, title.length()-16);
                QStringList ctrl = control.toString().split(" - ");
                emit updateStatus("Adding " + ctrl.first() + "—" + ctrl.last() + "…");
                db.AddControl(ctrl.first(), ctrl.last());
            }
            /** TODO: Qt XML parser fails on these elements
            else if (xml->isStartElement() && (xml->name() == "span"))
            {
                if (xml->attributes().hasAttribute("id"))
                {
                    QString id("");
                    foreach (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                            id = attr.value().toString();
                    }
                    if (id.endsWith("EnhancementNameDT"))
                    {
                        QString enhancement(xml->readElementText().trimmed());
                        xml->readNext();
                        qDebug() << xml->name();
                        xml->readNext();
                        qDebug() << xml->name();
                        xml->readNext();
                        qDebug() << xml->name();
                        xml->readNext();
                        qDebug() << xml->name();
                        if (xml->name() == "td")
                        {
                            QString enhancementName(xml->readElementText().trimmed());
                            qDebug() << "\t" << enhancement << enhancementName;
                        }
                    }
                }
            }
            */
            while (c.contains("EnhancementNameDT"))
            {
                //TODO: brute-force parsing until QXmlStreamReader can handle it
                c = c.right(c.length() - c.indexOf("EnhancementNameDT") - 19);
                QString enhancement(c.left(c.indexOf('<')).trimmed());
                c = c.right(c.length() - c.indexOf("<td>") - 4);
                QString name(c.left(c.indexOf('<')).trimmed());
                emit updateStatus("Adding " + enhancement + "—" + name + "…");
                db.AddControl(enhancement, name);
            }
        }

        delete xml;
        emit progress(-1);
    }
    db.DelayCommit(false);

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
                            int cciInt = cci.right(6).toInt();
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
                            c.control.title = control;
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
        emit updateStatus("Adding CCI-" + QString::number(c.cci) + "…");
        db.AddCCI(c.cci, c.control.title, c.definition);
        emit progress(-1);
    }
    db.DelayCommit(false);

    //complete
    emit updateStatus("Done!");
    emit finished();
}
