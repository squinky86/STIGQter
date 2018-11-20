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

#include "cciworker.h"
#include "common.h"

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QXmlStreamReader>

CCIWorker::CCIWorker()
{
}

void CCIWorker::process()
{
    //open database in this thread
    emit initialize(1, 0);
    DbManager db;

    //populate CCIs

    //Step 1: download NIST Families
    QUrl nist("https://nvd.nist.gov");
    QString rmf = DownloadPage(nist.toString() + "/800-53/Rev4/");

    //Step 2: Convert NIST page to XHTML
    rmf = HTML2XHTML(rmf);

    //Step 3: read the families
    QXmlStreamReader *xml = new QXmlStreamReader(rmf);
    QList<QString> todo;
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
                    QString family(xml->readElementText());
                    QString acronym(family.left(2));
                    QString familyName(family.right(family.length() - 5));
                    db.AddFamily(acronym, familyName);
                    todo.append(href);
                }
            }
        }
    }
    emit initialize(todo.size() + 1, 1);
    delete xml;

    //Step 4: download all controls for each family
    QList<QString> controls;
    foreach (const QString &s, todo)
    {
        QUrl family(nist.toString() + s);
        QString fam = DownloadPage(family);
        fam = HTML2XHTML(fam);
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

    //Step 5: get all control and enhancement information
    emit initialize(controls.size() + 1, 1);
    foreach (const QString &s, controls)
    {
        QUrl control(nist.toString() + s);
        QString c = DownloadPage(control);
        c = HTML2XHTML(c);
        xml = new QXmlStreamReader(c);
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement() && (xml->name() == "title"))
            {
                QString title(xml->readElementText().trimmed());
                QStringRef control(&title, 16, title.length()-16);
                QStringList ctrl = control.toString().split(" - ");
                qDebug() << ctrl;
                //TODO: insert controls
            }
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
                        qDebug() << "\t" << enhancement;
                    }
                }
            }
        }
        if (xml->hasError())
            qDebug() << xml->error();
        delete xml;
        emit progress(-1);
    }

    //TODO: download CCIs

    //complete
    emit finished();
}
