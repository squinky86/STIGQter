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

#include "ccithread.h"
#include "common.h"

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QXmlStreamReader>

CCIThread::CCIThread()
{
}

void CCIThread::run()
{
    //open database in this thread
    DbManager db;

    //populate CCIs

    //Step 1: download NIST Families
    QUrl nist("https://nvd.nist.gov/800-53/Rev4/");
    QString rmf = DownloadPage(nist);

    //Step 2: Convert NIST page to XHTML
    rmf = HTML2XHTML(rmf);

    //read the families
    QXmlStreamReader xml(rmf);
    int numFamilies = 0;
    while (!xml.atEnd() && !xml.hasError())
    {
        xml.readNext();
        if (xml.isStartElement() && (xml.name() == "a"))
        {
            if (xml.attributes().hasAttribute("id") && xml.attributes().hasAttribute("href"))
            {
                QString id("");
                QString href("");
                foreach(const QXmlStreamAttribute &attr, xml.attributes())
                {
                    if (attr.name() == "id")
                        id = attr.value().toString();
                    else if (attr.name() == "href")
                        href = attr.value().toString();
                }
                if (id.endsWith("FamilyLink"))
                {
                    QString family(xml.readElementText());
                    QString acronym(family.left(2));
                    QString familyName(family.right(family.length() - 5));
                    db.AddFamily(acronym, familyName);
                    numFamilies++;
                }
            }
        }
    }

    //TODO: download Controls
    //TODO: download CCIs
    //complete
}
