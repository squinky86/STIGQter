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
#include "stig.h"
#include "stigcheck.h"
#include "workerstigadd.h"

#include <QXmlStreamReader>

void WorkerSTIGAdd::ParseSTIG(const QByteArray &stig)
{
    //should be the .xml file inside of the STIG .zip file here
    QXmlStreamReader *xml = new QXmlStreamReader(stig);
    STIG s;
    STIGCheck c;
    s.id = -1;
    c.id = -1;
    QList<STIGCheck> checks;
    bool inStigRules = false;
    bool inProfile = false;
    bool inReference = false;
    bool inGroup = false;
    bool addedGroup = false; //if the rule has already been added by the new group tag
    DbManager db;
    while (!xml->atEnd() && !xml->hasError())
    {
        xml->readNext();
        if (!inStigRules)
        {
            if (xml->isStartElement())
            {
                if (!inProfile)
                {
                    if (xml->name() == "title")
                    {
                        s.title = xml->readElementText().trimmed();
                    }
                    else if (xml->name() == "description")
                    {
                        s.description = xml->readElementText().trimmed();
                    }
                    else if (xml->name() == "plain-text" && xml->attributes().hasAttribute("id"))
                    {
                        foreach (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "id")
                            {
                                if (attr.value().toString().trimmed() == "release-info")
                                    s.release = xml->readElementText().trimmed();
                            }
                        }
                    }
                    else if (xml->name() == "version")
                    {
                        s.version = xml->readElementText().toInt();
                    }
                }
                if (xml->name() == "Group")
                {
                    inStigRules = true; //Read all basic STIG data - switch to processing STIG checks
                }
                else if (xml->name() == "Profile")
                {
                    inProfile = true; // stop reading STIG details
                }
            }
        }
        if (inStigRules)
        {
            if (xml->isStartElement())
            {
                if (xml->name() == "Group" && xml->attributes().hasAttribute("id"))
                {
                    inGroup = true;
                    //add the previous rule
                    if (c.id == 0)
                    {
                        addedGroup = true;
                        //new rule; add the previous one!
                        checks.append(c);
                    }
                    foreach (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                        {
                            c.vulnNum = attr.value().toString().trimmed();
                        }
                    }
                }
                if (xml->name() == "Rule" && xml->attributes().hasAttribute("id") && xml->attributes().hasAttribute("severity") && xml->attributes().hasAttribute("weight"))
                {
                    inGroup = false;
                    inReference = false;
                    //check if we moved to another rule
                    if (addedGroup)
                    {
                        addedGroup = false;
                    }
                    else
                    {
                        if (c.id == 0)
                        {
                            //new rule; add the previous one!
                            checks.append(c);
                        }
                    }
                    c.id = 0;
                    foreach (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                        {
                            c.rule = attr.value().toString().trimmed();
                        }
                        else if (attr.name() == "severity")
                        {
                            c.severity = GetSeverity(attr.value().toString().trimmed());
                        }
                        else if (attr.name() == "weight")
                        {
                            c.weight = attr.value().toDouble();
                        }
                    }
                }
                else if (xml->name() == "title")
                {
                    if (inGroup)
                        c.groupTitle = xml->readElementText().trimmed();
                    if (!inGroup && !inReference)
                        c.title = xml->readElementText().trimmed();
                }
                else if (xml->name() == "description")
                {
                    if (!inGroup)
                    {
                        QString toParse = CleanXML(R"(<?xml version="1.0" encoding="UTF-8"?><VulnDescription>)" + xml->readElementText().trimmed() + "</VulnDescription>", true);
                        //parse vulnerability description elements
                        QXmlStreamReader xml2(toParse);
                        while (!xml2.atEnd() && !xml2.hasError())
                        {
                            xml2.readNext();
                            if (xml2.isStartElement())
                            {
                                if (xml2.name() == "VulnDiscussion")
                                {
                                    c.vulnDiscussion = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "FalsePositives")
                                {
                                    c.falsePositives = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "FalseNegatives")
                                {
                                    c.falseNegatives = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "Documentable")
                                {
                                    c.documentable = xml2.readElementText().trimmed().startsWith("t", Qt::CaseInsensitive);
                                }
                                else if (xml2.name() == "Mitigations")
                                {
                                    c.mitigations = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "SeverityOverrideGuidance")
                                {
                                    c.severityOverrideGuidance = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "PotentialImpacts")
                                {
                                    c.potentialImpact = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "ThirdPartyTools")
                                {
                                    c.thirdPartyTools = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "MitigationControl")
                                {
                                    c.mitigationControl = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name() == "Responsibility")
                                {
                                    c.responsibility = xml2.readElementText().trimmed();
                                }
                            }
                        }
                    }
                }
                else if (xml->name() == "ident")
                {
                    QString cci(xml->readElementText().trimmed());
                    if (cci.startsWith("CCI", Qt::CaseInsensitive))
                        c.cciId = db.GetCCIByCCI(GetCCINumber(cci)).id;
                }
                else if (xml->name() == "fixtext")
                {
                    c.fix = xml->readElementText().trimmed();
                }
                else if (xml->name() == "check-content-ref" && xml->attributes().hasAttribute("name"))
                {
                    foreach (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "name")
                        {
                            c.checkContentRef = attr.value().toString().trimmed();
                        }
                    }
                }
                else if (xml->name() == "check-content")
                {
                    c.check = xml->readElementText().trimmed();
                }
                else if (xml->name() == "reference")
                {
                    inReference = true;
                }
            }
        }
    }
    if (inStigRules)
    {
        checks.append(c);
    }
    delete xml;
    db.AddSTIG(s, checks);
}

WorkerSTIGAdd::WorkerSTIGAdd(QObject *parent) : QObject(parent)
{

}

void WorkerSTIGAdd::AddSTIGs(const QStringList &stigs)
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
