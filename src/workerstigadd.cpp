/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2020 Jon Hood, http://www.hoodsecurity.com/
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

/**
 * @class WorkerSTIGAdd
 * @brief Add STIGs and SRGs to the internal database.
 *
 * STIGs and SRGs are supplied as compressed archives with XML files
 * that detail the checklist items. The extraction and parsing of
 * these files is handled here.
 */

/**
 * @brief WorkerSTIGAdd::WorkerSTIGAdd
 * @param parent
 *
 * Default constructor.
 */
WorkerSTIGAdd::WorkerSTIGAdd(QObject *parent) : Worker(parent),
    _enableSupplements(false)
{
}

/**
 * @brief WorkerSTIGAdd::ParseSTIG
 * @param stig
 * @param fileName
 *
 * Once a STIG is extracted, it is then parsed for STIGChecks and
 * version information.
 */
void WorkerSTIGAdd::ParseSTIG(const QByteArray &stig, const QString &fileName, const QMap<QString, QByteArray> &supplements)
{
    //should be the .xml file inside of the STIG .zip file here
    auto *xml = new QXmlStreamReader(stig);
    STIG s;
    s.fileName = fileName;
    STIGCheck c;
    s.id = -1;
    c.id = -1;
    QVector<STIGCheck> checks;
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
                    else if (xml->name() == "plain-text" && xml->attributes().hasAttribute(QStringLiteral("id")))
                    {
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name() == "id")
                            {
                                if (attr.value().toString().trimmed() == QStringLiteral("release-info"))
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
                else if (xml->name() == "Benchmark" && xml->attributes().hasAttribute(QStringLiteral("id")))
                {
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                        {
                            s.benchmarkId = attr.value().toString().trimmed();
                        }
                    }
                }
            }
        }
        if (inStigRules)
        {
            if (xml->isStartElement())
            {
                if (xml->name() == "Group" && xml->attributes().hasAttribute(QStringLiteral("id")))
                {
                    inGroup = true;
                    //add the previous rule
                    if (c.id == 0)
                    {
                        addedGroup = true;
                        //new rule; add the previous one!
                        checks.append(c);
                        c.cciIds.clear();
                    }
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                        {
                            c.vulnNum = attr.value().toString().trimmed();
                            if (!c.vulnNum.startsWith(QStringLiteral("V-")) && c.vulnNum.contains(QStringLiteral("V-")))
                                c.vulnNum = c.vulnNum.right(c.vulnNum.length() - c.vulnNum.indexOf(QStringLiteral("V-")));
                        }
                    }
                }
                if (xml->name() == "Rule" && xml->attributes().hasAttribute(QStringLiteral("id")) && xml->attributes().hasAttribute(QStringLiteral("severity")) && xml->attributes().hasAttribute(QStringLiteral("weight")))
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
                            c.cciIds.clear();
                        }
                    }
                    c.id = 0;
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name() == "id")
                        {
                            c.rule = attr.value().toString().trimmed();
                            if (!c.rule.startsWith(QStringLiteral("SV-")) && c.rule.contains(QStringLiteral("SV-")))
                                c.rule = c.rule.right(c.rule.length() - c.rule.indexOf(QStringLiteral("SV-")));
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
                else if (xml->name() == "version")
                {
                    if (!inGroup && !inReference)
                        c.ruleVersion = xml->readElementText().trimmed();
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
                                    c.documentable = xml2.readElementText().trimmed().startsWith(QStringLiteral("t"), Qt::CaseInsensitive);
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
                else if (xml->name() == "identifier")
                {
                    c.targetKey = xml->readElementText().trimmed();
                }
                else if (xml->name() == "ident")
                {
                    bool legacy = false;
                    if (xml->attributes().hasAttribute(QStringLiteral("system")))
                    {
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name().endsWith(QStringLiteral("legacy"), Qt::CaseSensitivity::CaseInsensitive))
                            {
                                legacy = true;
                                QString toAppend = xml->readElementText().trimmed();
                                if (!c.legacyIds.contains(toAppend))
                                {
                                    c.legacyIds.append(toAppend);
                                }
                            }
                        }
                    }
                    if (!legacy)
                    {
                        QString cci(xml->readElementText().trimmed());
                        if (cci.startsWith(QStringLiteral("CCI"), Qt::CaseInsensitive))
                            c.cciIds.append(db.GetCCIByCCI(GetCCINumber(cci), &s).id);
                    }
                }
                else if (xml->name() == "fixtext")
                {
                    c.fix = xml->readElementText().trimmed();
                }
                else if (xml->name() == "check-content-ref" && xml->attributes().hasAttribute(QStringLiteral("name")))
                {
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
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
        c.cciIds.clear();
    }
    delete xml;

    QVector<Supplement> supplementsToAdd;

    if (_enableSupplements)
    {
        Q_FOREACH(const QString key, supplements.keys())
        {
            Supplement sup;
            sup.path = key;
            sup.contents = supplements.value(key);
            supplementsToAdd.append(sup);
        }
    }

    //Sometimes the .zip file contains extraneous .xml files
    if (checks.count() > 0)
        db.AddSTIG(s, checks, supplementsToAdd);
}

/**
 * @brief WorkerSTIGAdd::AddSTIGs
 * @param stigs
 *
 * Before processing the STIGs, set the list of STIG filenames to
 * parse.
 */
void WorkerSTIGAdd::AddSTIGs(const QStringList &stigs)
{
    _todo.append(stigs);
}

/**
 * @brief WorkerSTIGAdd::SetEnableSupplements
 * @param enableSupplements
 *
 * Sets whether to enable or disable importing the STIG supplementary
 * material into the DB
 */
void WorkerSTIGAdd::SetEnableSupplements(bool enableSupplements)
{
    _enableSupplements = enableSupplements;
}

/**
 * @brief WorkerSTIGAdd::process
 *
 * For each provided STIG/SRG zip file,
 * @list
 * @li extract the .xml files
 * @li attempt to parse the .xml file as a STIG checklist
 * @endlist
 */
void WorkerSTIGAdd::process()
{
    //get the list of STIG .zip files selected
    Q_EMIT initialize(_todo.count(), 0);
    //loop through it and parse all XML files inside
    Q_FOREACH(const QString s, _todo)
    {
        Q_EMIT updateStatus("Extracting " + s + "…");
        //get the list of XML files inside the STIG
        QMap<QString, QByteArray> toParse = GetFilesFromZip(s);

        Q_EMIT updateStatus("Parsing " + s + "…");
        Q_FOREACH(const QString stig, toParse.keys())
        {
            if (stig.endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive))
            {
                QByteArray val = toParse.value(stig);
                toParse.remove(stig);
                ParseSTIG(val, TrimFileName(stig), toParse);
            }
        }
        Q_EMIT progress(-1);
    }
    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
