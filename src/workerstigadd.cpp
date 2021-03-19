/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
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
                    if (xml->name().compare(QStringLiteral("title")) == 0)
                    {
                        s.title = xml->readElementText().trimmed();
                    }
                    else if (xml->name().compare(QStringLiteral("description")) == 0)
                    {
                        s.description = xml->readElementText().trimmed();
                    }
                    else if ((xml->name().compare(QStringLiteral("plain-text")) == 0) && xml->attributes().hasAttribute(QStringLiteral("id")))
                    {
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if (attr.name().compare(QStringLiteral("id")) == 0)
                            {
                                if (attr.value().toString().trimmed() == QStringLiteral("release-info"))
                                    s.release = xml->readElementText().trimmed();
                            }
                        }
                    }
                    else if (xml->name().compare(QStringLiteral("version")) == 0)
                    {
                        s.version = xml->readElementText().toInt();
                    }
                }
                if (xml->name().compare(QStringLiteral("Group")) == 0)
                {
                    inStigRules = true; //Read all basic STIG data - switch to processing STIG checks
                }
                else if (xml->name().compare(QStringLiteral("Profile")) == 0)
                {
                    inProfile = true; // stop reading STIG details
                }
                else if ((xml->name().compare(QStringLiteral("Benchmark")) == 0) && xml->attributes().hasAttribute(QStringLiteral("id")))
                {
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name().compare(QStringLiteral("id")) == 0)
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
                if ((xml->name().compare(QStringLiteral("Group")) == 0) && xml->attributes().hasAttribute(QStringLiteral("id")))
                {
                    inGroup = true;
                    //add the previous rule
                    if (c.id == 0)
                    {
                        addedGroup = true;
                        //new rule; add the previous one!
                        checks.append(c);
                        c.cciIds.clear();
                        c.legacyIds.clear();
                    }
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name().compare(QStringLiteral("id")) == 0)
                        {
                            c.vulnNum = attr.value().toString().trimmed();
                            if (!c.vulnNum.startsWith(QStringLiteral("V-")) && c.vulnNum.contains(QStringLiteral("V-")))
                                c.vulnNum = c.vulnNum.right(c.vulnNum.length() - c.vulnNum.indexOf(QStringLiteral("V-")));
                        }
                    }
                }
                if ((xml->name().compare(QStringLiteral("Rule")) == 0) && xml->attributes().hasAttribute(QStringLiteral("id")) && xml->attributes().hasAttribute(QStringLiteral("severity")) && xml->attributes().hasAttribute(QStringLiteral("weight")))
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
                            c.legacyIds.clear();
                        }
                    }
                    c.id = 0;
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name().compare(QStringLiteral("id")) == 0)
                        {
                            c.rule = attr.value().toString().trimmed();
                            if (!c.rule.startsWith(QStringLiteral("SV-")) && c.rule.contains(QStringLiteral("SV-")))
                                c.rule = c.rule.right(c.rule.length() - c.rule.indexOf(QStringLiteral("SV-")));
                        }
                        else if (attr.name().compare(QStringLiteral("severity")) == 0)
                        {
                            c.severity = GetSeverity(attr.value().toString().trimmed());
                        }
                        else if (attr.name().compare(QStringLiteral("weight")) == 0)
                        {
                            c.weight = attr.value().toDouble();
                        }
                    }
                }
                else if (xml->name().compare(QStringLiteral("version")) == 0)
                {
                    if (!inGroup && !inReference)
                        c.ruleVersion = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("title")) == 0)
                {
                    if (inGroup)
                        c.groupTitle = xml->readElementText().trimmed();
                    if (!inGroup && !inReference)
                        c.title = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("description")) == 0)
                {
                    if (!inGroup)
                    {
                        QString toParse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VulnDescription>" + XMLVulnFix(xml->readElementText().trimmed()) + "</VulnDescription>";

                        //parse vulnerability description elements
                        QXmlStreamReader xml2(toParse);
                        while (!xml2.atEnd() && !xml2.hasError())
                        {
                            xml2.readNext();
                            if (xml2.isStartElement())
                            {
                                if (xml2.name().compare(QStringLiteral("VulnDiscussion")) == 0)
                                {
                                    c.vulnDiscussion = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("FalsePositives")) == 0)
                                {
                                    c.falsePositives = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("FalseNegatives")) == 0)
                                {
                                    c.falseNegatives = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("Documentable")) == 0)
                                {
                                    c.documentable = xml2.readElementText().trimmed().startsWith(QStringLiteral("t"), Qt::CaseInsensitive);
                                }
                                else if (xml2.name().compare(QStringLiteral("Mitigations")) == 0)
                                {
                                    c.mitigations = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("SeverityOverrideGuidance")) == 0)
                                {
                                    c.severityOverrideGuidance = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("PotentialImpacts")) == 0)
                                {
                                    c.potentialImpact = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("ThirdPartyTools")) == 0)
                                {
                                    c.thirdPartyTools = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("MitigationControl")) == 0)
                                {
                                    c.mitigationControl = xml2.readElementText().trimmed();
                                }
                                else if (xml2.name().compare(QStringLiteral("Responsibility")) == 0)
                                {
                                    c.responsibility = xml2.readElementText().trimmed();
                                }
                            }
                        }
                    }
                }
                else if (xml->name().compare(QStringLiteral("identifier")) == 0)
                {
                    c.targetKey = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("ident")) == 0)
                {
                    bool legacy = false;

                    if (xml->attributes().hasAttribute(QStringLiteral("system")))
                    {
                        Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                        {
                            if ((attr.name().compare(QStringLiteral("system")) == 0) && attr.value().endsWith(QStringLiteral("legacy"), Qt::CaseSensitivity::CaseInsensitive))
                            {
                                legacy = true;
                                break;
                            }
                        }
                    }

                    QString elementText = xml->readElementText().trimmed();

                    if (legacy)
                    {
                        if (!c.legacyIds.contains(elementText))
                        {
                            c.legacyIds.append(elementText);
                        }
                    }
                    else
                    {
                        if (elementText.startsWith(QStringLiteral("CCI"), Qt::CaseInsensitive))
                        {
                            auto tmpCci = db.GetCCIByCCI(GetCCINumber(elementText), &s);
                            if (tmpCci.id >= 0 && !c.cciIds.contains(tmpCci.id))
                                c.cciIds.append(tmpCci.id);
                        }
                    }
                }
                else if (xml->name().compare(QStringLiteral("fixtext")) == 0)
                {
                    c.fix = xml->readElementText().trimmed();
                }
                else if ((xml->name().compare(QStringLiteral("check-content-ref")) == 0) && xml->attributes().hasAttribute(QStringLiteral("name")))
                {
                    Q_FOREACH (const QXmlStreamAttribute &attr, xml->attributes())
                    {
                        if (attr.name().compare(QStringLiteral("name")) == 0)
                        {
                            c.checkContentRef = attr.value().toString().trimmed();
                        }
                    }
                }
                else if (xml->name().compare(QStringLiteral("check-content")) == 0)
                {
                    c.check = xml->readElementText().trimmed();
                }
                else if (xml->name().compare(QStringLiteral("reference")) == 0)
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
        c.legacyIds.clear();
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
 * @brief WorkerSTIGAdd::XMLVulnFix
 * @param xml
 * @return formatted XML data encoded properly for STIG vulnDescription field
 */
QString WorkerSTIGAdd::XMLVulnFix(const QString &xml)
{
        QString temp(xml);

        temp.replace(QStringLiteral("&"), QStringLiteral("&amp;"));
        temp.replace(QStringLiteral("'"), QStringLiteral("&apos;"));
        temp.replace(QStringLiteral("\""), QStringLiteral("&quot;"));
        temp.replace(QStringLiteral("<"), QStringLiteral("&lt;"));
        temp.replace(QStringLiteral(">"), QStringLiteral("&gt;"));
        temp.replace(QStringLiteral("&lt;VulnDiscussion&gt;"), QStringLiteral("<VulnDiscussion>"));
        temp.replace(QStringLiteral("&lt;/VulnDiscussion&gt;"), QStringLiteral("</VulnDiscussion>"));
        temp.replace(QStringLiteral("&lt;FalsePositives&gt;"), QStringLiteral("<FalsePositives>"));
        temp.replace(QStringLiteral("&lt;/FalsePositives&gt;"), QStringLiteral("</FalsePositives>"));
        temp.replace(QStringLiteral("&lt;FalseNegatives&gt;"), QStringLiteral("<FalseNegatives>"));
        temp.replace(QStringLiteral("&lt;/FalseNegatives&gt;"), QStringLiteral("</FalseNegatives>"));
        temp.replace(QStringLiteral("&lt;Documentable&gt;"), QStringLiteral("<Documentable>"));
        temp.replace(QStringLiteral("&lt;/Documentable&gt;"), QStringLiteral("</Documentable>"));
        temp.replace(QStringLiteral("&lt;Mitigations&gt;"), QStringLiteral("<Mitigations>"));
        temp.replace(QStringLiteral("&lt;/Mitigations&gt;"), QStringLiteral("</Mitigations>"));
        temp.replace(QStringLiteral("&lt;SeverityOverrideGuidance&gt;"), QStringLiteral("<SeverityOverrideGuidance>"));
        temp.replace(QStringLiteral("&lt;/SeverityOverrideGuidance&gt;"), QStringLiteral("</SeverityOverrideGuidance>"));
        temp.replace(QStringLiteral("&lt;PotentialImpacts&gt;"), QStringLiteral("<PotentialImpacts>"));
        temp.replace(QStringLiteral("&lt;/PotentialImpacts&gt;"), QStringLiteral("</PotentialImpacts>"));
        temp.replace(QStringLiteral("&lt;ThirdPartyTools&gt;"), QStringLiteral("<ThirdPartyTools>"));
        temp.replace(QStringLiteral("&lt;/ThirdPartyTools&gt;"), QStringLiteral("</ThirdPartyTools>"));
        temp.replace(QStringLiteral("&lt;MitigationControl&gt;"), QStringLiteral("<MitigationControl>"));
        temp.replace(QStringLiteral("&lt;/MitigationControl&gt;"), QStringLiteral("</MitigationControl>"));
        temp.replace(QStringLiteral("&lt;Responsibility&gt;"), QStringLiteral("<Responsibility>"));
        temp.replace(QStringLiteral("&lt;/Responsibility&gt;"), QStringLiteral("</Responsibility>"));

        return temp;
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
    Worker::process();

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
            if (stig.endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive) || stig.endsWith(QStringLiteral("Manual_STIG.xml"), Qt::CaseInsensitive))
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
