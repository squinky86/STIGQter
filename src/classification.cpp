/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include <QRegularExpression>

/**
 * @brief GetClassification
 * @param marking
 * @return The @a Classification level parsed from a free-text marking.
 *
 * Markings are free text (e.g. "CUI [Controlled by: …]" or
 * "TOP SECRET//SI"). A level is only recognized when the marking contains
 * the complete classification word (matched case-insensitively on word
 * boundaries) — so an incidental marking like "Storage array" does not
 * escalate to SECRET. The highest classification word present wins
 * ("TOP SECRET" is checked before "SECRET"), and "CONTROLLED" is treated
 * as "CUI". Markings with no recognized word are the lowest level,
 * @c classPublicRelease.
 */
Classification GetClassification(const QString &marking)
{
    const QString m = marking.toUpper();
    static const QRegularExpression reTopSecret(QStringLiteral("\\bTOP SECRET\\b"));
    static const QRegularExpression reSecret(QStringLiteral("\\bSECRET\\b"));
    static const QRegularExpression reConfidential(QStringLiteral("\\bCONFIDENTIAL\\b"));
    static const QRegularExpression reCUI(QStringLiteral("\\b(CUI|CONTROLLED)\\b"));
    static const QRegularExpression reFOUO(QStringLiteral("\\bFOUO\\b"));
    static const QRegularExpression reUnclassified(QStringLiteral("\\bUNCLASSIFIED\\b"));

    if (m.contains(reTopSecret))
        return Classification::classTopSecret;
    if (m.contains(reSecret))
        return Classification::classSecret;
    if (m.contains(reConfidential))
        return Classification::classConfidential;
    if (m.contains(reCUI))
        return Classification::classCUI;
    if (m.contains(reFOUO))
        return Classification::classFOUO;
    if (m.contains(reUnclassified))
        return Classification::classUnclassified;
    return Classification::classPublicRelease;
}

/**
 * @brief GetClassificationString
 * @param classification
 * @return The canonical, human-readable label for a @a Classification.
 */
QString GetClassificationString(Classification classification)
{
    switch (classification)
    {
    case Classification::classUnclassified:
        return QStringLiteral("UNCLASSIFIED");
    case Classification::classFOUO:
        return QStringLiteral("FOUO");
    case Classification::classCUI:
        return QStringLiteral("CUI");
    case Classification::classConfidential:
        return QStringLiteral("CONFIDENTIAL");
    case Classification::classSecret:
        return QStringLiteral("SECRET");
    case Classification::classTopSecret:
        return QStringLiteral("TOP SECRET");
    default:
        return QStringLiteral("PUBLIC RELEASE");
    }
}

/**
 * @brief GetClassificationColor
 * @param classification
 * @return The banner color for a @a Classification as a 0xRRGGBB value,
 * usable both by Qt (QColor/QRgb) and by libxlsxwriter (lxw_color_t).
 *
 * Colors follow the standard DoD classification banner palette.
 */
quint32 GetClassificationColor(Classification classification)
{
    switch (classification)
    {
    case Classification::classCUI:
        return 0x502B85; //purple
    case Classification::classConfidential:
        return 0x0033A0; //blue
    case Classification::classSecret:
        return 0xC8102E; //red
    case Classification::classTopSecret:
        return 0xFF8C00; //orange
    case Classification::classPublicRelease:
    case Classification::classUnclassified:
    case Classification::classFOUO:
    default:
        return 0x007A33; //green
    }
}
