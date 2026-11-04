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

#include "workercheckversion.h"
#include "common.h"
#include "dbmanager.h"
#include "download.h"
#include "releasemetadata.h"

/**
 * @class WorkerCheckVersion
 * @brief Verify that the current version of the application is the
 * latest.
 *
 * Reads the public GitHub Pages stable-release manifest. No assessment
 * content or desktop GitHub credentials are sent.
 */

/**
 * @brief WorkerCheckVersion::WorkerCheckVersion
 * @param parent
 *
 * Default constructor.
 */
WorkerCheckVersion::WorkerCheckVersion(QObject *parent) : Worker(parent), _metadataUrl(ReleaseMetadata::latestUrl())
{
}

/**
 * @brief WorkerCheckVersion::process
 *
 * Compare validated stable metadata with the running application version.
 */
void WorkerCheckVersion::process()
{
    Worker::process();

    Q_EMIT updateStatus("Checking for latest version.");

    //open database in this thread
    Q_EMIT initialize(1, 0);
    DbManager db;

    if (db.GetVariable("checkVersion").compare("true", Qt::CaseInsensitive) == 0)
    {
        const auto response = Downloads::fetch(_metadataUrl);
        ReleaseMetadata::StableRelease release;
        QString error;
        if (!response.ok || !ReleaseMetadata::parse(response.data, release, error))
        {
            Q_EMIT updateStatus(QStringLiteral("Unable to check for updates. You can continue working offline."));
            Warning(QStringLiteral("Version check unavailable"), response.ok ? error : response.error, true);
        }
        else if (ReleaseMetadata::isNewer(release, VERSION))
        {
            Q_EMIT ThrowWarning(QStringLiteral("A new stable version of STIGQter is available."),
                                QStringLiteral("Download STIGQter %1 from <a href=\"%2\">GitHub Releases</a>.")
                                .arg(release.version.toString().toHtmlEscaped(), release.page.toString().toHtmlEscaped()));
        }
        else
        {
            Q_EMIT updateStatus(QStringLiteral("No newer stable STIGQter release is available."));
        }
    }

    Q_EMIT finished();
}

void WorkerCheckVersion::SetMetadataUrl(const QUrl &url)
{
    _metadataUrl = url;
}
