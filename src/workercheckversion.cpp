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

#include "workercheckversion.h"
#include "common.h"
#include "dbmanager.h"

/**
 * @class WorkerCheckVersion
 * @brief Verify that the current version of the application is the
 * latest.
 *
 * This class pings the STIGQter server for the latest version of the
 * software.
 */

/**
 * @brief WorkerCheckVersion::WorkerCheckVersion
 * @param parent
 *
 * Default constructor.
 */
WorkerCheckVersion::WorkerCheckVersion(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCheckVersion::process
 *
 * Download the page that displays the version number if an update is
 * needed. If the version is the latest, it displays "OK".
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
        //get the latest version
        QString ret = DownloadPage(QStringLiteral("https://www.stigqter.com/update.php"));
        if (!ret.isNull() && !ret.isEmpty() && !ret.startsWith(QStringLiteral("OK")))
        {
            Q_EMIT ThrowWarning(QStringLiteral("Please update to the latest version of STIGQter."), "Please visit <a href=\"https://www.stigqter.com/\">www.stigqter.com</a> to download version " + ret + ".");
        }
        else
        {
            Q_EMIT updateStatus("STIGQter version is up-to-date.");
        }
    }

    Q_EMIT finished();
}
