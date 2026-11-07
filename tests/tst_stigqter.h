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

#pragma once

#include <QObject>

class STIGQter;

class TestSTIGQter : public QObject
{
    Q_OBJECT

public:
    explicit TestSTIGQter(QObject *parent = nullptr);

private:
    STIGQter *w = nullptr;
    QString _testDataPath;
    void procEvents(int timeout = 120000);

private Q_SLOTS:
    void initTestCase();
    void test00_Classification();
    void test00_LocalFileDownload();
    void test00_StableRelease();
    void test00_PublishedRelease();
    void test00_HttpDownloads();
    void test00_UntrustedTls();
    void test00_ContentCatalog();
    void test00_ArchiveFailures();
    void test00_XccdfParser();
    void test00_WorkerCleanup();
    void test01_IndexCCIs();
    void test02_UpdateCCI();
    void test03_IndexSTIGs();
    void test04a_RunInterface();
    void test04b_RunInterface();
    void test04c_RunInterface();
    void test04c_ProjectLoadSafety();
    void test04c_ProjectUpgrade();
    void test04c_ChecklistFormats();
    void test04c_UpgradePreservation();
    void test04c_XccdfTransaction();
    void test04c_ChecklistAutosave();
    void test04c_AssessmentFieldsAndOptions();
    void test04d_RunInterface();
    void test04e_RunInterface();
    void test04f_Escalation();
    void test05_DeleteAndHash();
    void test06_CKLImport();
    void test07_Cleanup();
    void cleanupTestCase();
};
