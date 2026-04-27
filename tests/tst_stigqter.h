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
    void procEvents();

private Q_SLOTS:
    void initTestCase();
    void test01_IndexCCIs();
    void test02_UpdateCCI();
    void test03_IndexSTIGs();
    void test04_RunInterface();
    void test05_DeleteAndHash();
    void test06_CKLImport();
    void test07_Cleanup();
    void cleanupTestCase();
};
