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

#ifndef ASSETVIEW_H
#define ASSETVIEW_H

#include "asset.h"
#include "cklcheck.h"
#include "stigcheck.h"

#include <QListWidget>
#include <QWidget>

namespace Ui {
class AssetView;
}

class AssetView : public QWidget
{
    Q_OBJECT

public:
    explicit AssetView(QWidget *parent = nullptr);
    AssetView(const Asset &a, QWidget *parent = nullptr);
    ~AssetView();
    void Display();
    void SelectSTIGs();
    void ShowChecks();
    void UpdateCKLCheck(const CKLCheck &cc);
    void UpdateSTIGCheck(const STIGCheck &sc);

private slots:
    void CheckSelected(QListWidgetItem *current, QListWidgetItem *previous);
    void UpdateCKL();
    void UpdateCKLStatus(const QString &val);
    void UpdateCKLSeverity(const QString &val);
    void UpdateSTIGs();

private:
    Ui::AssetView *ui;
    Asset _a;
    QString _justification;
    void SetItemColor(QListWidgetItem *i, const Status &stat, const Severity &sev);
};

#endif // ASSETVIEW_H
