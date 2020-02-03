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

#ifndef ASSETVIEW_H
#define ASSETVIEW_H

#include "asset.h"
#include "cklcheck.h"
#include "stigcheck.h"
#include "stigqter.h"

#include <QLabel>
#include <QListWidget>
#include <QProgressBar>
#include <QShortcut>
#include <QTimer>
#include <QWidget>

namespace Ui {
class AssetView;
}

class AssetView : public QWidget
{
    Q_OBJECT

public:
    AssetView() = delete;
    AssetView(const AssetView &av) = delete;
    explicit AssetView(Asset &asset, QWidget *parent = nullptr);
    ~AssetView() override;
    void DisableInput();
    void Display();
    void EnableInput();
    void SelectSTIGs(const QString &search = QString());
    void ShowChecks(bool countOnly = false);
    void UpdateCKLCheck(const CKLCheck &cklCheck);
    void UpdateSTIGCheck(const STIGCheck &stigCheck);
    void SetTabIndex(int index);
#ifdef USE_TESTS
    void RunTests();
#endif

private Q_SLOTS:
    void CheckSelected(QListWidgetItem *current, QListWidgetItem *previous);
    void CheckSelectedChanged();
    void CountChecks();
    void DeleteAsset(bool confirm = false);
    void FilterSTIGs(const QString &text);
    void ImportXCCDF(const QString &filename = QString());
    void KeyShortcutCtrlN();
    void KeyShortcutCtrlO();
    void KeyShortcutCtrlR();
    void KeyShortcutCtrlX();
    void RenameAsset(const QString &name = QString());
    void SaveCKL(const QString &name = QString());
    void UpdateChecks();
    void UpdateCKL();
    void UpdateCKLHelper();
    void UpdateCKLStatus(const QString &val);
    void UpdateCKLSeverity(const QString &val);
    void UpdateSTIGs();

private:
    Ui::AssetView *ui;
    Asset _asset;
    QString _justification;
    QTimer _timer;
    QTimer _timerChecks;
    QList<QShortcut*> _shortcuts;
    bool _updateStatus;
    int _tabIndex;
    void KeyShortcut(Status action);
    void SetItemColor(QListWidgetItem *i, Status stat, Severity sev);
    bool _isFiltered;
    QProgressBar *_progressBar;
    QLabel *_lblStatus;
    STIGQter *_parent;

Q_SIGNALS:
    void CloseTab(int);
};

#endif // ASSETVIEW_H
