/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "stig.h"
#include "stigcheck.h"
#include "stigedit.h"
#include "supplement.h"
#include "workerstigexport.h"

#include "ui_stigedit.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>

/**
 * @brief STIGEdit::STIGEdit
 * @param stig
 * @param parent
 *
 * Main Constructor
 */
STIGEdit::STIGEdit(STIG &stig, QWidget *parent) : TabViewWidget (parent),
    ui(new Ui::STIGEdit),
    _s(stig)
{
    ui->setupUi(this);

    ui->txtTitle->setText(_s.title);
    ui->txtDescription->setText(_s.description);
    ui->txtVersion->setText(QString::number(_s.version));
    QString tmpRelease = _s.release;
    if (tmpRelease.contains(QStringLiteral("Release: ")))
    {
        tmpRelease = tmpRelease.right(tmpRelease.size() - 9);
        if (tmpRelease.contains(QStringLiteral(" ")))
        {
            ui->txtRelease->setText(tmpRelease.left(tmpRelease.indexOf(QStringLiteral(" "))));
        }
    }
    if (tmpRelease.contains(QStringLiteral("Date: ")))
    {
        tmpRelease = tmpRelease.right(tmpRelease.size() - tmpRelease.indexOf(QStringLiteral("Date: ")) - 6);

        QDate d = QDate::fromString(tmpRelease, QStringLiteral("dd MMM yyyy"));
        ui->date->setDate(d);
    }

    UpdateChecks();
    UpdateSupplements();

    DbManager db;
    for (auto cci : db.GetCCIs())
    {
        ui->cbCCIs->addItem(QString::number(cci.cci), QVariant::fromValue(cci));
    }
}

/**
 * @brief STIGEdit::DisableInput
 *
 * Disable all button input
 */
void STIGEdit::DisableInput()
{
    ui->btnSave->setEnabled(false);
    ui->btnNewCheck->setEnabled(false);
    ui->btnDeleteCheck->setEnabled(false);
    ui->btnCciAdd->setEnabled(false);
    ui->btnCciDelete->setEnabled(false);
    ui->txtTitle->setEnabled(false);
    ui->txtRelease->setEnabled(false);
    ui->txtVersion->setEnabled(false);
    ui->txtDescription->setEnabled(false);
}

/**
 * @brief STIGEdit::EnableInput
 *
 * Enable all button input
 */
void STIGEdit::EnableInput()
{
    ui->btnSave->setEnabled(true);
    ui->btnNewCheck->setEnabled(true);
    ui->btnDeleteCheck->setEnabled(!ui->lstChecks->selectedItems().isEmpty());
    ui->btnCciAdd->setEnabled(true);
    ui->btnCciDelete->setEnabled(true);
    ui->txtTitle->setEnabled(true);
    ui->txtRelease->setEnabled(true);
    ui->txtVersion->setEnabled(true);
    ui->txtDescription->setEnabled(true);
}

/**
 * @brief STIGEdit::GetTabType
 * @return Indication that this is a STIG editing tab
 */
TabType STIGEdit::GetTabType()
{
    return TabType::stig;
}

void STIGEdit::RunTests()
{
    int onTest = 0;

    for (int i = 0; (i < ui->lstChecks->count()) && (i < 10); ++i)
    {
        qDebug("STIGEdit test %d: Select STIGCheck %d", onTest++, i);
        ui->lstChecks->item(i)->setSelected(true);
        ProcEvents();

        qDebug("STIGEdit test %d: Change STIGCheck", onTest++);
        ui->txtFix->setText(QStringLiteral("FIX IT"));
        ui->txtCheckTitle->setText(ui->txtCheckTitle->text() + QStringLiteral(" (edited)"));
        UpdateCheck();
        ProcEvents();

        qDebug("STIGEdit test %d: Change severity/documentable", onTest++);
        ui->cboBoxSeverity->setCurrentIndex((ui->cboBoxSeverity->currentIndex() + 1) % ui->cboBoxSeverity->count());
        ui->cbDocumentable->setChecked(!ui->cbDocumentable->isChecked());
        ProcEvents();

        qDebug("STIGEdit test %d: Add and remove a CCI (net-zero)", onTest++);
        int cciCount = ui->lstCCIs->count();
        AddCCI();
        ProcEvents();
        if (ui->lstCCIs->count() > cciCount)
        {
            //remove the CCI just added so the check's mapping is left intact
            ui->lstCCIs->item(ui->lstCCIs->count() - 1)->setSelected(true);
            DeleteCCI();
            ProcEvents();
        }
    }

    qDebug("STIGEdit test %d: Add a new check", onTest++);
    int checkCount = ui->lstChecks->count();
    AddCheck();
    ProcEvents();

    qDebug("STIGEdit test %d: Delete the new check", onTest++);
    if (ui->lstChecks->count() > checkCount)
    {
        ui->lstChecks->setCurrentRow(ui->lstChecks->count() - 1);
        ProcEvents();
        DeleteCheck();
        ProcEvents();
    }

    qDebug("STIGEdit test %d: Edit STIG title", onTest++);
    ui->txtTitle->setText(ui->txtTitle->text() + QStringLiteral(" (edited)"));
    ProcEvents();

    qDebug("STIGEdit test %d: Export STIG to zip", onTest++);
    SaveSTIG(QStringLiteral("tests/exported_stig.zip"));
    ProcEvents();

    Q_EMIT CloseTab(_tabIndex);
}

/**
 * @brief STIGEdit::UpdateChecks
 *
 * Update the list of STIGChecks
 */
void STIGEdit::UpdateChecks()
{
    ui->lstChecks->clear();
    for (auto sc : _s.GetSTIGChecks())
    {
        auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstChecks container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<STIGCheck>(sc));
        tmpItem->setText(PrintSTIGCheck(sc));
        ui->lstChecks->addItem(tmpItem);
    }
}

/**
 * @brief STIGEdit::UpdateSupplements
 *
 * Update the list of STIG supplementary material
 */
void STIGEdit::UpdateSupplements()
{
    ui->lstSupplements->clear();
    for (auto s : _s.GetSupplements())
    {
        auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstChecks container
        tmpItem->setData(Qt::UserRole, QVariant::fromValue<Supplement>(s));
        tmpItem->setText(PrintSupplement(s));
        ui->lstSupplements->addItem(tmpItem);
    }
}

/**
 * @brief STIGEdit::AddCCI
 *
 * Adds the selected CCI to the STIGCheck's mapping
 */
void STIGEdit::AddCCI()
{
    CCI toAdd = ui->cbCCIs->currentData().value<CCI>();
    for (int i = 0; i < ui->lstCCIs->count(); ++i)
    {
        QListWidgetItem *cciItem = ui->lstCCIs->item(i);
        if (cciItem)
        {
            CCI cci = cciItem->data(Qt::UserRole).value<CCI>();
            if (cci == toAdd)
                return;
        }
    }
    auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstCCIs container
    tmpItem->setData(Qt::UserRole, QVariant::fromValue<CCI>(toAdd));
    tmpItem->setText(PrintCCI(toAdd));
    ui->lstCCIs->addItem(tmpItem);
    QApplication::processEvents();
    UpdateCheck();
}

/**
 * @brief STIGEdit::DeleteCCI
 *
 * Removes the selected CCI(s) from the current STIGCheck's mapping
 */
void STIGEdit::DeleteCCI()
{
    QList<QListWidgetItem *> selected = ui->lstCCIs->selectedItems();
    if (selected.isEmpty())
        return;
    for (QListWidgetItem *i : selected)
    {
        //taking the row deletes the item; free it after removing from the list
        delete ui->lstCCIs->takeItem(ui->lstCCIs->row(i));
    }
    QApplication::processEvents();
    UpdateCheck();
}

/**
 * @brief STIGEdit::AddCheck
 *
 * Adds a new, blank STIGCheck to the STIG and selects it for editing
 */
void STIGEdit::AddCheck()
{
    DbManager db;
    STIGCheck sc;
    sc.stigId = _s.id;
    sc.vulnNum = QStringLiteral("V-");
    sc.rule = QStringLiteral("SV-");
    sc.ruleVersion = QString();
    sc.severity = Severity::medium;
    sc.weight = 10.0;
    sc.title = QStringLiteral("New Check");
    sc.documentable = false;
    sc.isRemap = false;
    db.AddSTIGCheck(_s, sc);

    UpdateChecks();

    //select the newly added check (last item) so it is ready to edit
    if (ui->lstChecks->count() > 0)
        ui->lstChecks->setCurrentRow(ui->lstChecks->count() - 1);

    if (_parent)
        _parent->Display();
}

/**
 * @brief STIGEdit::DeleteCheck
 *
 * Deletes the selected STIGCheck(s) from the STIG
 */
void STIGEdit::DeleteCheck()
{
    QList<QListWidgetItem *> selected = ui->lstChecks->selectedItems();
    if (selected.isEmpty())
        return;

    const QMessageBox::StandardButton reply = IgnoreWarnings ? QMessageBox::Yes : QMessageBox::question(
        this, QStringLiteral("Delete STIG Checks"),
        QStringLiteral("Delete %1 selected check(s) from this STIG? This cannot be undone.").arg(selected.count()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    DbManager db;
    for (QListWidgetItem *i : selected)
    {
        auto sc = i->data(Qt::UserRole).value<STIGCheck>();
        db.DeleteSTIGCheck(sc);
    }

    UpdateChecks();
    ui->lstCCIs->clear();

    if (_parent)
        _parent->Display();
}

/**
 * @brief STIGEdit::SelectCheck
 *
 * A new STIGCheck has been selected
 */
void STIGEdit::SelectCheck()
{
    //while loading, the setText()/setChecked()/setCurrentText() calls below emit
    //change signals wired to UpdateCheck(); guard against re-saving during load
    _loading = true;
    for (QListWidgetItem *i : ui->lstChecks->selectedItems())
    {
        auto sc = i->data(Qt::UserRole).value<STIGCheck>();
        ui->txtCheckRule->setText(sc.rule);
        ui->txtCheckRuleVersion->setText(sc.ruleVersion);
        ui->txtCheckTitle->setText(sc.title);
        ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
        ui->cbDocumentable->setChecked(sc.documentable);
        ui->txtDiscussion->setText(sc.vulnDiscussion);
        ui->txtFalsePositives->setText(sc.falsePositives);
        ui->txtFalseNegatives->setText(sc.falseNegatives);
        ui->txtFix->setText(sc.fix);
        ui->txtCheck->setText(sc.check);
        ui->lstCCIs->clear();
        for (auto cci : sc.GetCCIs())
        {
            auto *tmpItem = new QListWidgetItem(); //memory managed by ui->lstCCIs container
            tmpItem->setData(Qt::UserRole, QVariant::fromValue<CCI>(cci));
            tmpItem->setText(PrintCCI(cci));
            ui->lstCCIs->addItem(tmpItem);
        }
    }
    _loading = false;
    ui->btnDeleteCheck->setEnabled(!ui->lstChecks->selectedItems().isEmpty());
}

/**
 * @brief STIGEdit::UpdateSTIG
 *
 * Update the database with the new STIG values
 */
void STIGEdit::UpdateSTIG()
{
    DbManager db;
    _s.title = ui->txtTitle->text();
    _s.release = "Release: " + ui->txtRelease->text() + " Benchmark Date: " + ui->date->date().toString(QStringLiteral("dd MMM yyyy"));
    _s.version = ui->txtVersion->text().toInt();
    db.UpdateSTIG(_s);

    Q_EMIT RenameTab(_tabIndex, PrintSTIG(_s));

    if (_parent)
    {
        _parent->Display();
    }
}

/**
 * @brief STIGEdit::UpdateCheck
 *
 * Update the database with the new STIGCheck values
 */
void STIGEdit::UpdateCheck()
{
    //ignore change signals raised while SelectCheck() is populating the widgets
    if (_loading)
        return;

    DbManager db;
    for (QListWidgetItem *i : ui->lstChecks->selectedItems())
    {
        auto sc = i->data(Qt::UserRole).value<STIGCheck>();
        sc.rule = ui->txtCheckRule->text();
        sc.ruleVersion = ui->txtCheckRuleVersion->text();
        sc.title = ui->txtCheckTitle->text();
        sc.severity = GetSeverity(ui->cboBoxSeverity->currentText());
        sc.documentable = ui->cbDocumentable->isChecked();
        sc.vulnDiscussion = ui->txtDiscussion->toPlainText();
        sc.falsePositives = ui->txtFalsePositives->toPlainText();
        sc.falseNegatives = ui->txtFalseNegatives->toPlainText();
        sc.fix = ui->txtFix->toPlainText();
        sc.check = ui->txtCheck->toPlainText();

        sc.cciIds.clear();
        for (int j = 0; j < ui->lstCCIs->count(); ++j)
        {
            QListWidgetItem *tmpCCIItem = ui->lstCCIs->item(j);
            auto cci = tmpCCIItem->data(Qt::UserRole).value<CCI>();
            sc.cciIds.append(cci.id);
        }

        db.UpdateSTIGCheck(sc);
        //keep the list item's stored data (and label) in sync with the edits
        i->setData(Qt::UserRole, QVariant::fromValue<STIGCheck>(sc));
        i->setText(PrintSTIGCheck(sc));
    }

    if (_parent)
        _parent->Display();
}

/**
 * @brief STIGEdit::SaveSTIG
 * @param fileName
 *
 * Export the (edited) STIG as a re-importable XCCDF benchmark packaged
 * in a .zip archive. When @a fileName is empty, the user is prompted for
 * a destination; the explicit argument is used by the test harness to
 * bypass the file dialog.
 */
void STIGEdit::SaveSTIG(const QString &fileName)
{
    DbManager db;
    QString fn = fileName;
    if (fn.isEmpty())
    {
        fn = QFileDialog::getSaveFileName(this, QStringLiteral("Save STIG"),
                db.GetVariable(QStringLiteral("lastdir")) + QDir::separator() + PrintSTIG(_s) + QStringLiteral(".zip"),
                QStringLiteral("Compressed STIG (*.zip)"));
    }
    if (fn.isNull() || fn.isEmpty())
        return; //cancelled

    db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fn).absolutePath());

    auto *f = new WorkerSTIGExport();
    f->SetSTIG(_s);
    f->SetExportPath(fn);
    if (_parent)
        _parent->ConnectThreads(f)->start();
}
