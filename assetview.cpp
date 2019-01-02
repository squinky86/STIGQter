/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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

#include "assetview.h"
#include "common.h"
#include "cklcheck.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "ui_assetview.h"

#include <QFileDialog>
#include <QFont>
#include <QInputDialog>
#include <QMessageBox>
#include <QShortcut>
#include <QXmlStreamWriter>
#include <QTimer>

AssetView::AssetView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AssetView),
    _justification(),
    _updateStatus(false),
    _tabIndex(-1)
{
    ui->setupUi(this);
    _timer.setSingleShot(true);
    _timerChecks.setSingleShot(true);
    connect(&_timer, SIGNAL(timeout()), this, SLOT(UpdateCKLHelper()));
    connect(&_timerChecks, SIGNAL(timeout()), this, SLOT(CountChecks()));

    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_N), this, SLOT(KeyShortcutCtrlN())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_O), this, SLOT(KeyShortcutCtrlO())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_R), this, SLOT(KeyShortcutCtrlR())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_X), this, SLOT(KeyShortcutCtrlX())));
}

AssetView::AssetView(const Asset &a, QWidget *parent) : AssetView(parent)
{
    _a = a;
    Display();
}

AssetView::~AssetView()
{
    foreach (QShortcut *shortcut, _shortcuts)
        delete shortcut;
    _shortcuts.clear();
    delete ui;
}

void AssetView::Display()
{
    SelectSTIGs();
    ShowChecks();
}

void AssetView::SelectSTIGs()
{
    DbManager db;
    //ui->lstSTIGs->blockSignals(true);
    ui->lstSTIGs->clear();
    QList<STIG> stigs = _a.STIGs();
    foreach (const STIG s, db.GetSTIGs())
    {
        QListWidgetItem *i = new QListWidgetItem(PrintSTIG(s));
        ui->lstSTIGs->addItem(i);
        i->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        i->setSelected(stigs.contains(s));
    }
    //ui->lstSTIGs->blockSignals(false);
}

void AssetView::CountChecks()
{
    ShowChecks(true);
}

void AssetView::ShowChecks(bool countOnly)
{
    if (!countOnly)
        ui->lstChecks->clear();
    int total = 0;
    int open = 0;
    int closed = 0;
    foreach(const CKLCheck c, _a.CKLChecks())
    {
        total++;
        switch (c.status)
        {
        case Status::NotAFinding:
            closed++;
            break;
        case Status::Open:
            open++;
            break;
        default:
            break;
        }
        if (!countOnly)
        {
            QListWidgetItem *i = new QListWidgetItem(PrintCKLCheck(c));
            ui->lstChecks->addItem(i);
            i->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(c));
            SetItemColor(i, c.status, (c.severityOverride == Severity::none) ? c.STIGCheck().severity : c.severityOverride);
        }
    }
    ui->lblTotalChecks->setText(QString::number(total));
    ui->lblOpen->setText(QString::number(open));
    ui->lblNotAFinding->setText(QString::number(closed));
    if (!countOnly)
        ui->lstChecks->sortItems();
}

void AssetView::UpdateCKLCheck(const CKLCheck &cc)
{
    ui->txtComments->blockSignals(true);
    ui->txtFindingDetails->blockSignals(true);
    ui->cboBoxStatus->blockSignals(true);
    ui->cboBoxSeverity->blockSignals(true);
    ui->cboBoxStatus->setCurrentText(GetStatus(cc.status));
    ui->txtComments->clear();
    ui->txtComments->insertPlainText(cc.comments);
    ui->txtFindingDetails->clear();
    ui->txtFindingDetails->insertPlainText(cc.findingDetails);
    _justification = cc.severityJustification;

    UpdateSTIGCheck(cc.STIGCheck());
    if (cc.severityOverride != Severity::none)
        ui->cboBoxSeverity->setCurrentText(GetSeverity(cc.severityOverride));

    ui->txtComments->blockSignals(false);
    ui->txtFindingDetails->blockSignals(false);
    ui->cboBoxStatus->blockSignals(false);
    ui->cboBoxSeverity->blockSignals(false);
}

void AssetView::UpdateSTIGCheck(const STIGCheck &sc)
{
    ui->lblCheckRule->setText(sc.rule);
    ui->lblCheckTitle->setText(sc.title);
    ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
    ui->cbDocumentable->setChecked(sc.documentable);
    ui->lblDiscussion->setText(sc.vulnDiscussion);
    ui->lblFalsePositives->setText(sc.falsePositives);
    ui->lblFalseNegatives->setText(sc.falseNegatives);
    ui->lblFix->setText(sc.fix);
    ui->lblCheck->setText(sc.check);
}

void AssetView::SetTabIndex(int index)
{
    _tabIndex = index;
}

void AssetView::CheckSelectedChanged()
{
    if (ui->lstChecks->selectedItems().count() > 1)
    {
        //disable multi-editable fields
        ui->txtComments->setEnabled(false);
        ui->txtFindingDetails->setEnabled(false);
        ui->cboBoxSeverity->setEnabled(false);
    }
    else
    {
        //enable multi-editable fields
        ui->txtComments->setEnabled(true);
        ui->txtFindingDetails->setEnabled(true);
        ui->cboBoxSeverity->setEnabled(true);
    }
}

void AssetView::DeleteAsset()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm", "Are you sure you want to delete " + PrintAsset(_a) + "?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DbManager db;
        foreach (const STIG &s, _a.STIGs())
            db.DeleteSTIGFromAsset(s, _a);
        db.DeleteAsset(_a);
        if (_tabIndex > 0)
            emit CloseTab(_tabIndex);
    }
}

void AssetView::KeyShortcutCtrlN()
{
    KeyShortcut(Status::NotAFinding);
}

void AssetView::KeyShortcutCtrlO()
{
    KeyShortcut(Status::Open);
}

void AssetView::KeyShortcutCtrlR()
{
    KeyShortcut(Status::NotReviewed);
}

void AssetView::KeyShortcutCtrlX()
{
    KeyShortcut(Status::NotApplicable);
}

void AssetView::SaveCKL()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Save STIG/SRG Checklist", QDir::home().dirName(), "STIG Checklist (*.ckl)");
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly))
    {
        QXmlStreamWriter stream(&file);
        //xml for a CKL file
        stream.writeStartDocument("1.0");
        stream.writeComment("STIGQter :: " + QString(VERSION));
        stream.writeStartElement("CHECKLIST");
        stream.writeStartElement("ASSET");
        stream.writeStartElement("ROLE");
        stream.writeCharacters("None");
        stream.writeEndElement(); //ROLE
        stream.writeStartElement("ASSET_TYPE");
        stream.writeCharacters(_a.assetType);
        stream.writeEndElement(); //ASSET_TYPE
        stream.writeStartElement("HOST_NAME");
        stream.writeCharacters(_a.hostName);
        stream.writeEndElement(); //HOST_NAME
        stream.writeStartElement("HOST_IP");
        stream.writeCharacters(_a.hostIP);
        stream.writeEndElement(); //HOST_IP
        stream.writeStartElement("HOST_MAC");
        stream.writeCharacters(_a.hostMAC);
        stream.writeEndElement(); //HOST_MAC
        stream.writeStartElement("HOST_FQDN");
        stream.writeCharacters(_a.hostFQDN);
        stream.writeEndElement(); //HOST_FQDN
        stream.writeStartElement("TECH_AREA");
        stream.writeCharacters(_a.techArea);
        stream.writeEndElement(); //TECH_AREA
        stream.writeStartElement("TARGET_KEY");
        stream.writeCharacters(_a.targetKey);
        stream.writeEndElement(); //TARGET_KEY
        stream.writeStartElement("WEB_OR_DATABASE");
        stream.writeCharacters(PrintTrueFalse(_a.webOrDB));
        stream.writeEndElement(); //WEB_OR_DATABASE
        stream.writeStartElement("WEB_DB_SITE");
        stream.writeCharacters(_a.webDbSite);
        stream.writeEndElement(); //WEB_DB_SITE
        stream.writeStartElement("WEB_DB_INSTANCE");
        stream.writeCharacters(_a.webDbInstance);
        stream.writeEndElement(); //WEB_DB_INSTANCE
        stream.writeEndElement(); //ASSET
        stream.writeStartElement("STIGS");
        foreach (const STIG &s, _a.STIGs())
        {
            stream.writeStartElement("iSTIG");
            stream.writeStartElement("STIG_INFO");

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("version");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(QString::number(s.version));
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("stigid");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.benchmarkId);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("description");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.description);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("filename");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.fileName);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("releaseinfo");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.release);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("title");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.title);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeEndElement(); //STIG_INFO

            foreach (const CKLCheck &cc, _a.CKLChecks(&s))
            {
                const STIGCheck sc = cc.STIGCheck();
                stream.writeStartElement("VULN");

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Vuln_Num");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.vulnNum);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Severity");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(GetSeverity(cc.GetSeverity(), false));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Group_Title");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.groupTitle);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_ID");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.rule);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_Ver");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.ruleVersion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_Title");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.title);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Vuln_Discuss");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.vulnDiscussion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("IA_Controls");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.iaControls);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Check_Content");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.check);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Fix_Text");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.fix);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("False_Positives");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.falsePositives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("False_Negatives");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.falseNegatives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Documentable");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(PrintTrueFalse(sc.documentable));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Mitigations");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.mitigations);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Potential_Impact");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.potentialImpact);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Third_Party_Tools");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.thirdPartyTools);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Mitigation_Control");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.mitigationControl);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Responsibility");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.responsibility);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Security_Override_Guidance");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.severityOverrideGuidance);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Check_Content_Ref");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.checkContentRef);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Weight");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(QString::number(sc.weight));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("STIGRef");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(s.title + " :: Version " + QString::number(s.version) + ", " + s.release);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("TargetKey");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.targetKey);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("CCI_REF");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(PrintCCI(sc.CCI()));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STATUS");
                stream.writeCharacters(GetStatus(cc.status, true));
                stream.writeEndElement(); //STATUS

                stream.writeStartElement("FINDING_DETAILS");
                stream.writeCharacters(cc.findingDetails);
                stream.writeEndElement(); //FINDING_DETAILS

                stream.writeStartElement("COMMENTS");
                stream.writeCharacters(cc.comments);
                stream.writeEndElement(); //COMMENTS

                stream.writeStartElement("SEVERITY_OVERRIDE");
                stream.writeCharacters(GetSeverity(cc.severityOverride, false));
                stream.writeEndElement(); //SEVERITY_OVERRIDE

                stream.writeStartElement("SEVERITY_JUSTIFICATION");
                stream.writeCharacters(cc.severityJustification);
                stream.writeEndElement(); //SEVERITY_JUSTIFICATION

                stream.writeEndElement(); //VULN
            }

            stream.writeEndElement(); //iSTIG
        }
        stream.writeEndElement(); //STIGS
        stream.writeEndElement(); //CHECKLIST
        stream.writeEndDocument();
    }
}

void AssetView::KeyShortcut(const Status &action)
{
    if (this->isVisible())
    {
        switch (action)
        {
        case Status::NotReviewed:
            ui->cboBoxStatus->setCurrentIndex(0);
            break;
        case Status::Open:
            ui->cboBoxStatus->setCurrentIndex(1);
            break;
        case Status::NotAFinding:
            ui->cboBoxStatus->setCurrentIndex(2);
            break;
        default:
            ui->cboBoxStatus->setCurrentIndex(3);
            break;
        }
    }
}

void AssetView::UpdateCKLHelper()
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    int count = selectedItems.count();
    //make sure that something is selected
    if (count > 0)
    {
        foreach (QListWidgetItem *i, selectedItems)
        {
            CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
            //if multiple checks are selected, only update their status
            if (count < 2)
            {
                cc.comments = ui->txtComments->toPlainText();
                cc.findingDetails = ui->txtFindingDetails->toPlainText();
                Severity tmpSeverity = GetSeverity(ui->cboBoxSeverity->currentText());
                cc.severityOverride = (tmpSeverity == cc.STIGCheck().severity) ? cc.severityOverride = Severity::none : tmpSeverity;
                cc.severityJustification = _justification;
                cc.status = GetStatus(ui->cboBoxStatus->currentText());
            }
            else {
                if (_updateStatus)
                {
                    cc.status = GetStatus(ui->cboBoxStatus->currentText());
                }
            }
            DbManager db;
            db.UpdateCKLCheck(cc);
            i->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(db.GetCKLCheck(cc)));
        }
        _updateStatus = false;
        _timerChecks.start(1000);
    }
}

void AssetView::UpdateCKL()
{
    //avoid updating the database for every keypress. Wait for 9/50 of a second before saving
    //https://forum.qt.io/topic/97857/qplaintextedit-autosave-to-database
    _timer.start(180);
}

void AssetView::UpdateCKLStatus(const QString &val)
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    Status stat;
    stat = GetStatus(val);
    if (selectedItems.count() > 0)
    {
        foreach (QListWidgetItem *i, selectedItems)
        {
            CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
            STIGCheck sc = cc.STIGCheck();
            SetItemColor(i, stat, (cc.severityOverride == Severity::none) ? sc.severity : cc.severityOverride);
        }
        _updateStatus = true;
        UpdateCKL();
    }
}

void AssetView::UpdateCKLSeverity(const QString &val)
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    //should only be executed if one severity is set
    if (selectedItems.count() > 0)
    {
        QListWidgetItem *i = selectedItems.first();
        CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
        STIGCheck sc = cc.STIGCheck();
        Severity tmpSeverity = GetSeverity(val);
        if (sc.severity != tmpSeverity)
        {
            if (tmpSeverity == Severity::none)
            {
                QMessageBox::warning(nullptr, "Removed Severity Override", "Severity override is removed; findings cannot be downgraded to CAT IV.");
                _justification = "";
                ui->cboBoxSeverity->blockSignals(true);
                ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
                ui->cboBoxSeverity->blockSignals(false);
            }
            else
            {
                bool ok(false);
                QString justification = QInputDialog::getMultiLineText(this, tr("Severity Override Justification"),
                                        tr("Justification:"), _justification, &ok);
                if (ok)
                {
                    _justification = justification;
                }
                else
                {
                    ui->cboBoxSeverity->blockSignals(true);
                    ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
                    ui->cboBoxSeverity->blockSignals(false);
                    return;
                }
            }
        }
        SetItemColor(i, GetStatus(ui->cboBoxStatus->currentText()), GetSeverity(ui->cboBoxSeverity->currentText()));
        UpdateCKL();
    }
}

void AssetView::UpdateSTIGs()
{
    DbManager db;
    QList<STIG> stigs = _a.STIGs();
    for (int i = 0; i < ui->lstSTIGs->count(); i++)
    {
        QListWidgetItem *item = ui->lstSTIGs->item(i);
        STIG s = item->data(Qt::UserRole).value<STIG>();
        if (item->isSelected() && !stigs.contains(s))
        {
            db.AddSTIGToAsset(s, _a);
            ShowChecks();
        }
        else if (!item->isSelected() && stigs.contains(s))
        {
            //confirm to delete the STIG (avoid accidental clicks in the STIG box)
            QMessageBox::StandardButton confirm = QMessageBox::question(this, "Confirm STIG Removal", "Really delete the " + PrintSTIG(s) + " stig from " + PrintAsset(_a) + "?",
                                            QMessageBox::Yes|QMessageBox::No);
            if (confirm == QMessageBox::Yes)
            {
                db.DeleteSTIGFromAsset(s, _a);
                ShowChecks();
            }
            else
            {
                //keep STIG selected on accidental click
                ui->lstSTIGs->blockSignals(true);
                item->setSelected(true);
                ui->lstSTIGs->blockSignals(false);
            }
        }
    }
}

void AssetView::SetItemColor(QListWidgetItem *i, const Status &stat, const Severity &sev)
{
    QFont f;
    i->setFont(f);
    if (stat == Status::Open)
    {
        f.setBold(true);
        i->setFont(f);
        switch (sev)
        {
        case Severity::high:
            i->setForeground(Qt::red);
            break;
        case Severity::medium:
            i->setForeground(QColor("orange"));
            break;
        case Severity::low:
            i->setForeground(Qt::yellow);
            break;
        default:
            i->setForeground(Qt::black);
            break;
        }
    }
    else if (stat == Status::NotAFinding)
    {
        i->setForeground(Qt::green);
    }
    else if (stat == Status::NotApplicable)
    {
        i->setForeground(Qt::gray);
    }
    else
    {
        i->setForeground(Qt::black);
    }
}

void AssetView::CheckSelected(QListWidgetItem *current, QListWidgetItem *previous [[maybe_unused]])
{
    if (current)
    {
        CKLCheck cc = current->data(Qt::UserRole).value<CKLCheck>();
        DbManager db;
        UpdateCKLCheck(db.GetCKLCheck(cc));
    }
}
