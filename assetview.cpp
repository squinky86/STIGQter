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

#include "assetview.h"
#include "dbmanager.h"
#include "ui_assetview.h"

AssetView::AssetView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AssetView)
{
    ui->setupUi(this);
}

AssetView::AssetView(const Asset &a, QWidget *parent) : AssetView(parent)
{
    Display(a);
}

AssetView::~AssetView()
{
    delete ui;
}

void AssetView::Display(const Asset &a)
{
    SelectSTIGs(a.STIGs());
}

void AssetView::SelectSTIGs(const QList<STIG> &stigs)
{
    DbManager db;
    ui->lstSTIGs->clear();
    foreach (const STIG s, db.GetSTIGs())
    {
        QListWidgetItem *i = new QListWidgetItem(PrintSTIG(s));
        i->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        i->setSelected(stigs.contains(s)); //TODO: this is not selecting the item
        ui->lstSTIGs->addItem(i);
    }
}
