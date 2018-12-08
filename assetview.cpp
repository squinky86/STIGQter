#include "assetview.h"
#include "ui_assetview.h"

AssetView::AssetView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AssetView)
{
    ui->setupUi(this);
}

AssetView::~AssetView()
{
    delete ui;
}
