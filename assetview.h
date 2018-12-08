#ifndef ASSETVIEW_H
#define ASSETVIEW_H

#include <QWidget>

namespace Ui {
class AssetView;
}

class AssetView : public QWidget
{
    Q_OBJECT

public:
    explicit AssetView(QWidget *parent = nullptr);
    ~AssetView();

private:
    Ui::AssetView *ui;
};

#endif // ASSETVIEW_H
