#pragma once

#include <QString>
#include <QPixmap>
#include <QPushButton>
#include <QToolButton>
#include <QWidget>

class QKeyEvent;
class QMouseEvent;
class QPaintEvent;
class QResizeEvent;
class QTimer;

class SplashWindow final : public QWidget {
    Q_OBJECT

public:
    explicit SplashWindow(const QString &iconPath, QWidget *parent = nullptr);

    bool logoLoaded() const noexcept;
    void setThemeMode(const QString &mode);
    QString themeMode() const;
    void centerOnPrimaryScreen();
    void beginLoading();
    void setStatus(const QString &status);
    void showStartupError(const QString &message, const QString &logPath);

signals:
    void retryRequested();
    void openLogsRequested();
    void closeRequested();

protected:
    void paintEvent(QPaintEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

private:
    void updateActionGeometry();
    void rebuildBackgroundCache();

    QPixmap m_logo;
    QPixmap m_backgroundCache;
    QTimer *m_animationTimer = nullptr;
    QToolButton *m_closeButton = nullptr;
    QPushButton *m_retryButton = nullptr;
    QPushButton *m_openLogsButton = nullptr;
    QPushButton *m_errorCloseButton = nullptr;
    QString m_status = QStringLiteral("Preparing the desktop experience");
    QString m_errorMessage;
    QString m_logPath;
    QString m_themeMode = QStringLiteral("dark");
    int m_spinnerAngle = 0;
    int m_progressOffset = 0;
    bool m_errorState = false;
    bool m_dragging = false;
    QPoint m_dragOffset;
};
