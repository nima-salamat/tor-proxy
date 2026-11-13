#include "splash_window.h"

#include <QFont>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QLinearGradient>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QRadialGradient>
#include <QResizeEvent>
#include <QScreen>
#include <QTimer>
#include <QToolButton>

namespace {
constexpr int kWindowWidth = 560;
constexpr int kWindowHeight = 360;

QString actionButtonStyle(const QString &background, const QString &hover,
                          const QString &foreground = QStringLiteral("#EAF4F7"),
                          const QString &pressed = QStringLiteral("#173A43"),
                          const QString &border = QStringLiteral("rgba(133,176,190,48)"),
                          const QString &hoverBorder = QStringLiteral("rgba(80,211,192,145)")) {
    return QStringLiteral(
        "QPushButton {"
        " color: %3; background: %1; border: 1px solid %4;"
        " border-radius: 10px; padding: 8px 14px; font-size: 12px; font-weight: 600;"
        " }"
        "QPushButton:hover { background: %2; border-color: %5; }"
        "QPushButton:pressed { background: %6; }"
    ).arg(background).arg(hover).arg(foreground).arg(border).arg(hoverBorder).arg(pressed);
}
} // namespace

SplashWindow::SplashWindow(const QString &iconPath, QWidget *parent)
    : QWidget(parent), m_logo(iconPath) {
    setObjectName(QStringLiteral("torProxySplash"));
    setWindowFlags(Qt::SplashScreen | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground, true);
    setAttribute(Qt::WA_DeleteOnClose, false);
    setFixedSize(kWindowWidth, kWindowHeight);
    setWindowTitle(QStringLiteral("TorProxy"));
    setFocusPolicy(Qt::StrongFocus);

    m_closeButton = new QToolButton(this);
    m_closeButton->setText(QStringLiteral("×"));
    m_closeButton->setCursor(Qt::PointingHandCursor);
    m_closeButton->setToolTip(QStringLiteral("Close"));
    m_closeButton->setStyleSheet(QStringLiteral(
        "QToolButton { color: #8EA7B2; background: transparent; border: 0;"
        " border-radius: 9px; font-size: 21px; font-weight: 400; }"
        "QToolButton:hover { color: #F4FAFC; background: rgba(255,255,255,22); }"
    ));
    connect(m_closeButton, &QToolButton::clicked, this, &SplashWindow::closeRequested);

    m_retryButton = new QPushButton(QStringLiteral("Try again"), this);
    m_retryButton->setCursor(Qt::PointingHandCursor);
    m_retryButton->setStyleSheet(actionButtonStyle(
        QStringLiteral("#176D69"), QStringLiteral("#1B817A")
    ));
    connect(m_retryButton, &QPushButton::clicked, this, &SplashWindow::retryRequested);

    m_openLogsButton = new QPushButton(QStringLiteral("Open logs"), this);
    m_openLogsButton->setCursor(Qt::PointingHandCursor);
    m_openLogsButton->setStyleSheet(actionButtonStyle(
        QStringLiteral("#1D2B37"), QStringLiteral("#263A49")
    ));
    connect(m_openLogsButton, &QPushButton::clicked, this, &SplashWindow::openLogsRequested);

    m_errorCloseButton = new QPushButton(QStringLiteral("Close"), this);
    m_errorCloseButton->setCursor(Qt::PointingHandCursor);
    m_errorCloseButton->setStyleSheet(actionButtonStyle(
        QStringLiteral("#1D2B37"), QStringLiteral("#263A49")
    ));
    connect(m_errorCloseButton, &QPushButton::clicked, this, &SplashWindow::closeRequested);

    m_retryButton->hide();
    m_openLogsButton->hide();
    m_errorCloseButton->hide();
    setThemeMode(QStringLiteral("dark"));
    updateActionGeometry();

    m_animationTimer = new QTimer(this);
    m_animationTimer->setInterval(50);
    connect(m_animationTimer, &QTimer::timeout, this, [this]() {
        m_spinnerAngle = (m_spinnerAngle + 17) % 360;
        m_progressOffset = (m_progressOffset + 8) % 500;
        update();
    });
    m_animationTimer->start();
}

bool SplashWindow::logoLoaded() const noexcept {
    return !m_logo.isNull();
}

void SplashWindow::setThemeMode(const QString &mode) {
    m_themeMode = mode == QStringLiteral("light")
        ? QStringLiteral("light")
        : QStringLiteral("dark");
    const bool dark = m_themeMode == QStringLiteral("dark");

    m_closeButton->setStyleSheet(dark
        ? QStringLiteral(
            "QToolButton { color: #8EA7B2; background: transparent; border: 0;"
            " border-radius: 9px; font-size: 21px; font-weight: 400; }"
            "QToolButton:hover { color: #F4FAFC; background: rgba(255,255,255,22); }"
          )
        : QStringLiteral(
            "QToolButton { color: #526D79; background: transparent; border: 0;"
            " border-radius: 9px; font-size: 21px; font-weight: 400; }"
            "QToolButton:hover { color: #1D3742; background: rgba(37,79,94,18); }"
          ));

    if (dark) {
        m_retryButton->setStyleSheet(actionButtonStyle(
            QStringLiteral("#176D69"), QStringLiteral("#1B817A")));
        m_openLogsButton->setStyleSheet(actionButtonStyle(
            QStringLiteral("#1D2B37"), QStringLiteral("#263A49")));
        m_errorCloseButton->setStyleSheet(actionButtonStyle(
            QStringLiteral("#1D2B37"), QStringLiteral("#263A49")));
    } else {
        const QString border = QStringLiteral("rgba(91,126,140,110)");
        const QString hoverBorder = QStringLiteral("rgba(28,144,132,150)");
        m_retryButton->setStyleSheet(actionButtonStyle(
            QStringLiteral("#188C80"), QStringLiteral("#1F9C90"),
            QStringLiteral("#FFFFFF"), QStringLiteral("#126B63"), border, hoverBorder));
        const QString secondary = QStringLiteral("#E9F1F4");
        const QString secondaryHover = QStringLiteral("#DDE9ED");
        const QString foreground = QStringLiteral("#233B46");
        const QString pressed = QStringLiteral("#CFDEE4");
        m_openLogsButton->setStyleSheet(actionButtonStyle(
            secondary, secondaryHover, foreground, pressed, border, hoverBorder));
        m_errorCloseButton->setStyleSheet(actionButtonStyle(
            secondary, secondaryHover, foreground, pressed, border, hoverBorder));
    }
    rebuildBackgroundCache();
    update();
}

QString SplashWindow::themeMode() const {
    return m_themeMode;
}

void SplashWindow::centerOnPrimaryScreen() {
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        const QRect area = screen->availableGeometry();
        move(area.center() - rect().center());
    }
}

void SplashWindow::beginLoading() {
    m_errorState = false;
    m_errorMessage.clear();
    m_logPath.clear();
    m_status = QStringLiteral("Preparing the desktop experience");
    m_retryButton->hide();
    m_openLogsButton->hide();
    m_errorCloseButton->hide();
    update();
}

void SplashWindow::setStatus(const QString &status) {
    if (m_errorState) {
        return;
    }
    m_status = status.trimmed().left(120);
    update();
}

void SplashWindow::showStartupError(const QString &message, const QString &logPath) {
    m_errorState = true;
    m_errorMessage = message.trimmed().left(1800);
    m_logPath = logPath;
    m_status = QStringLiteral("Startup needs attention");
    m_retryButton->show();
    m_openLogsButton->setEnabled(!m_logPath.isEmpty());
    m_openLogsButton->show();
    m_errorCloseButton->show();
    updateActionGeometry();
    update();
}

void SplashWindow::updateActionGeometry() {
    if (!m_closeButton) {
        return;
    }
    m_closeButton->setGeometry(width() - 42, 13, 27, 27);

    const int buttonWidth = 132;
    const int gap = 10;
    const int totalWidth = buttonWidth * 3 + gap * 2;
    const int left = (width() - totalWidth) / 2;
    const int top = height() - 62;
    m_retryButton->setGeometry(left, top, buttonWidth, 38);
    m_openLogsButton->setGeometry(left + buttonWidth + gap, top, buttonWidth, 38);
    m_errorCloseButton->setGeometry(left + (buttonWidth + gap) * 2, top, buttonWidth, 38);
}

void SplashWindow::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
    updateActionGeometry();
    rebuildBackgroundCache();
}

void SplashWindow::rebuildBackgroundCache() {
    if (size().isEmpty()) {
        m_backgroundCache = QPixmap();
        return;
    }

    QPixmap cache(size());
    cache.fill(Qt::transparent);
    QPainter painter(&cache);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF panel = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
    QPainterPath panelPath;
    panelPath.addRoundedRect(panel, 23.0, 23.0);

    const bool dark = m_themeMode == QStringLiteral("dark");
    QLinearGradient background(panel.topLeft(), panel.bottomRight());
    background.setColorAt(0.0, dark ? QColor("#172431") : QColor("#F8FBFC"));
    background.setColorAt(0.52, dark ? QColor("#101B26") : QColor("#EDF3F6"));
    background.setColorAt(1.0, dark ? QColor("#0C151E") : QColor("#E3EDF1"));
    painter.fillPath(panelPath, background);

    QRadialGradient tealGlow(QPointF(width() * 0.50, 113.0), 205.0);
    tealGlow.setColorAt(0.0, dark ? QColor(20, 155, 144, 38) : QColor(20, 155, 144, 24));
    tealGlow.setColorAt(1.0, QColor(20, 155, 144, 0));
    painter.fillPath(panelPath, tealGlow);
    painter.setPen(QPen(dark ? QColor(140, 181, 195, 48) : QColor(83, 110, 124, 95), 1.0));
    painter.drawPath(panelPath);
    painter.end();

    m_backgroundCache = cache;
}

void SplashWindow::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event)

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::SmoothPixmapTransform, true);

    if (m_backgroundCache.isNull() || m_backgroundCache.size() != size()) {
        rebuildBackgroundCache();
    }
    painter.drawPixmap(0, 0, m_backgroundCache);
    const bool dark = m_themeMode == QStringLiteral("dark");

    QFont eyebrow(QStringLiteral("Arial"), 8, QFont::DemiBold);
    eyebrow.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
    painter.setFont(eyebrow);
    painter.setPen(dark ? QColor("#90A8B4") : QColor("#536F7B"));
    painter.drawText(QRectF(34, 25, 250, 18), Qt::AlignLeft | Qt::AlignVCenter,
                     QStringLiteral("TORPROXY  /  DESKTOP"));

#ifndef TORPROXY_VERSION
#define TORPROXY_VERSION "1.4.0"
#endif
    QFont versionFont(QStringLiteral("Arial"), 8, QFont::Medium);
    painter.setFont(versionFont);
    painter.setPen(dark ? QColor("#637C89") : QColor("#768C96"));
    painter.drawText(QRectF(width() - 108, 25, 62, 18), Qt::AlignRight | Qt::AlignVCenter,
                     QStringLiteral("v") + QStringLiteral(TORPROXY_VERSION));

    const QRectF logoRect(width() / 2.0 - 39.0, 55.0, 78.0, 78.0);
    painter.setPen(Qt::NoPen);
    painter.setBrush(dark ? QColor(47, 194, 175, 24) : QColor(35, 145, 133, 24));
    painter.drawEllipse(logoRect.adjusted(-12, -12, 12, 12));
    if (!m_logo.isNull()) {
        painter.drawPixmap(logoRect.toRect(), m_logo);
    } else {
        painter.setBrush(QColor("#32C8B3"));
        painter.drawEllipse(logoRect.adjusted(8, 8, -8, -8));
    }

    QFont titleFont(QStringLiteral("Arial"), 22, QFont::DemiBold);
    painter.setFont(titleFont);
    painter.setPen(dark ? QColor("#F0F6F8") : QColor("#1F3440"));
    const QString title = m_errorState
        ? QStringLiteral("Couldn't start TorProxy")
        : QStringLiteral("TorProxy");
    painter.drawText(QRectF(32, 146, width() - 64, 35), Qt::AlignHCenter | Qt::AlignVCenter, title);

    QFont subtitleFont(QStringLiteral("Arial"), 9, QFont::Normal);
    painter.setFont(subtitleFont);
    painter.setPen(dark ? QColor("#91A8B4") : QColor("#5C7480"));
    painter.drawText(QRectF(42, 181, width() - 84, 24), Qt::AlignHCenter | Qt::AlignVCenter,
                     m_errorState
                         ? QStringLiteral("The desktop process stopped before it became ready.")
                         : QStringLiteral("Private connections, simplified"));

    if (!m_errorState) {
        const QRectF spinnerRect(width() / 2.0 - 11.0, 213.0, 22.0, 22.0);
        painter.setPen(QPen(dark ? QColor(134, 169, 181, 45) : QColor(92, 120, 133, 60), 2.5, Qt::SolidLine, Qt::RoundCap));
        painter.drawEllipse(spinnerRect);
        painter.setPen(QPen(dark ? QColor("#41D5BE") : QColor("#148F85"), 2.8, Qt::SolidLine, Qt::RoundCap));
        painter.drawArc(spinnerRect, m_spinnerAngle * 16, 245 * 16);

        QFont statusFont(QStringLiteral("Arial"), 9, QFont::Medium);
        painter.setFont(statusFont);
        painter.setPen(dark ? QColor("#C4D4DA") : QColor("#425B67"));
        const QString visibleStatus = QFontMetrics(statusFont).elidedText(
            m_status, Qt::ElideRight, width() - 96
        );
        painter.drawText(QRectF(42, 243, width() - 84, 27),
                         Qt::AlignHCenter | Qt::AlignVCenter, visibleStatus);

        const QRectF track(40, 286, width() - 80, 3);
        QPainterPath trackPath;
        trackPath.addRoundedRect(track, 1.5, 1.5);
        painter.fillPath(trackPath, dark ? QColor(125, 158, 169, 42) : QColor(92, 121, 134, 48));

        const qreal segmentWidth = 92.0;
        const qreal trackWidth = track.width();
        const qreal x = track.left() + (m_progressOffset / 500.0) * (trackWidth + segmentWidth)
                        - segmentWidth;
        const QRectF segment(x, track.top(), segmentWidth, track.height());
        QPainterPath segmentPath;
        segmentPath.addRoundedRect(segment.intersected(track), 1.5, 1.5);
        painter.fillPath(segmentPath, dark ? QColor("#36BFAE") : QColor("#1F9B8D"));

        QFont footerFont(QStringLiteral("Arial"), 8);
        painter.setFont(footerFont);
        painter.setPen(dark ? QColor("#627B88") : QColor("#718994"));
        painter.drawText(QRectF(40, 301, width() - 80, 20),
                         Qt::AlignHCenter | Qt::AlignVCenter,
                         QStringLiteral("Loading desktop components"));
    } else {
        painter.setPen(QPen(QColor("#F06C72"), 2.6, Qt::SolidLine, Qt::RoundCap));
        const QPointF center(width() / 2.0, 223.0);
        painter.drawEllipse(center, 10.5, 10.5);
        painter.drawLine(QPointF(center.x(), center.y() - 5.0),
                         QPointF(center.x(), center.y() + 1.0));
        painter.drawPoint(QPointF(center.x(), center.y() + 5.5));

        QFont detailFont(QStringLiteral("Arial"), 8);
        painter.setFont(detailFont);
        painter.setPen(dark ? QColor("#9EB2BB") : QColor("#576F7A"));
        const QRectF detailRect(38, 243, width() - 76, 40);
        painter.drawText(detailRect, Qt::AlignHCenter | Qt::AlignVCenter | Qt::TextWordWrap,
                         m_errorMessage);
    }

    painter.setPen(QPen(dark ? QColor(130, 166, 180, 22) : QColor(90, 120, 132, 45), 1.0));
    painter.drawLine(QPointF(30, height() - 22), QPointF(width() - 30, height() - 22));
}

void SplashWindow::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton && event->position().y() < 52.0) {
        m_dragging = true;
        m_dragOffset = event->globalPosition().toPoint() - frameGeometry().topLeft();
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void SplashWindow::mouseMoveEvent(QMouseEvent *event) {
    if (m_dragging && (event->buttons() & Qt::LeftButton)) {
        move(event->globalPosition().toPoint() - m_dragOffset);
        event->accept();
        return;
    }
    QWidget::mouseMoveEvent(event);
}

void SplashWindow::mouseReleaseEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
        m_dragging = false;
    }
    QWidget::mouseReleaseEvent(event);
}

void SplashWindow::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Escape) {
        emit closeRequested();
        event->accept();
        return;
    }
    QWidget::keyPressEvent(event);
}
