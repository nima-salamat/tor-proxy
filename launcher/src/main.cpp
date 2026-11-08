#include "splash_window.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QProcessEnvironment>
#include <QScreen>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <QUrl>

#include <cstdio>

namespace {
constexpr int kStartupTimeoutMs = 90000;

QString applicationRoot() {
    QDir candidate(QCoreApplication::applicationDirPath());
    for (int level = 0; level < 4; ++level) {
#ifdef Q_OS_WIN
        const QString mainExecutable = candidate.filePath(QStringLiteral("TorProxy.exe"));
#else
        const QString mainExecutable = candidate.filePath(QStringLiteral("TorProxy"));
#endif
        if (QFileInfo(mainExecutable).isFile()) {
            return candidate.absolutePath();
        }
        if (!candidate.cdUp()) {
            break;
        }
    }
    return QCoreApplication::applicationDirPath();
}

QString mainApplicationPath() {
#ifdef Q_OS_WIN
    return QDir(applicationRoot()).filePath(QStringLiteral("TorProxy.exe"));
#else
    return QDir(applicationRoot()).filePath(QStringLiteral("TorProxy"));
#endif
}

QString applicationIconPath() {
    const QString root = applicationRoot();
    const QString direct = QDir(root).filePath(QStringLiteral("assets/icon.png"));
    if (QFileInfo::exists(direct)) {
        return direct;
    }
    // PyInstaller 6 uses an _internal directory for collected data files.
    return QDir(root).filePath(QStringLiteral("_internal/assets/icon.png"));
}

QString tailOfFile(const QString &path, qsizetype maximumCharacters = 1100) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    QString text = QString::fromUtf8(file.readAll()).trimmed();
    if (text.size() > maximumCharacters) {
        text = QStringLiteral("…") + text.right(maximumCharacters);
    }
    return text;
}

class StartupController final : public QObject {
public:
    explicit StartupController(SplashWindow *splash, QObject *parent = nullptr)
        : QObject(parent), m_splash(splash) {
        m_server.setSocketOptions(QLocalServer::UserAccessOption);
        m_server.setMaxPendingConnections(2);
        connect(&m_server, &QLocalServer::newConnection,
                this, [this]() { acceptConnections(); });

        m_timeout.setSingleShot(true);
        m_timeout.setInterval(kStartupTimeoutMs);
        connect(&m_timeout, &QTimer::timeout, this, [this]() {
            showError(QStringLiteral(
                "TorProxy did not report that its main window was ready within 90 seconds."
            ));
        });

        connect(m_splash, &SplashWindow::retryRequested,
                this, [this]() { start(); });
        connect(m_splash, &SplashWindow::openLogsRequested,
                this, [this]() {
            if (!m_logPath.isEmpty()) {
                QDesktopServices::openUrl(QUrl::fromLocalFile(m_logPath));
            }
        });
        connect(m_splash, &SplashWindow::closeRequested,
                this, [this]() { stopAndQuit(); });
    }

    void start() {
        if (m_ready) {
            return;
        }
        stopCurrentProcess();
        m_splash->beginLoading();

        m_errorShown = false;
        m_server.close();
        if (!m_serverName.isEmpty()) {
            QLocalServer::removeServer(m_serverName);
        }

        const QString executable = mainApplicationPath();
        const QFileInfo executableInfo(executable);
        if (!executableInfo.isFile() || !executableInfo.isExecutable()) {
            showError(QStringLiteral("The main TorProxy executable is missing or is not executable: %1")
                          .arg(executable));
            return;
        }

        m_serverName = QStringLiteral("torproxy-startup-") +
                       QUuid::createUuid().toString(QUuid::WithoutBraces);
        m_token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (!m_server.listen(m_serverName)) {
            showError(QStringLiteral("Could not create the private startup channel: %1")
                          .arg(m_server.errorString()));
            return;
        }

        const QString dataRoot =
            QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        const QString logDirectory = QDir(dataRoot).filePath(QStringLiteral("logs"));
        if (!QDir().mkpath(logDirectory)) {
            showError(QStringLiteral("Could not create the per-user startup log directory."));
            return;
        }
        m_logPath = QDir(logDirectory).filePath(QStringLiteral("launcher-startup.log"));
        QFile::remove(m_logPath);

        m_splash->setStatus(QStringLiteral("Starting the TorProxy desktop process…"));

        // Keep this QProcess unparented. When READY arrives, the launcher exits
        // without destroying the still-running application process.
        m_process = new QProcess;
        m_process->setWorkingDirectory(applicationRoot());
        m_process->setProcessChannelMode(QProcess::MergedChannels);
        m_process->setStandardOutputFile(m_logPath, QIODevice::Append);

        QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
        environment.insert(QStringLiteral("TORPROXY_LAUNCHER_SERVER"), m_serverName);
        environment.insert(QStringLiteral("TORPROXY_LAUNCHER_TOKEN"), m_token);
        environment.insert(QStringLiteral("TORPROXY_LAUNCHER_LOG"), m_logPath);
        m_process->setProcessEnvironment(environment);

        connect(m_process, &QProcess::started, this, [this]() {
            m_splash->setStatus(QStringLiteral("Loading Python and desktop components…"));
        });
        connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart && !m_ready) {
                showError(QStringLiteral("The operating system could not start TorProxy: %1")
                              .arg(m_process ? m_process->errorString() : QStringLiteral("unknown error")));
            }
        });
        connect(m_process,
                qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
                this,
                [this](int exitCode, QProcess::ExitStatus exitStatus) {
            if (m_ready || m_errorShown) {
                return;
            }
            const QString reason = exitStatus == QProcess::CrashExit
                ? QStringLiteral("The TorProxy process crashed before startup completed.")
                : QStringLiteral("The TorProxy process exited before reporting READY (exit code %1).")
                      .arg(exitCode);
            showError(reason);
        });

        QStringList arguments = QCoreApplication::arguments();
        if (!arguments.isEmpty()) {
            arguments.removeFirst();
        }
        m_process->start(executable, arguments);
        m_timeout.start();
    }

private:
    void acceptConnections() {
        while (m_server.hasPendingConnections()) {
            QLocalSocket *socket = m_server.nextPendingConnection();
            if (!socket) {
                continue;
            }
            connect(socket, &QLocalSocket::readyRead, this, [this, socket]() {
                QByteArray buffer = socket->property("torproxyBuffer").toByteArray();
                buffer += socket->readAll();
                const qsizetype newline = buffer.indexOf('\n');
                if (newline < 0) {
                    socket->setProperty("torproxyBuffer", buffer.left(4096));
                    return;
                }

                const QByteArray payload = buffer.left(newline);
                const QJsonDocument document = QJsonDocument::fromJson(payload);
                socket->disconnectFromServer();
                socket->deleteLater();
                if (!document.isObject()) {
                    return;
                }

                const QJsonObject message = document.object();
                if (message.value(QStringLiteral("token")).toString() != m_token) {
                    return;
                }

                const QString status = message.value(QStringLiteral("status")).toString();
                if (status == QStringLiteral("ready")) {
                    onReady();
                } else if (status == QStringLiteral("failed")) {
                    const QString detail = message.value(QStringLiteral("message")).toString();
                    showError(detail.isEmpty()
                        ? QStringLiteral("TorProxy reported a startup failure.")
                        : detail);
                }
            });
        }
    }

    void onReady() {
        if (m_ready) {
            return;
        }
        m_ready = true;
        m_timeout.stop();
        m_server.close();
        QLocalServer::removeServer(m_serverName);

        // Do not delete a running QProcess: Qt's destructor terminates a child
        // it still owns. The operating system will reclaim this small watcher
        // object when the short-lived launcher process exits.
        if (m_process) {
            m_process->disconnect(this);
            m_process = nullptr;
        }

        m_splash->setStatus(QStringLiteral("TorProxy is ready"));
        QTimer::singleShot(220, this, [this]() {
            m_splash->close();
            QCoreApplication::quit();
        });
    }

    void showError(const QString &message) {
        if (m_ready || m_errorShown) {
            return;
        }
        m_errorShown = true;
        m_timeout.stop();
        QString details = tailOfFile(m_logPath);
        QString fullMessage = message.trimmed();
        if (!details.isEmpty()) {
            fullMessage += QStringLiteral("\n\n") + details;
        }
        m_splash->showStartupError(fullMessage, m_logPath);
    }

    void stopCurrentProcess() {
        m_timeout.stop();
        if (!m_process) {
            return;
        }
        if (m_process->state() != QProcess::NotRunning) {
            m_process->terminate();
            if (!m_process->waitForFinished(1600)) {
                m_process->kill();
                m_process->waitForFinished(1600);
            }
        }
        delete m_process;
        m_process = nullptr;
    }

    void stopAndQuit() {
        stopCurrentProcess();
        m_server.close();
        if (!m_serverName.isEmpty()) {
            QLocalServer::removeServer(m_serverName);
        }
        QCoreApplication::quit();
    }

    SplashWindow *m_splash = nullptr;
    QLocalServer m_server;
    QTimer m_timeout;
    QProcess *m_process = nullptr;
    QString m_serverName;
    QString m_token;
    QString m_logPath;
    bool m_ready = false;
    bool m_errorShown = false;
};
} // namespace

int main(int argc, char *argv[]) {
    for (int index = 1; index < argc; ++index) {
        const QByteArray argument(argv[index]);
        if (argument == "--version") {
            std::printf("TorProxyLauncher %s\n", TORPROXY_VERSION);
            return 0;
        }
    }

    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("TorProxy"));
    QCoreApplication::setOrganizationName(QStringLiteral("TorProxy"));
    application.setApplicationDisplayName(QStringLiteral("TorProxy"));
    QApplication::setQuitOnLastWindowClosed(false);

    SplashWindow splash(applicationIconPath());
    application.setWindowIcon(QIcon(applicationIconPath()));

    if (application.arguments().contains(QStringLiteral("--self-test"))) {
        splash.centerOnPrimaryScreen();
        splash.show();
        application.processEvents();
        const bool ready = splash.isVisible() && splash.logoLoaded();
        splash.close();
        return ready ? 0 : 2;
    }

    StartupController controller(&splash);
    splash.centerOnPrimaryScreen();
    splash.show();
    splash.raise();
    splash.activateWindow();
    application.processEvents();
    QTimer::singleShot(80, &controller, [&controller]() { controller.start(); });

    return application.exec();
}
