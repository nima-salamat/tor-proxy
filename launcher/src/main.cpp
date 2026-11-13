#include "splash_window.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPalette>
#include <QScreen>
#include <QStyleHints>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <QUrl>
#include <QThread>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
constexpr int kStartupTimeoutMs = 180000;

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


QString launcherConfigPath() {
    const QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    QString configRoot = environment.value(QStringLiteral("XDG_CONFIG_HOME"));
    if (configRoot.isEmpty()) {
        configRoot = QDir::home().filePath(QStringLiteral(".config"));
    }
    return QDir(configRoot)
        .filePath(QStringLiteral("torproxy/config.json"));
}

QString systemThemeMode(QApplication *application) {
    if (!application) {
        return QStringLiteral("light");
    }

    const Qt::ColorScheme scheme = application->styleHints()->colorScheme();
    if (scheme == Qt::ColorScheme::Dark) {
        return QStringLiteral("dark");
    }
    if (scheme == Qt::ColorScheme::Light) {
        return QStringLiteral("light");
    }

    const QColor windowColor = application->palette().color(QPalette::ColorRole::Window);
    return windowColor.lightness() < 128
        ? QStringLiteral("dark")
        : QStringLiteral("light");
}

QString resolveSplashTheme(QApplication *application) {
    QFile configFile(launcherConfigPath());
    if (configFile.open(QIODevice::ReadOnly)) {
        const QJsonDocument document = QJsonDocument::fromJson(configFile.readAll());
        if (document.isObject()) {
            const QJsonObject configuration = document.object();
            const QString preference =
                configuration.value(QStringLiteral("theme_preference")).toString();
            if (preference == QStringLiteral("dark") ||
                preference == QStringLiteral("light")) {
                return preference;
            }
            if (preference == QStringLiteral("system")) {
                return systemThemeMode(application);
            }

            // Compatibility with configurations created before theme_preference
            // was introduced: those files persist only the effective mode.
            const QString legacyMode =
                configuration.value(QStringLiteral("mode")).toString();
            if (legacyMode == QStringLiteral("dark") ||
                legacyMode == QStringLiteral("light")) {
                return legacyMode;
            }
        }
    }
    return systemThemeMode(application);
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
        // Linux bootstrap starts Python before execv() loads this Qt runtime.
        // exec preserves the parent PID, so this process owns the child.
        m_statusPath = qEnvironmentVariable("TORPROXY_LAUNCHER_STATUS_FILE");
        m_token = qEnvironmentVariable("TORPROXY_LAUNCHER_TOKEN");
        m_logPath = qEnvironmentVariable("TORPROXY_LAUNCHER_LOG");
        bool pidOk = false;
        const qlonglong childPid =
            qEnvironmentVariable("TORPROXY_LAUNCHER_PID").toLongLong(&pidOk);
        if (pidOk && childPid > 0) {
            m_prestartedPid = static_cast<pid_t>(childPid);
        }
        m_statusPoll.setInterval(60);
        connect(&m_statusPoll, &QTimer::timeout,
                this, [this]() { pollPrestartedProcess(); });

        m_server.setSocketOptions(QLocalServer::UserAccessOption);
        m_server.setMaxPendingConnections(2);
        connect(&m_server, &QLocalServer::newConnection,
                this, [this]() { acceptConnections(); });

        m_timeout.setSingleShot(true);
        m_timeout.setInterval(kStartupTimeoutMs);
        connect(&m_timeout, &QTimer::timeout, this, [this]() {
            showError(QStringLiteral(
                "TorProxy did not report that its main window was ready within 180 seconds."
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
        if (m_startedOnce) {
            stopCurrentProcess();
            if (!m_statusPath.isEmpty()) {
                QFile::remove(m_statusPath);
            }
            m_statusPath.clear();
            m_token.clear();
            qunsetenv("TORPROXY_LAUNCHER_STATUS_FILE");
            qunsetenv("TORPROXY_LAUNCHER_TOKEN");
            qunsetenv("TORPROXY_LAUNCHER_PID");
        }
        m_startedOnce = true;
        m_splash->beginLoading();
        m_errorShown = false;

        const bool hasPrestartedChild =
            m_prestartedPid > 0 && !m_statusPath.isEmpty() && !m_token.isEmpty();
        if (hasPrestartedChild) {
            m_splash->setStatus(QStringLiteral("Python is already starting…"));
            m_timeout.start();
            m_statusPoll.start();
            pollPrestartedProcess();
            return;
        }

        // Keep a normal QProcess fallback for systems where private IPC or
        // prelaunch setup failed before the Qt runtime was available.
        stopCurrentProcess();
        const QString executable = mainApplicationPath();
        const QFileInfo executableInfo(executable);
        if (!executableInfo.isFile() || !executableInfo.isExecutable()) {
            showError(QStringLiteral("The main TorProxy executable is missing or is not executable: %1")
                          .arg(executable));
            return;
        }

        m_server.close();
        if (!m_serverName.isEmpty()) {
            QLocalServer::removeServer(m_serverName);
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

        m_process = new QProcess;
        m_process->setWorkingDirectory(applicationRoot());
        m_process->setProcessChannelMode(QProcess::MergedChannels);
        m_process->setStandardOutputFile(m_logPath, QIODevice::Append);

        QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
        environment.remove(QStringLiteral("TORPROXY_LAUNCHER_STATUS_FILE"));
        environment.remove(QStringLiteral("TORPROXY_LAUNCHER_PID"));
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
    void pollPrestartedProcess() {
        if (m_prestartedPid <= 0 || m_ready) {
            m_statusPoll.stop();
            return;
        }

        QFile statusFile(m_statusPath);
        if (statusFile.open(QIODevice::ReadOnly) && statusFile.size() <= 16384) {
            const QList<QByteArray> fields = statusFile.readAll().split('\n');
            if (fields.size() >= 3 && fields.at(0) == m_token.toLatin1()) {
                const QByteArray signature = fields.at(1) + QByteArray("\n") + fields.at(2);
                if (signature != m_lastStatusPayload) {
                    m_lastStatusPayload = signature;
                    const QString status = QString::fromLatin1(fields.at(1));
                    const QString detail = QString::fromUtf8(QByteArray::fromHex(fields.at(2)));
                    if (status == QStringLiteral("starting")) {
                        if (!detail.isEmpty()) {
                            m_splash->setStatus(detail);
                        }
                        m_timeout.start();
                    } else if (status == QStringLiteral("ready")) {
                        onReady();
                        return;
                    } else if (status == QStringLiteral("failed")) {
                        showError(detail.isEmpty()
                            ? QStringLiteral("TorProxy reported a startup failure.")
                            : detail);
                    }
                }
            }
        }

        int childStatus = 0;
        const pid_t child = m_prestartedPid;
        const pid_t result = waitpid(child, &childStatus, WNOHANG);
        if (result == 0 || (result < 0 && errno == EINTR)) {
            return;
        }
        if (result == child || (result < 0 && errno == ECHILD)) {
            const bool childWasReaped = result == child;
            m_prestartedPid = -1;
            m_statusPoll.stop();
            if (!m_ready && !m_errorShown) {
                QString reason;
                if (!childWasReaped) {
                    reason = QStringLiteral("The launcher could not verify ownership of the startup process.");
                } else if (WIFEXITED(childStatus)) {
                    reason = QStringLiteral("TorProxy exited before reporting READY (exit code %1).")
                                 .arg(WEXITSTATUS(childStatus));
                } else if (WIFSIGNALED(childStatus)) {
                    reason = QStringLiteral("TorProxy stopped before reporting READY (signal %1).")
                                 .arg(WTERMSIG(childStatus));
                } else {
                    reason = QStringLiteral("TorProxy exited before reporting READY.");
                }
                showError(reason);
            }
            return;
        }
        if (result < 0) {
            m_prestartedPid = -1;
            m_statusPoll.stop();
            if (!m_ready && !m_errorShown) {
                showError(QStringLiteral("The launcher lost supervision of the TorProxy startup process."));
            }
        }
    }

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
                if (!document.isObject()) {
                    socket->disconnectFromServer();
                    socket->deleteLater();
                    return;
                }

                const QJsonObject message = document.object();
                if (message.value(QStringLiteral("token")).toString() != m_token) {
                    socket->disconnectFromServer();
                    socket->deleteLater();
                    return;
                }

                const QString status = message.value(QStringLiteral("status")).toString();
                bool accepted = false;
                if (status == QStringLiteral("starting")) {
                    accepted = true;
                    const QString detail = message.value(QStringLiteral("message")).toString();
                    if (!detail.isEmpty()) {
                        m_splash->setStatus(detail);
                    }
                    // Progress messages refresh the inactivity watchdog. A slow
                    // but healthy cold start is not treated as a failed launch.
                    m_timeout.start();
                } else if (status == QStringLiteral("ready")) {
                    accepted = true;
                    onReady();
                } else if (status == QStringLiteral("failed")) {
                    accepted = true;
                    const QString detail = message.value(QStringLiteral("message")).toString();
                    showError(detail.isEmpty()
                        ? QStringLiteral("TorProxy reported a startup failure.")
                        : detail);
                }

                if (accepted) {
                    // ACK means the launcher has actually parsed and authenticated
                    // the message, not merely that the sender's local buffer drained.
                    socket->write("ACK\n");
                    socket->flush();
                    socket->disconnectFromServer();
                } else {
                    socket->disconnectFromServer();
                }
                socket->deleteLater();
            });
        }
    }

    void onReady() {
        if (m_ready) {
            return;
        }
        m_ready = true;
        m_timeout.stop();
        m_statusPoll.stop();
        m_prestartedPid = -1; // The desktop app continues after the splash exits.
        if (!m_statusPath.isEmpty()) {
            QFile::remove(m_statusPath);
            m_statusPath.clear();
        }
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
        m_statusPoll.stop();
        if (m_process) {
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

        if (m_prestartedPid > 0) {
            const pid_t child = m_prestartedPid;
            kill(child, SIGTERM);
            QElapsedTimer elapsed;
            elapsed.start();
            int childStatus = 0;
            bool reaped = false;
            while (elapsed.elapsed() < 500) {
                const pid_t result = waitpid(child, &childStatus, WNOHANG);
                if (result == child || (result < 0 && errno == ECHILD)) {
                    reaped = true;
                    break;
                }
                if (result < 0 && errno != EINTR) break;
                QThread::msleep(10);
            }
            if (!reaped) {
                kill(child, SIGKILL);
                while (waitpid(child, &childStatus, 0) < 0 && errno == EINTR) {}
            }
            m_prestartedPid = -1;
        }
        if (!m_statusPath.isEmpty()) QFile::remove(m_statusPath);
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
    QString m_statusPath;
    QByteArray m_lastStatusPayload;
    QTimer m_statusPoll;
    pid_t m_prestartedPid = -1;
    bool m_startedOnce = false;
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
    splash.setThemeMode(resolveSplashTheme(&application));
    application.setWindowIcon(QIcon(applicationIconPath()));

    if (application.arguments().contains(QStringLiteral("--self-test"))) {
        QString expectedTheme;
        for (const QString &argument : application.arguments()) {
            if (argument.startsWith(QStringLiteral("--expect-theme="))) {
                expectedTheme = argument.mid(QStringLiteral("--expect-theme=").size());
                break;
            }
        }
        splash.centerOnPrimaryScreen();
        splash.show();
        application.processEvents();
        const bool themeMatches = expectedTheme.isEmpty() ||
            (expectedTheme == QStringLiteral("system")
                ? splash.themeMode() == systemThemeMode(&application)
                : splash.themeMode() == expectedTheme);
        const bool ready = splash.isVisible() && splash.logoLoaded() && themeMatches;
        splash.close();
        return ready ? 0 : 2;
    }

    StartupController controller(&splash);
    splash.centerOnPrimaryScreen();
    splash.show();
    splash.raise();
    splash.activateWindow();
    application.processEvents();
    // The first splash frame is already visible. Start immediately; the
    // QProcess fallback is asynchronous and the Linux fast path is in flight.
    controller.start();

    return application.exec();
}
