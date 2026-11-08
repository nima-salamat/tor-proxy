#include <cerrno>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

namespace {
std::wstring quoteArgument(const std::wstring &argument) {
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }
    std::wstring quoted = L"\"";
    unsigned int backslashes = 0;
    for (wchar_t character : argument) {
        if (character == L'\\') {
            ++backslashes;
        } else if (character == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(character);
            backslashes = 0;
        } else {
            quoted.append(backslashes, L'\\');
            backslashes = 0;
            quoted.push_back(character);
        }
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

std::wstring executablePath() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                             static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    const std::wstring bootstrap = executablePath();
    if (bootstrap.empty()) {
        MessageBoxW(nullptr, L"Could not locate the TorProxy launcher.",
                    L"TorProxy", MB_OK | MB_ICONERROR);
        return 2;
    }

    const size_t separator = bootstrap.find_last_of(L"\\/");
    const std::wstring root = separator == std::wstring::npos
        ? L"." : bootstrap.substr(0, separator);
    const std::wstring gui = root + L"\\launcher-runtime\\bin\\TorProxyLauncherUI.exe";

    std::wstring commandLine = quoteArgument(gui);
    int argumentCount = 0;
    LPWSTR *arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (arguments) {
        for (int index = 1; index < argumentCount; ++index) {
            commandLine.push_back(L' ');
            commandLine += quoteArgument(arguments[index]);
        }
        LocalFree(arguments);
    }

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessW(gui.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                        CREATE_UNICODE_ENVIRONMENT, nullptr, root.c_str(),
                        &startupInfo, &processInfo)) {
        const DWORD error = GetLastError();
        wchar_t detail[256]{};
        std::swprintf(detail, sizeof(detail) / sizeof(detail[0]),
                      L"Could not start the TorProxy splash runtime (Windows error %lu).",
                      static_cast<unsigned long>(error));
        MessageBoxW(nullptr, detail, L"TorProxy startup error", MB_OK | MB_ICONERROR);
        return static_cast<int>(error);
    }

    CloseHandle(processInfo.hThread);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);
    CloseHandle(processInfo.hProcess);
    return static_cast<int>(exitCode);
}

#else

#include <limits.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char executable[PATH_MAX + 1]{};
    const ssize_t length = readlink("/proc/self/exe", executable, PATH_MAX);
    if (length <= 0) {
        std::perror("TorProxyLauncher: cannot resolve executable path");
        return 2;
    }
    executable[length] = '\0';

    std::string root(executable);
    const std::size_t separator = root.find_last_of('/');
    root = separator == std::string::npos ? "." : root.substr(0, separator);
    const std::string gui = root + "/launcher-runtime/bin/TorProxyLauncherUI";

    std::vector<char *> arguments;
    arguments.reserve(static_cast<std::size_t>(argc) + 1);
    arguments.push_back(const_cast<char *>(gui.c_str()));
    for (int index = 1; index < argc; ++index) {
        arguments.push_back(argv[index]);
    }
    arguments.push_back(nullptr);

    execv(gui.c_str(), arguments.data());
    std::perror("TorProxyLauncher: cannot start native splash runtime");
    return errno == 0 ? 127 : errno;
}
#endif
