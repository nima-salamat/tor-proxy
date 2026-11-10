#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <algorithm>
#include <cmath>
#include <string>
#include <memory>
#include <gdiplus.h>

#ifdef _MSC_VER
#pragma comment(lib, "Advapi32.lib")
#endif

namespace {
constexpr wchar_t kClassName[] = L"TorProxy.LauncherWindow";
constexpr UINT_PTR kTimer = 1;
constexpr UINT kClose = 1003;
constexpr int kDesignWidth = 760, kDesignHeight = 480;
constexpr float kPanelCornerRadius = 25.0f;
constexpr float kMaximumWorkAreaWidth = 0.88f;
constexpr float kMaximumWorkAreaHeight = 0.86f;
constexpr ULONGLONG kIdleTimeout = 180000;

struct State {
    HWND window = nullptr;
    HICON icon = nullptr;
    std::unique_ptr<Gdiplus::Bitmap> logo;
    HDC backBufferDc = nullptr;
    HBITMAP backBufferBitmap = nullptr;
    HGDIOBJ backBufferPreviousBitmap = nullptr;
    int backBufferWidth = 0, backBufferHeight = 0;
    HANDLE process = nullptr, thread = nullptr;
    std::wstring root, executable, logPath, statusPath, token;
    std::wstring status = L"Preparing the desktop experience";
    std::wstring error, lastPayload;
    ULONGLONG lastProgress = 0;
    unsigned int angle = 0, progress = 0, pollCount = 0;
    int width = kDesignWidth, height = kDesignHeight;
    float scale = 1.0f;
    int hoverAction = -1;
    bool closeHover = false, trackingMouse = false;
    bool failed = false, ready = false;
    bool darkTheme = true;
};

bool loadSplashLogo(State &s) {
    const std::wstring candidates[] = {
        s.root + L"\\assets\\icon.png",
        s.root + L"\\_internal\\assets\\icon.png"
    };
    for (const auto &candidatePath : candidates) {
        auto image = std::make_unique<Gdiplus::Bitmap>(candidatePath.c_str());
        if (image->GetLastStatus() == Gdiplus::Ok) {
            s.logo = std::move(image);
            return true;
        }
    }
    return false;
}

std::wstring executablePath() {
    std::wstring value(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (!n || n >= value.size()) return {};
    value.resize(n);
    return value;
}
std::wstring guid() {
    GUID value{};
    if (FAILED(CoCreateGuid(&value))) return {};
    wchar_t buffer[40]{};
    if (!StringFromGUID2(value, buffer, 40)) return {};
    std::wstring result(buffer);
    result.erase(std::remove(result.begin(), result.end(), L'{'), result.end());
    result.erase(std::remove(result.begin(), result.end(), L'}'), result.end());
    return result;
}
std::wstring quote(const std::wstring &value) {
    if (value.find_first_of(L" \t\n\v\"") == std::wstring::npos) return value;
    std::wstring out = L"\""; size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') ++slashes;
        else if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out += c; slashes = 0; }
        else { out.append(slashes, L'\\'); slashes = 0; out += c; }
    }
    out.append(slashes * 2, L'\\'); out += L'"'; return out;
}
std::wstring utf8(const std::string &value) {
    if (value.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                static_cast<int>(value.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), out.data(), n);
    return out;
}
std::wstring fromHex(const std::wstring &hex) {
    if (hex.size() % 2 || hex.size() > 12000) return {};
    std::string bytes; bytes.reserve(hex.size() / 2);
    auto digit = [](wchar_t c) {
        if (c >= L'0' && c <= L'9') return int(c - L'0');
        if (c >= L'a' && c <= L'f') return int(c - L'a' + 10);
        if (c >= L'A' && c <= L'F') return int(c - L'A' + 10);
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int a = digit(hex[i]), b = digit(hex[i + 1]);
        if (a < 0 || b < 0) return {};
        bytes.push_back(static_cast<char>((a << 4) | b));
    }
    return utf8(bytes);
}
std::wstring readFile(const std::wstring &path, DWORD limit = 16384) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > limit) {
        CloseHandle(file); return {};
    }
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0'); DWORD got = 0;
    BOOL ok = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr);
    CloseHandle(file);
    if (!ok || !got) return {};
    bytes.resize(got); return utf8(bytes);
}

void skipJsonWhitespace(const std::wstring &json, size_t &position) {
    while (position < json.size() &&
           (json[position] == L' ' || json[position] == L'\t' ||
            json[position] == L'\r' || json[position] == L'\n')) {
        ++position;
    }
}

bool readJsonString(const std::wstring &json, size_t &position, std::wstring *decoded) {
    if (position >= json.size() || json[position] != L'"') return false;
    ++position;
    if (decoded) decoded->clear();

    while (position < json.size()) {
        const wchar_t value = json[position++];
        if (value == L'"') return true;
        if (value != L'\\') {
            if (decoded) decoded->push_back(value);
            continue;
        }
        if (position >= json.size()) return false;

        const wchar_t escaped = json[position++];
        wchar_t character = 0;
        switch (escaped) {
        case L'"': character = L'"'; break;
        case L'\\': character = L'\\'; break;
        case L'/': character = L'/'; break;
        case L'b': character = L'\b'; break;
        case L'f': character = L'\f'; break;
        case L'n': character = L'\n'; break;
        case L'r': character = L'\r'; break;
        case L't': character = L'\t'; break;
        case L'u': {
            if (position + 4 > json.size()) return false;
            unsigned int codepoint = 0;
            for (int digit = 0; digit < 4; ++digit) {
                const wchar_t hex = json[position++];
                unsigned int part = 0;
                if (hex >= L'0' && hex <= L'9') part = static_cast<unsigned int>(hex - L'0');
                else if (hex >= L'a' && hex <= L'f') part = static_cast<unsigned int>(hex - L'a' + 10);
                else if (hex >= L'A' && hex <= L'F') part = static_cast<unsigned int>(hex - L'A' + 10);
                else return false;
                codepoint = (codepoint << 4) | part;
            }
            // Only ASCII theme names are decoded by this launcher.
            character = codepoint <= 0x7F ? static_cast<wchar_t>(codepoint) : L'?';
            break;
        }
        default:
            return false;
        }
        if (decoded) decoded->push_back(character);
    }
    return false;
}

bool skipJsonValue(const std::wstring &json, size_t &position) {
    skipJsonWhitespace(json, position);
    if (position >= json.size()) return false;

    if (json[position] == L'"') {
        return readJsonString(json, position, nullptr);
    }
    if (json[position] == L'{' || json[position] == L'[') {
        int depth = 0;
        while (position < json.size()) {
            const wchar_t value = json[position];
            if (value == L'"') {
                if (!readJsonString(json, position, nullptr)) return false;
                continue;
            }
            if (value == L'{' || value == L'[') ++depth;
            else if (value == L'}' || value == L']') {
                --depth;
                ++position;
                if (depth == 0) return true;
                continue;
            }
            ++position;
        }
        return false;
    }

    const size_t start = position;
    while (position < json.size() && json[position] != L',' &&
           json[position] != L'}' && json[position] != L']') {
        ++position;
    }
    return position > start;
}

bool readJsonStringProperty(const std::wstring &json, const std::wstring &property,
                            std::wstring &value) {
    size_t position = 0;
    skipJsonWhitespace(json, position);
    if (position >= json.size() || json[position++] != L'{') return false;

    while (position < json.size()) {
        skipJsonWhitespace(json, position);
        if (position >= json.size() || json[position] == L'}') return false;

        std::wstring key;
        if (!readJsonString(json, position, &key)) return false;
        skipJsonWhitespace(json, position);
        if (position >= json.size() || json[position++] != L':') return false;
        skipJsonWhitespace(json, position);

        if (key == property) {
            return readJsonString(json, position, &value);
        }
        if (!skipJsonValue(json, position)) return false;
        skipJsonWhitespace(json, position);
        if (position < json.size() && json[position] == L',') ++position;
        else return false;
    }
    return false;
}

bool windowsUsesDarkTheme() {
    DWORD appsUseLightTheme = 1;
    DWORD valueSize = sizeof(appsUseLightTheme);
    const LSTATUS registryStatus = RegGetValueW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme",
        RRF_RT_REG_DWORD,
        nullptr,
        &appsUseLightTheme,
        &valueSize
    );
    if (registryStatus == ERROR_SUCCESS) {
        return appsUseLightTheme == 0;
    }

    // Registry access can be unavailable in restricted profiles. Fall back to
    // the effective system window color instead of forcing the dark palette.
    const COLORREF windowColor = GetSysColor(COLOR_WINDOW);
    const unsigned int luminance =
        (299u * GetRValue(windowColor) + 587u * GetGValue(windowColor) +
         114u * GetBValue(windowColor)) / 1000u;
    return luminance < 128u;
}

bool resolveConfiguredDarkTheme() {
    std::wstring roamingDirectory;
    DWORD required = GetEnvironmentVariableW(L"APPDATA", nullptr, 0);
    if (required > 1 && required < 32768) {
        roamingDirectory.resize(required);
        const DWORD copied = GetEnvironmentVariableW(
            L"APPDATA", roamingDirectory.data(), required
        );
        if (copied > 0 && copied < required) roamingDirectory.resize(copied);
        else roamingDirectory.clear();
    }
    if (roamingDirectory.empty()) {
        PWSTR knownFolder = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(
                FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, nullptr, &knownFolder)) &&
            knownFolder) {
            roamingDirectory = knownFolder;
            CoTaskMemFree(knownFolder);
        }
    }

    if (!roamingDirectory.empty()) {
        const std::wstring configPath =
            roamingDirectory + L"\\TorProxy\\config.json";
        const std::wstring config = readFile(configPath, 1024u * 1024u);
        std::wstring preference;
        if (readJsonStringProperty(config, L"theme_preference", preference)) {
            if (preference == L"dark") return true;
            if (preference == L"light") return false;
            if (preference == L"system") return windowsUsesDarkTheme();
        }

        // Older configuration files only persisted the effective mode.
        if (readJsonStringProperty(config, L"mode", preference)) {
            if (preference == L"dark") return true;
            if (preference == L"light") return false;
        }
    }
    return windowsUsesDarkTheme();
}

std::wstring logTail(const std::wstring &path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) { CloseHandle(file); return {}; }
    DWORD count = static_cast<DWORD>(std::min<LONGLONG>(size.QuadPart, 5000));
    LARGE_INTEGER offset{}; offset.QuadPart = -static_cast<LONGLONG>(count);
    SetFilePointerEx(file, offset, nullptr, FILE_END);
    std::string bytes(count, '\0'); DWORD got = 0;
    BOOL ok = ReadFile(file, bytes.data(), count, &got, nullptr); CloseHandle(file);
    if (!ok || !got) return {};
    bytes.resize(got); std::wstring out = utf8(bytes);
    if (out.size() > 1500) out = L"…" + out.substr(out.size() - 1500);
    return out;
}
void showError(State &s, const std::wstring &message) {
    if (s.ready || s.failed) return;
    s.failed = true; s.status = L"Startup needs attention"; s.error = message;
    const auto tail = logTail(s.logPath);
    if (!tail.empty()) s.error += L"\r\n\r\n" + tail;
    InvalidateRect(s.window, nullptr, FALSE);
}
void stopChild(State &s) {
    if (s.process) {
        DWORD code = 0;
        if (GetExitCodeProcess(s.process, &code) && code == STILL_ACTIVE) {
            TerminateProcess(s.process, 1); WaitForSingleObject(s.process, 1600);
        }
        CloseHandle(s.process); s.process = nullptr;
    }
    if (s.thread) { CloseHandle(s.thread); s.thread = nullptr; }
}
bool preparePaths(State &s) {
    wchar_t local[MAX_PATH]{}; DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    s.logPath = std::wstring(local, n) + L"\\TorProxy\\State\\logs\\launcher-startup.log";
    const auto slash = s.logPath.find_last_of(L"\\/");
    const auto directory = s.logPath.substr(0, slash);
    int result = SHCreateDirectoryExW(nullptr, directory.c_str(), nullptr);
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS)
        return false;
    wchar_t temp[MAX_PATH]{}; n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH) return false;
    const auto id = guid(), token = guid();
    if (id.empty() || token.empty()) return false;
    s.statusPath = std::wstring(temp) + L"torproxy-" + id + L".status";
    s.token = token; return true;
}
void startApp(State &s) {
    if (s.ready) return;
    stopChild(s); DeleteFileW(s.statusPath.c_str());
    s.darkTheme = resolveConfiguredDarkTheme();
    s.failed = false; s.error.clear(); s.lastPayload.clear();
    s.status = L"Starting TorProxy…"; s.lastProgress = GetTickCount64();
    InvalidateRect(s.window, nullptr, FALSE);
    if (!preparePaths(s)) { showError(s, L"Could not prepare TorProxy's per-user startup paths."); return; }
    DeleteFileW(s.logPath.c_str());
    SetEnvironmentVariableW(L"TORPROXY_LAUNCHER_STATUS_FILE", s.statusPath.c_str());
    SetEnvironmentVariableW(L"TORPROXY_LAUNCHER_TOKEN", s.token.c_str());
    SetEnvironmentVariableW(L"TORPROXY_LAUNCHER_LOG", s.logPath.c_str());

    std::wstring command = quote(s.executable);
    int argc = 0; LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (std::wstring(argv[i]) == L"--self-test") continue;
            command += L" " + quote(argv[i]);
        }
        LocalFree(argv);
    }
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(s.executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                        CREATE_UNICODE_ENVIRONMENT, nullptr, s.root.c_str(), &startup, &process)) {
        showError(s, L"Windows could not start TorProxy (error " +
                  std::to_wstring(GetLastError()) + L").");
        return;
    }
    s.process = process.hProcess; s.thread = process.hThread;
    InvalidateRect(s.window, nullptr, FALSE);
}
void readStartupStatus(State &s) {
    const auto text = readFile(s.statusPath);
    const auto first = text.find(L'\n');
    const auto second = first == std::wstring::npos ? first : text.find(L'\n', first + 1);
    if (first == std::wstring::npos || second == std::wstring::npos) return;
    if (text.substr(0, first) != s.token) return;
    const auto status = text.substr(first + 1, second - first - 1);
    auto payload = text.substr(second + 1);
    const auto lineEnd = payload.find_first_of(L"\r\n");
    if (lineEnd != std::wstring::npos) payload.resize(lineEnd);
    const auto unique = status + L"\n" + payload;
    if (unique == s.lastPayload) return;
    s.lastPayload = unique;
    if (status == L"starting") {
        s.status = fromHex(payload);
        if (s.status.empty()) s.status = L"Preparing TorProxy…";
        s.lastProgress = GetTickCount64(); InvalidateRect(s.window, nullptr, FALSE);
    } else if (status == L"ready") {
        s.ready = true; DeleteFileW(s.statusPath.c_str());
        if (s.thread) { CloseHandle(s.thread); s.thread = nullptr; }
        if (s.process) { CloseHandle(s.process); s.process = nullptr; }
        DestroyWindow(s.window);
    } else if (status == L"failed") {
        auto detail = fromHex(payload);
        if (detail.empty()) detail = L"TorProxy reported a startup failure. Open the log for details.";
        showError(s, detail);
    }
}
void poll(State &s) {
    if (s.ready || s.failed) return;
    readStartupStatus(s);
    if (s.ready || s.failed) return;
    if (s.process) {
        DWORD code = STILL_ACTIVE;
        if (GetExitCodeProcess(s.process, &code) && code != STILL_ACTIVE) {
            showError(s, L"TorProxy exited before its main window reported READY (exit code " +
                      std::to_wstring(code) + L").");
            return;
        }
    }
    const ULONGLONG idle = GetTickCount64() - s.lastProgress;
    if (idle > kIdleTimeout) {
        if (s.status.find(L"still starting") == std::wstring::npos) {
            s.status = L"Startup is taking longer than usual — still starting…";
            s.lastProgress = GetTickCount64();
            InvalidateRect(s.window, nullptr, FALSE);
        } else {
            showError(s, L"TorProxy did not report startup progress for another three minutes. Check the startup log.");
        }
    }
}
float logicalX(const State &s, int x) {
    return static_cast<float>(x) / std::max(0.01f, s.scale);
}
void addRoundedPath(Gdiplus::GraphicsPath &path, const Gdiplus::RectF &rect, float radius) {
    using namespace Gdiplus;
    const float diameter = radius * 2.0f;
    path.AddArc(rect.X, rect.Y, diameter, diameter, 180.0f, 90.0f);
    path.AddArc(rect.GetRight() - diameter, rect.Y, diameter, diameter, 270.0f, 90.0f);
    path.AddArc(rect.GetRight() - diameter, rect.GetBottom() - diameter,
                diameter, diameter, 0.0f, 90.0f);
    path.AddArc(rect.X, rect.GetBottom() - diameter, diameter, diameter, 90.0f, 90.0f);
    path.CloseFigure();
}
void drawText(Gdiplus::Graphics &graphics, const std::wstring &text,
              const Gdiplus::RectF &rect, float size, const Gdiplus::Color &color,
              bool bold = false,
              Gdiplus::StringAlignment alignment = Gdiplus::StringAlignmentCenter,
              Gdiplus::StringAlignment lineAlignment = Gdiplus::StringAlignmentCenter,
              bool wrap = false) {
    using namespace Gdiplus;
    Font font(L"Segoe UI", size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color);
    StringFormat format;
    format.SetAlignment(alignment);
    format.SetLineAlignment(lineAlignment);
    format.SetTrimming(StringTrimmingEllipsisWord);
    if (!wrap) format.SetFormatFlags(StringFormatFlagsNoWrap);
    graphics.DrawString(text.c_str(), static_cast<INT>(text.size()), &font,
                        rect, &format, &brush);
}
struct ThemePalette {
    Gdiplus::Color backgroundStart, backgroundEnd, glowCenter, glowEdge, outline;
    Gdiplus::Color accentStart, accentEnd, eyebrow, metadata;
    Gdiplus::Color closeHoverFill, closePen, closePenHover, logoHalo;
    Gdiplus::Color title, subtitle, spinnerTrack, spinner, status;
    Gdiplus::Color progressTrack, progressStart, progressEnd, footer;
    Gdiplus::Color errorTitle, errorSubtitle, errorDetail;
    Gdiplus::Color primaryTop, primaryBottom, primaryHoverTop, primaryHoverBottom;
    Gdiplus::Color secondaryTop, secondaryBottom, secondaryHoverTop, secondaryHoverBottom;
    Gdiplus::Color primaryText, secondaryText, buttonBorder, buttonHoverBorder;
};

ThemePalette themePalette(bool dark) {
    using Gdiplus::Color;
    if (dark) {
        return {
            Color(255, 20, 34, 47), Color(255, 10, 19, 29),
            Color(42, 37, 172, 153), Color(0, 37, 172, 153),
            Color(70, 143, 185, 198),
            Color(255, 57, 210, 187), Color(255, 39, 127, 157),
            Color(255, 143, 170, 182), Color(255, 100, 127, 141),
            Color(32, 232, 245, 248), Color(155, 220, 234, 238),
            Color(245, 220, 234, 238), Color(30, 77, 221, 194),
            Color(255, 241, 247, 249), Color(255, 151, 174, 184),
            Color(65, 139, 174, 184), Color(255, 65, 220, 195),
            Color(255, 202, 219, 224),
            Color(55, 130, 164, 176), Color(255, 50, 205, 181),
            Color(255, 44, 137, 167), Color(255, 102, 132, 145),
            Color(255, 244, 247, 248), Color(255, 159, 181, 190),
            Color(255, 172, 191, 198),
            Color(255, 36, 151, 137), Color(255, 25, 119, 111),
            Color(255, 48, 178, 161), Color(255, 34, 145, 133),
            Color(255, 31, 48, 62), Color(255, 23, 37, 50),
            Color(255, 42, 64, 79), Color(255, 29, 47, 62),
            Color(255, 234, 245, 247), Color(255, 234, 245, 247),
            Color(65, 125, 190, 190), Color(125, 125, 190, 190)
        };
    }
    return {
        Color(255, 248, 251, 252), Color(255, 230, 238, 242),
        Color(30, 33, 151, 139), Color(0, 33, 151, 139),
        Color(95, 93, 125, 139),
        Color(255, 24, 148, 135), Color(255, 42, 118, 157),
        Color(255, 76, 103, 115), Color(255, 108, 129, 140),
        Color(28, 28, 52, 64), Color(190, 42, 66, 77),
        Color(255, 26, 46, 56), Color(36, 45, 160, 150),
        Color(255, 22, 40, 50), Color(255, 74, 97, 108),
        Color(65, 74, 109, 122), Color(255, 20, 143, 133),
        Color(255, 58, 80, 92),
        Color(60, 91, 119, 132), Color(255, 32, 155, 142),
        Color(255, 37, 130, 165), Color(255, 111, 132, 143),
        Color(255, 22, 40, 50), Color(255, 84, 104, 114),
        Color(255, 76, 96, 107),
        Color(255, 24, 137, 126), Color(255, 20, 113, 105),
        Color(255, 40, 158, 145), Color(255, 30, 133, 124),
        Color(255, 229, 239, 243), Color(255, 219, 232, 237),
        Color(255, 212, 227, 233), Color(255, 199, 218, 225),
        Color(255, 247, 252, 253), Color(255, 33, 57, 67),
        Color(95, 72, 112, 130), Color(145, 72, 112, 130)
    };
}

void drawButton(Gdiplus::Graphics &graphics, const Gdiplus::RectF &rect,
                const std::wstring &label, bool primary, bool hovered,
                const ThemePalette &colors) {
    using namespace Gdiplus;
    GraphicsPath path;
    addRoundedPath(path, rect, 12.0f);
    Color top = primary ? colors.primaryTop : colors.secondaryTop;
    Color bottom = primary ? colors.primaryBottom : colors.secondaryBottom;
    if (hovered) {
        top = primary ? colors.primaryHoverTop : colors.secondaryHoverTop;
        bottom = primary ? colors.primaryHoverBottom : colors.secondaryHoverBottom;
    }
    LinearGradientBrush fill(rect, top, bottom, LinearGradientModeVertical);
    graphics.FillPath(&fill, &path);
    Pen border(hovered ? colors.buttonHoverBorder : colors.buttonBorder,
               hovered ? 1.4f : 1.0f);
    graphics.DrawPath(&border, &path);
    drawText(graphics, label, rect, 13.0f,
             primary ? colors.primaryText : colors.secondaryText, true);
}
int hitAction(const State &s, int x, int y) {
    const float lx = logicalX(s, x), ly = logicalX(s, y);
    if (lx >= 698.0f && lx <= 744.0f && ly >= 18.0f && ly <= 64.0f) return kClose;
    if (!s.failed || ly < 388.0f || ly > 448.0f) return -1;
    constexpr float left = 73.0f, width = 192.0f, gap = 16.0f;
    for (int index = 0; index < 3; ++index) {
        const float x1 = left + index * (width + gap);
        if (lx >= x1 && lx <= x1 + width) return index;
    }
    return -1;
}
void paintFrame(State &s, HDC dc) {
    using namespace Gdiplus;
    const ThemePalette colors = themePalette(s.darkTheme);
    Graphics graphics(dc);
    graphics.Clear(colors.backgroundEnd);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetPixelOffsetMode(PixelOffsetModeHighQuality);
    graphics.SetCompositingQuality(CompositingQualityHighQuality);
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    // Grayscale antialiasing avoids ClearType sub-pixel fringes on the off-screen surface.
    graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    graphics.ScaleTransform(s.scale, s.scale);

    const RectF canvas(0.0f, 0.0f, static_cast<float>(kDesignWidth),
                       static_cast<float>(kDesignHeight));
    GraphicsPath panel;
    addRoundedPath(panel, canvas, kPanelCornerRadius);
    LinearGradientBrush background(
        canvas, colors.backgroundStart, colors.backgroundEnd,
        LinearGradientModeForwardDiagonal
    );
    graphics.FillPath(&background, &panel);

    GraphicsPath glowPath;
    glowPath.AddEllipse(RectF(210.0f, 20.0f, 340.0f, 300.0f));
    PathGradientBrush glow(&glowPath);
    glow.SetCenterColor(colors.glowCenter);
    Color glowEdges[] = {colors.glowEdge};
    INT edgeCount = 1;
    glow.SetSurroundColors(glowEdges, &edgeCount);
    graphics.FillPath(&glow, &glowPath);

    Pen outline(colors.outline, 1.0f);
    graphics.DrawPath(&outline, &panel);
    LinearGradientBrush accent(RectF(30.0f, 0.0f, 700.0f, 3.0f),
                               colors.accentStart, colors.accentEnd,
                               LinearGradientModeHorizontal);
    graphics.FillRectangle(&accent, RectF(30.0f, 0.0f, 700.0f, 3.0f));

    drawText(graphics, L"TORPROXY  /  DESKTOP",
             RectF(42.0f, 25.0f, 300.0f, 24.0f), 11.0f,
             colors.eyebrow, true, StringAlignmentNear);
    drawText(graphics, L"WINDOWS",
             RectF(610.0f, 25.0f, 70.0f, 24.0f), 10.0f,
             colors.metadata, false, StringAlignmentFar);

    const RectF closeRect(698.0f, 18.0f, 46.0f, 46.0f);
    if (s.closeHover) {
        GraphicsPath closeBg;
        addRoundedPath(closeBg, closeRect, 14.0f);
        SolidBrush hover(colors.closeHoverFill);
        graphics.FillPath(&hover, &closeBg);
    }
    Pen closePen(s.closeHover ? colors.closePenHover : colors.closePen,
                 s.closeHover ? 2.2f : 1.8f);
    closePen.SetStartCap(LineCapRound); closePen.SetEndCap(LineCapRound);
    graphics.DrawLine(&closePen, 714.0f, 34.0f, 728.0f, 48.0f);
    graphics.DrawLine(&closePen, 728.0f, 34.0f, 714.0f, 48.0f);

    if (s.logo && s.logo->GetLastStatus() == Ok) {
        SolidBrush logoHalo(colors.logoHalo);
        graphics.FillEllipse(&logoHalo, RectF(319.0f, 73.0f, 122.0f, 122.0f));
        graphics.DrawImage(s.logo.get(), RectF(331.0f, 85.0f, 98.0f, 98.0f));
    }

    if (!s.failed) {
        drawText(graphics, L"TorProxy", RectF(60.0f, 190.0f, 640.0f, 55.0f),
                 35.0f, colors.title, true);
        drawText(graphics, L"Private connections, simplified",
                 RectF(80.0f, 245.0f, 600.0f, 30.0f), 14.0f,
                 colors.subtitle);

        Pen spinnerTrack(colors.spinnerTrack, 3.6f);
        spinnerTrack.SetStartCap(LineCapRound); spinnerTrack.SetEndCap(LineCapRound);
        graphics.DrawEllipse(&spinnerTrack, RectF(367.0f, 309.0f, 26.0f, 26.0f));
        Pen spinner(colors.spinner, 3.8f);
        spinner.SetStartCap(LineCapRound); spinner.SetEndCap(LineCapRound);
        graphics.DrawArc(&spinner, RectF(367.0f, 309.0f, 26.0f, 26.0f),
                         static_cast<REAL>(s.angle), 255.0f);
        drawText(graphics, s.status, RectF(58.0f, 345.0f, 644.0f, 30.0f),
                 13.0f, colors.status, true);

        const RectF track(52.0f, 402.0f, 656.0f, 5.0f);
        GraphicsPath trackPath;
        addRoundedPath(trackPath, track, 2.5f);
        SolidBrush trackBrush(colors.progressTrack);
        graphics.FillPath(&trackBrush, &trackPath);
        const float segmentWidth = 115.0f;
        const float travel = track.Width + segmentWidth;
        const float offset = static_cast<float>(s.progress % 500) / 500.0f * travel;
        RectF moving(track.X + offset - segmentWidth, track.Y, segmentWidth, track.Height);
        const float visibleLeft = std::max(moving.X, track.X);
        const float visibleTop = std::max(moving.Y, track.Y);
        const float visibleRight = std::min(moving.GetRight(), track.GetRight());
        const float visibleBottom = std::min(moving.GetBottom(), track.GetBottom());
        if (visibleRight > visibleLeft && visibleBottom > visibleTop) {
            RectF visible(visibleLeft, visibleTop, visibleRight - visibleLeft, visibleBottom - visibleTop);
            GraphicsPath movingPath;
            addRoundedPath(movingPath, visible, 2.5f);
            LinearGradientBrush movingBrush(visible, colors.progressStart,
                                             colors.progressEnd, LinearGradientModeHorizontal);
            graphics.FillPath(&movingBrush, &movingPath);
        }
        drawText(graphics, L"Loading Python and desktop components",
                 RectF(65.0f, 423.0f, 630.0f, 22.0f), 10.5f,
                 colors.footer);
    } else {
        drawText(graphics, L"Startup needs attention",
                 RectF(55.0f, 190.0f, 650.0f, 52.0f), 30.0f,
                 colors.errorTitle, true);
        drawText(graphics, L"The desktop process stopped before it became ready.",
                 RectF(68.0f, 242.0f, 624.0f, 30.0f), 13.0f,
                 colors.errorSubtitle);
        std::wstring detail = s.error;
        if (detail.size() > 700) detail = detail.substr(0, 690) + L"…";
        drawText(graphics, detail, RectF(80.0f, 284.0f, 600.0f, 92.0f),
                 11.0f, colors.errorDetail, false,
                 StringAlignmentNear, StringAlignmentNear, true);

        drawButton(graphics, RectF(73.0f, 394.0f, 192.0f, 46.0f),
                   L"Try again", true, s.hoverAction == 0, colors);
        drawButton(graphics, RectF(281.0f, 394.0f, 192.0f, 46.0f),
                   L"Open logs", false, s.hoverAction == 1, colors);
        drawButton(graphics, RectF(489.0f, 394.0f, 192.0f, 46.0f),
                   L"Close", false, s.hoverAction == 2, colors);
    }

    Pen footerLine(s.darkTheme ? Color(30, 137, 174, 187) : Color(55, 92, 119, 132), 1.0f);
    graphics.DrawLine(&footerLine, 34.0f, 461.0f, 726.0f, 461.0f);
}


void releaseBackBuffer(State &s) {
    if (s.backBufferDc && s.backBufferPreviousBitmap) {
        SelectObject(s.backBufferDc, s.backBufferPreviousBitmap);
    }
    if (s.backBufferBitmap) {
        DeleteObject(s.backBufferBitmap);
    }
    if (s.backBufferDc) {
        DeleteDC(s.backBufferDc);
    }
    s.backBufferDc = nullptr;
    s.backBufferBitmap = nullptr;
    s.backBufferPreviousBitmap = nullptr;
    s.backBufferWidth = 0;
    s.backBufferHeight = 0;
}

bool ensureBackBuffer(State &s, HDC referenceDc, int width, int height) {
    if (s.backBufferDc && s.backBufferBitmap &&
        s.backBufferWidth == width && s.backBufferHeight == height) {
        return true;
    }

    releaseBackBuffer(s);

    HDC memoryDc = CreateCompatibleDC(referenceDc);
    if (!memoryDc) {
        return false;
    }

    HBITMAP bitmap = CreateCompatibleBitmap(referenceDc, width, height);
    if (!bitmap) {
        DeleteDC(memoryDc);
        return false;
    }

    HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
    if (!previousBitmap || previousBitmap == HGDI_ERROR) {
        DeleteObject(bitmap);
        DeleteDC(memoryDc);
        return false;
    }

    s.backBufferDc = memoryDc;
    s.backBufferBitmap = bitmap;
    s.backBufferPreviousBitmap = previousBitmap;
    s.backBufferWidth = width;
    s.backBufferHeight = height;
    return true;
}

void paint(State &s, HDC targetDc) {
    RECT client{};
    if (!GetClientRect(s.window, &client)) {
        return;
    }

    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    if (width <= 0 || height <= 0) {
        return;
    }

    if (!ensureBackBuffer(s, targetDc, width, height)) {
        // Preserve a visible splash if GDI cannot allocate an off-screen surface.
        paintFrame(s, targetDc);
        return;
    }

    // Render a complete frame off-screen, then publish it with one blit.
    paintFrame(s, s.backBufferDc);
    if (!BitBlt(targetDc, 0, 0, width, height,
                s.backBufferDc, 0, 0, SRCCOPY)) {
        paintFrame(s, targetDc);
    }
}

void updateMonitorLayout(State &s, UINT dpi) {
    if (!s.window) return;
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    HMONITOR monitor = MonitorFromWindow(s.window, MONITOR_DEFAULTTONEAREST);
    if (!monitor || !GetMonitorInfoW(monitor, &monitorInfo)) return;

    const float dpiScale = static_cast<float>(dpi ? dpi : 96) / 96.0f;
    const int availableWidth = monitorInfo.rcWork.right - monitorInfo.rcWork.left;
    const int availableHeight = monitorInfo.rcWork.bottom - monitorInfo.rcWork.top;
    const float fitWidth = (availableWidth * kMaximumWorkAreaWidth) / kDesignWidth;
    const float fitHeight = (availableHeight * kMaximumWorkAreaHeight) / kDesignHeight;
    s.scale = std::max(0.65f, std::min(dpiScale, std::min(fitWidth, fitHeight)));
    s.width = static_cast<int>(std::lround(kDesignWidth * s.scale));
    s.height = static_cast<int>(std::lround(kDesignHeight * s.scale));
    const int x = monitorInfo.rcWork.left + (availableWidth - s.width) / 2;
    const int y = monitorInfo.rcWork.top + (availableHeight - s.height) / 2;
    SetWindowPos(s.window, HWND_TOPMOST, x, y, s.width, s.height,
                 SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    // The window region and painted outline use the same 25-DIP radius.
    // Do not also ask DWM to round this custom-shaped popup: that creates a
    // second, independently rounded edge that looks like a nested border.
    const int cornerDiameter = static_cast<int>(
        std::lround(2.0f * kPanelCornerRadius * s.scale)
    );
    HRGN roundedRegion = CreateRoundRectRgn(
        0, 0, s.width + 1, s.height + 1, cornerDiameter, cornerDiameter
    );
    if (roundedRegion && !SetWindowRgn(s.window, roundedRegion, TRUE))
        DeleteObject(roundedRegion);
    InvalidateRect(s.window, nullptr, FALSE);
}

LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto *s = reinterpret_cast<State *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        s = static_cast<State *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
        s->window = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    }
    if (!s) return DefWindowProcW(hwnd, msg, wp, lp);

    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, kTimer, 32, nullptr);
        return 0;
    case WM_TIMER:
        s->angle = (s->angle + 11) % 360;
        s->progress = (s->progress + 5) % 500;
        if (++s->pollCount >= 4) { s->pollCount = 0; poll(*s); }
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_DPICHANGED: {
        const UINT newDpi = HIWORD(wp);
        const RECT *suggested = reinterpret_cast<const RECT *>(lp);
        SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        updateMonitorLayout(*s, newDpi);
        return 0;
    }
    case WM_DISPLAYCHANGE:
        releaseBackBuffer(*s);
        updateMonitorLayout(*s, GetDpiForWindow(hwnd));
        return 0;
    case WM_NCHITTEST: {
        POINT point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        ScreenToClient(hwnd, &point);
        const float x = logicalX(*s, point.x);
        const float y = logicalX(*s, point.y);
        if (x >= 698.0f && x <= 744.0f && y >= 18.0f && y <= 64.0f)
            return HTCLIENT;
        if (y >= 0.0f && y <= 70.0f) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_MOUSEMOVE: {
        if (!s->trackingMouse) {
            TRACKMOUSEEVENT tracking{};
            tracking.cbSize = sizeof(tracking);
            tracking.dwFlags = TME_LEAVE;
            tracking.hwndTrack = hwnd;
            s->trackingMouse = TrackMouseEvent(&tracking) != FALSE;
        }
        const int action = hitAction(*s, GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        const bool closeHover = action == kClose;
        if (action != s->hoverAction || closeHover != s->closeHover) {
            s->hoverAction = action;
            s->closeHover = closeHover;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        s->trackingMouse = false;
        s->hoverAction = -1;
        s->closeHover = false;
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_SETCURSOR:
        if (LOWORD(lp) == HTCLIENT && (s->closeHover || s->hoverAction >= 0)) {
            SetCursor(LoadCursorW(nullptr, MAKEINTRESOURCEW(32649)));
            return TRUE;
        }
        break;
    case WM_LBUTTONUP: {
        const int action = hitAction(*s, GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        if (action == kClose) {
            stopChild(*s);
            DestroyWindow(hwnd);
            return 0;
        }
        if (action == 0 && s->failed) {
            startApp(*s);
            return 0;
        }
        if (action == 1 && s->failed) {
            if (!s->logPath.empty())
                ShellExecuteW(hwnd, L"open", s->logPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        if (action == 2 && s->failed) {
            stopChild(*s);
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        paint(*s, dc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_CLOSE:
        stopChild(*s);
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, kTimer);
        releaseBackBuffer(*s);
        stopChild(*s);
        if (!s->statusPath.empty()) DeleteFileW(s->statusPath.c_str());
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
bool createWindow(State &s, HINSTANCE instance) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    wc.lpfnWndProc = windowProc;
    wc.hInstance = instance;
    wc.hIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101),
        IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = kClassName;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    s.icon = wc.hIcon;

    POINT cursor{};
    GetCursorPos(&cursor);
    HMONITOR monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    if (!monitor || !GetMonitorInfoW(monitor, &info)) return false;
    const int x = info.rcWork.left + ((info.rcWork.right - info.rcWork.left) - kDesignWidth) / 2;
    const int y = info.rcWork.top + ((info.rcWork.bottom - info.rcWork.top) - kDesignHeight) / 2;

    // WS_POPUP is intentional: no title bar, caption, resize border or system menu.
    s.window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_TOPMOST, kClassName, L"TorProxy",
        WS_POPUP, x, y, kDesignWidth, kDesignHeight,
        nullptr, nullptr, instance, &s);
    if (!s.window) return false;

    updateMonitorLayout(s, GetDpiForWindow(s.window));
    ShowWindow(s.window, SW_SHOWNORMAL);
    UpdateWindow(s.window);
    return true;
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    SetCurrentProcessExplicitAppUserModelID(L"TorProxy.Desktop");

    Gdiplus::GdiplusStartupInput gdiplusInput;
    ULONG_PTR gdiplusToken = 0;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusInput, nullptr) != Gdiplus::Ok) {
        MessageBoxW(nullptr, L"Could not initialize the TorProxy startup renderer.",
                    L"TorProxy", MB_OK | MB_ICONERROR);
        return 5;
    }

    State state;
    state.darkTheme = resolveConfiguredDarkTheme();
    const auto path = executablePath();
    if (path.empty()) {
        Gdiplus::GdiplusShutdown(gdiplusToken);
        MessageBoxW(nullptr, L"Could not locate the TorProxy launcher.",
                    L"TorProxy", MB_OK | MB_ICONERROR);
        return 2;
    }
    const auto slash = path.find_last_of(L"\\/");
    state.root = slash == std::wstring::npos ? L"." : path.substr(0, slash);
    state.executable = state.root + L"\\TorProxy.exe";

    bool selfTest = false;
    std::wstring expectedTheme;
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            const std::wstring argument(argv[i]);
            if (argument == L"--self-test") selfTest = true;
            else if (argument.compare(0, 15, L"--expect-theme=") == 0)
                expectedTheme = argument.substr(15);
        }
        LocalFree(argv);
    }
    if (!loadSplashLogo(state)) {
        Gdiplus::GdiplusShutdown(gdiplusToken);
        MessageBoxW(nullptr,
                    L"Could not load the high-resolution TorProxy logo (assets\\icon.png).",
                    L"TorProxy", MB_OK | MB_ICONERROR);
        return 6;
    }

    if (!createWindow(state, instance)) {
        state.logo.reset();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        MessageBoxW(nullptr, L"Could not create the TorProxy startup window.",
                    L"TorProxy", MB_OK | MB_ICONERROR);
        return 3;
    }

    if (selfTest) {
        const LONG_PTR style = GetWindowLongPtrW(state.window, GWL_STYLE);
        RECT bounds{};
        GetWindowRect(state.window, &bounds);
        const bool frameless = (style & WS_POPUP) != 0 &&
            (style & (WS_CAPTION | WS_THICKFRAME | WS_SYSMENU)) == 0;
        const bool sizeValid = state.scale >= 0.65f &&
            (bounds.right - bounds.left) >= 680 &&
            (bounds.bottom - bounds.top) >= 420;
        const bool iconLoaded = state.icon != nullptr;
        const bool logoLoaded = state.logo && state.logo->GetLastStatus() == Gdiplus::Ok;
        const bool themeMatches = expectedTheme.empty() ||
            (expectedTheme == L"dark" && state.darkTheme) ||
            (expectedTheme == L"light" && !state.darkTheme);
        const bool bufferedPaintReady = state.backBufferDc != nullptr &&
            state.backBufferBitmap != nullptr &&
            state.backBufferWidth == bounds.right - bounds.left &&
            state.backBufferHeight == bounds.bottom - bounds.top;
        DestroyWindow(state.window);
        state.logo.reset();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return (frameless && sizeValid && iconLoaded && logoLoaded &&
                bufferedPaintReady && themeMatches) ? 0 : 4;
    }

    startApp(state);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    state.logo.reset();
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return static_cast<int>(msg.wParam);
}
#else
#include <cerrno>
#include <cstdio>
#include <limits.h>
#include <string>
#include <vector>
#include <unistd.h>
int main(int argc, char *argv[]) {
    char executable[PATH_MAX + 1]{};
    const ssize_t length = readlink("/proc/self/exe", executable, PATH_MAX);
    if (length <= 0) { std::perror("TorProxyLauncher: cannot resolve executable path"); return 2; }
    executable[length] = '\0';
    std::string root(executable);
    const std::size_t separator = root.find_last_of('/');
    root = separator == std::string::npos ? "." : root.substr(0, separator);
    const std::string gui = root + "/launcher-runtime/bin/TorProxyLauncherUI";
    std::vector<char *> args; args.reserve(static_cast<size_t>(argc) + 1);
    args.push_back(const_cast<char *>(gui.c_str()));
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    args.push_back(nullptr);
    execv(gui.c_str(), args.data());
    std::perror("TorProxyLauncher: cannot start native splash runtime");
    return errno == 0 ? 127 : errno;
}
#endif
