#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <algorithm>
#include <cmath>
#include <string>

namespace {
constexpr wchar_t kClassName[] = L"TorProxy.LauncherWindow";
constexpr UINT_PTR kTimer = 1;
constexpr UINT kRetry = 1001, kLogs = 1002, kClose = 1003;
constexpr int kWidth = 560, kHeight = 340;
constexpr ULONGLONG kIdleTimeout = 180000;

struct State {
    HWND window = nullptr, retry = nullptr, logs = nullptr, close = nullptr;
    HICON icon = nullptr;
    HANDLE process = nullptr, thread = nullptr;
    std::wstring root, executable, logPath, statusPath, token;
    std::wstring status = L"Preparing the desktop experience";
    std::wstring error, lastPayload;
    ULONGLONG lastProgress = 0;
    unsigned int angle = 0, progress = 0, pollCount = 0;
    bool failed = false, ready = false;
};

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
    ShowWindow(s.retry, SW_SHOW); ShowWindow(s.logs, s.logPath.empty() ? SW_HIDE : SW_SHOW);
    ShowWindow(s.close, SW_SHOW); InvalidateRect(s.window, nullptr, TRUE);
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
    s.failed = false; s.error.clear(); s.lastPayload.clear();
    s.status = L"Starting TorProxy…"; s.lastProgress = GetTickCount64();
    ShowWindow(s.retry, SW_HIDE); ShowWindow(s.logs, SW_HIDE); ShowWindow(s.close, SW_HIDE);
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
    InvalidateRect(s.window, nullptr, TRUE);
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
        s.lastProgress = GetTickCount64(); InvalidateRect(s.window, nullptr, TRUE);
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
            InvalidateRect(s.window, nullptr, TRUE);
        } else {
            showError(s, L"TorProxy did not report startup progress for another three minutes. Check the startup log.");
        }
    }
}
void drawText(HDC dc, const std::wstring &text, RECT rect, COLORREF color,
              int size, bool bold = false, UINT flags = DT_CENTER | DT_VCENTER | DT_SINGLELINE) {
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, color);
    HFONT font = CreateFontW(-size, 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL,
        FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    HGDIOBJ old = SelectObject(dc, font);
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, flags);
    SelectObject(dc, old); DeleteObject(font);
}
void fill(HDC dc, RECT rect, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color); FillRect(dc, &rect, brush); DeleteObject(brush);
}
void paint(State &s, HDC dc) {
    RECT bg{0, 0, kWidth, kHeight}; fill(dc, bg, RGB(14, 24, 34));
    RECT accent{26, 0, kWidth - 26, 2}; fill(dc, accent, RGB(54, 191, 174));
    RECT eyebrow{32, 16, 310, 38};
    drawText(dc, L"TORPROXY  /  DESKTOP", eyebrow, RGB(144, 168, 180), 11, true, DT_LEFT | DT_VCENTER);
    RECT platform{425, 16, 526, 38};
    drawText(dc, L"WINDOWS", platform, RGB(99, 124, 137), 10, false, DT_RIGHT | DT_VCENTER);
    if (s.icon) DrawIconEx(dc, (kWidth - 76) / 2, 48, s.icon, 76, 76, 0, nullptr, DI_NORMAL);
    RECT title{26, 130, kWidth - 26, 167};
    drawText(dc, s.failed ? L"Couldn't start TorProxy" : L"TorProxy",
             title, RGB(240, 246, 248), 28, true);
    RECT subtitle{30, 166, kWidth - 30, 192};
    drawText(dc, s.failed ? L"The desktop process stopped before it became ready."
                          : L"Private connections, simplified",
             subtitle, RGB(145, 168, 180), 12);
    if (!s.failed) {
        const int cx = kWidth / 2, cy = 215, r = 10;
        HPEN track = CreatePen(PS_SOLID, 3, RGB(40, 59, 70));
        HGDIOBJ oldPen = SelectObject(dc, track);
        HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Ellipse(dc, cx-r, cy-r, cx+r, cy+r);
        HPEN active = CreatePen(PS_SOLID, 3, RGB(65, 213, 190));
        SelectObject(dc, active);
        const double a = s.angle * 3.141592653589793 / 180.0;
        POINT p1{cx + int(std::cos(a)*r), cy - int(std::sin(a)*r)};
        POINT p2{cx + int(std::cos(a-4.2)*r), cy - int(std::sin(a-4.2)*r)};
        Arc(dc, cx-r, cy-r, cx+r, cy+r, p1.x, p1.y, p2.x, p2.y);
        SelectObject(dc, oldPen); SelectObject(dc, oldBrush);
        DeleteObject(track); DeleteObject(active);
        RECT status{34, 234, kWidth - 34, 262};
        drawText(dc, s.status, status, RGB(196, 212, 218), 12, true);
        RECT trackRect{38, 285, kWidth - 38, 289}; fill(dc, trackRect, RGB(36, 54, 65));
        const int width = 90, travel = trackRect.right - trackRect.left;
        int offset = int(s.progress % unsigned(travel + width));
        RECT segment{trackRect.left + offset - width, trackRect.top, trackRect.left + offset, trackRect.bottom};
        RECT clipped{}; if (IntersectRect(&clipped, &segment, &trackRect)) fill(dc, clipped, RGB(54, 191, 174));
        RECT footer{35, 294, kWidth - 35, 320};
        drawText(dc, L"Loading Python and desktop components", footer, RGB(98, 123, 136), 10);
    } else {
        RECT detail{34, 206, kWidth - 34, 274};
        drawText(dc, s.error, detail, RGB(158, 178, 187), 10, false,
                 DT_CENTER | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
    }
}
LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto *s = reinterpret_cast<State *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        s = static_cast<State *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
        s->window = hwnd; SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    }
    if (!s) return DefWindowProcW(hwnd, msg, wp, lp);
    switch (msg) {
    case WM_CREATE:
        s->retry = CreateWindowW(L"BUTTON", L"Try again", WS_CHILD | BS_PUSHBUTTON,
            54, 280, 138, 34, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kRetry)), nullptr, nullptr);
        s->logs = CreateWindowW(L"BUTTON", L"Open logs", WS_CHILD | BS_PUSHBUTTON,
            211, 280, 138, 34, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kLogs)), nullptr, nullptr);
        s->close = CreateWindowW(L"BUTTON", L"Close", WS_CHILD | BS_PUSHBUTTON,
            368, 280, 138, 34, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kClose)), nullptr, nullptr);
        SetTimer(hwnd, kTimer, 32, nullptr); return 0;
    case WM_TIMER:
        s->angle = (s->angle + 11) % 360; s->progress = (s->progress + 5) % 500;
        if (++s->pollCount >= 4) { s->pollCount = 0; poll(*s); }
        InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kRetry) { startApp(*s); return 0; }
        if (LOWORD(wp) == kLogs) {
            if (!s->logPath.empty()) ShellExecuteW(hwnd, L"open", s->logPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        if (LOWORD(wp) == kClose) { stopChild(*s); DestroyWindow(hwnd); return 0; }
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd, &ps); paint(*s, dc); EndPaint(hwnd, &ps); return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_CLOSE: stopChild(*s); DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        KillTimer(hwnd, kTimer); stopChild(*s);
        if (!s->statusPath.empty()) DeleteFileW(s->statusPath.c_str());
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
bool createWindow(State &s, HINSTANCE instance) {
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = windowProc;
    wc.hInstance = instance; wc.hIcon = static_cast<HICON>(LoadImageW(instance,
        MAKEINTRESOURCEW(101), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    wc.hIconSm = wc.hIcon; wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = kClassName;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    s.icon = wc.hIcon;
    RECT rect{0, 0, kWidth, kHeight}; AdjustWindowRect(&rect, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
    RECT work{}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int x = work.left + ((work.right-work.left) - (rect.right-rect.left))/2;
    int y = work.top + ((work.bottom-work.top) - (rect.bottom-rect.top))/2;
    s.window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_TOPMOST, kClassName, L"TorProxy",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, x, y,
        rect.right-rect.left, rect.bottom-rect.top, nullptr, nullptr, instance, &s);
    if (!s.window) return false;
    ShowWindow(s.window, SW_SHOWNORMAL); UpdateWindow(s.window); return true;
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    SetCurrentProcessExplicitAppUserModelID(L"TorProxy.Desktop");
    State state;
    const auto path = executablePath();
    if (path.empty()) {
        MessageBoxW(nullptr, L"Could not locate the TorProxy launcher.", L"TorProxy", MB_OK | MB_ICONERROR);
        return 2;
    }
    const auto slash = path.find_last_of(L"\\/");
    state.root = slash == std::wstring::npos ? L"." : path.substr(0, slash);
    state.executable = state.root + L"\\TorProxy.exe";
    bool selfTest = false; int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) if (std::wstring(argv[i]) == L"--self-test") selfTest = true;
        LocalFree(argv);
    }
    if (!createWindow(state, instance)) {
        MessageBoxW(nullptr, L"Could not create the TorProxy startup window.", L"TorProxy", MB_OK | MB_ICONERROR);
        return 3;
    }
    if (selfTest) { DestroyWindow(state.window); return state.icon ? 0 : 4; }
    startApp(state);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
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
