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
#include <gdiplus.h>
#include <dwmapi.h>

namespace {
constexpr wchar_t kClassName[] = L"TorProxy.LauncherWindow";
constexpr UINT_PTR kTimer = 1;
constexpr UINT kClose = 1003;
constexpr int kDesignWidth = 760, kDesignHeight = 480;
constexpr float kMaximumWorkAreaWidth = 0.88f;
constexpr float kMaximumWorkAreaHeight = 0.86f;
constexpr ULONGLONG kIdleTimeout = 180000;

struct State {
    HWND window = nullptr;
    HICON icon = nullptr;
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
    InvalidateRect(s.window, nullptr, TRUE);
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
    InvalidateRect(s.window, nullptr, TRUE);
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
void drawButton(Gdiplus::Graphics &graphics, const Gdiplus::RectF &rect,
                const std::wstring &label, bool primary, bool hovered) {
    using namespace Gdiplus;
    GraphicsPath path;
    addRoundedPath(path, rect, 12.0f);
    Color top = primary ? Color(255, 36, 151, 137) : Color(255, 31, 48, 62);
    Color bottom = primary ? Color(255, 25, 119, 111) : Color(255, 23, 37, 50);
    if (hovered) {
        top = primary ? Color(255, 48, 178, 161) : Color(255, 42, 64, 79);
        bottom = primary ? Color(255, 34, 145, 133) : Color(255, 29, 47, 62);
    }
    LinearGradientBrush fill(rect, top, bottom, LinearGradientModeVertical);
    graphics.FillPath(&fill, &path);
    Pen border(Color(hovered ? 125 : 65, 125, 190, 190), hovered ? 1.4f : 1.0f);
    graphics.DrawPath(&border, &path);
    drawText(graphics, label, rect, 13.0f,
             Color(255, 234, 245, 247), true);
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
void paint(State &s, HDC dc) {
    using namespace Gdiplus;
    Graphics graphics(dc);
    graphics.Clear(Color(255, 8, 14, 21));
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetPixelOffsetMode(PixelOffsetModeHighQuality);
    graphics.SetCompositingQuality(CompositingQualityHighQuality);
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    graphics.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    graphics.ScaleTransform(s.scale, s.scale);

    const RectF canvas(0.0f, 0.0f, static_cast<float>(kDesignWidth),
                       static_cast<float>(kDesignHeight));
    GraphicsPath panel;
    addRoundedPath(panel, canvas, 25.0f);
    LinearGradientBrush background(
        canvas, Color(255, 20, 34, 47), Color(255, 10, 19, 29),
        LinearGradientModeForwardDiagonal
    );
    graphics.FillPath(&background, &panel);

    GraphicsPath glowPath;
    glowPath.AddEllipse(RectF(210.0f, 20.0f, 340.0f, 300.0f));
    PathGradientBrush glow(&glowPath);
    glow.SetCenterColor(Color(42, 37, 172, 153));
    Color glowEdges[] = {Color(0, 37, 172, 153)};
    INT edgeCount = 1;
    glow.SetSurroundColors(glowEdges, &edgeCount);
    graphics.FillPath(&glow, &glowPath);

    Pen outline(Color(70, 143, 185, 198), 1.0f);
    graphics.DrawPath(&outline, &panel);
    LinearGradientBrush accent(RectF(30.0f, 0.0f, 700.0f, 3.0f),
                               Color(255, 57, 210, 187),
                               Color(255, 39, 127, 157),
                               LinearGradientModeHorizontal);
    graphics.FillRectangle(&accent, RectF(30.0f, 0.0f, 700.0f, 3.0f));

    drawText(graphics, L"TORPROXY  /  DESKTOP",
             RectF(42.0f, 25.0f, 300.0f, 24.0f), 11.0f,
             Color(255, 143, 170, 182), true, StringAlignmentNear);
    drawText(graphics, L"WINDOWS",
             RectF(610.0f, 25.0f, 70.0f, 24.0f), 10.0f,
             Color(255, 100, 127, 141), false, StringAlignmentFar);

    const RectF closeRect(698.0f, 18.0f, 46.0f, 46.0f);
    if (s.closeHover) {
        GraphicsPath closeBg;
        addRoundedPath(closeBg, closeRect, 14.0f);
        SolidBrush hover(Color(32, 232, 245, 248));
        graphics.FillPath(&hover, &closeBg);
    }
    Pen closePen(Color(s.closeHover ? 245 : 155, 220, 234, 238),
                 s.closeHover ? 2.2f : 1.8f);
    closePen.SetStartCap(LineCapRound); closePen.SetEndCap(LineCapRound);
    graphics.DrawLine(&closePen, 714.0f, 34.0f, 728.0f, 48.0f);
    graphics.DrawLine(&closePen, 728.0f, 34.0f, 714.0f, 48.0f);

    if (s.icon) {
        Bitmap logo(s.icon);
        if (logo.GetLastStatus() == Ok) {
            SolidBrush logoHalo(Color(30, 77, 221, 194));
            graphics.FillEllipse(&logoHalo, RectF(319.0f, 73.0f, 122.0f, 122.0f));
            graphics.DrawImage(&logo, RectF(331.0f, 85.0f, 98.0f, 98.0f));
        }
    }

    if (!s.failed) {
        drawText(graphics, L"TorProxy", RectF(60.0f, 190.0f, 640.0f, 55.0f),
                 35.0f, Color(255, 241, 247, 249), true);
        drawText(graphics, L"Private connections, simplified",
                 RectF(80.0f, 245.0f, 600.0f, 30.0f), 14.0f,
                 Color(255, 151, 174, 184));

        Pen spinnerTrack(Color(65, 139, 174, 184), 3.6f);
        spinnerTrack.SetStartCap(LineCapRound); spinnerTrack.SetEndCap(LineCapRound);
        graphics.DrawEllipse(&spinnerTrack, RectF(367.0f, 309.0f, 26.0f, 26.0f));
        Pen spinner(Color(255, 65, 220, 195), 3.8f);
        spinner.SetStartCap(LineCapRound); spinner.SetEndCap(LineCapRound);
        graphics.DrawArc(&spinner, RectF(367.0f, 309.0f, 26.0f, 26.0f),
                         static_cast<REAL>(s.angle), 255.0f);
        drawText(graphics, s.status, RectF(58.0f, 345.0f, 644.0f, 30.0f),
                 13.0f, Color(255, 202, 219, 224), true);

        const RectF track(52.0f, 402.0f, 656.0f, 5.0f);
        GraphicsPath trackPath;
        addRoundedPath(trackPath, track, 2.5f);
        SolidBrush trackBrush(Color(55, 130, 164, 176));
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
            LinearGradientBrush movingBrush(visible, Color(255, 50, 205, 181),
                                             Color(255, 44, 137, 167), LinearGradientModeHorizontal);
            graphics.FillPath(&movingBrush, &movingPath);
        }
        drawText(graphics, L"Loading Python and desktop components",
                 RectF(65.0f, 423.0f, 630.0f, 22.0f), 10.5f,
                 Color(255, 102, 132, 145));
    } else {
        drawText(graphics, L"Startup needs attention",
                 RectF(55.0f, 190.0f, 650.0f, 52.0f), 30.0f,
                 Color(255, 244, 247, 248), true);
        drawText(graphics, L"The desktop process stopped before it became ready.",
                 RectF(68.0f, 242.0f, 624.0f, 30.0f), 13.0f,
                 Color(255, 159, 181, 190));
        std::wstring detail = s.error;
        if (detail.size() > 700) detail = detail.substr(0, 690) + L"…";
        drawText(graphics, detail, RectF(80.0f, 284.0f, 600.0f, 92.0f),
                 11.0f, Color(255, 172, 191, 198), false,
                 StringAlignmentNear, StringAlignmentNear, true);

        drawButton(graphics, RectF(73.0f, 394.0f, 192.0f, 46.0f),
                   L"Try again", true, s.hoverAction == 0);
        drawButton(graphics, RectF(281.0f, 394.0f, 192.0f, 46.0f),
                   L"Open logs", false, s.hoverAction == 1);
        drawButton(graphics, RectF(489.0f, 394.0f, 192.0f, 46.0f),
                   L"Close", false, s.hoverAction == 2);
    }

    Pen footerLine(Color(30, 137, 174, 187), 1.0f);
    graphics.DrawLine(&footerLine, 34.0f, 461.0f, 726.0f, 461.0f);
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
    const int corner = static_cast<int>(std::lround(46.0f * s.scale));
    HRGN roundedRegion = CreateRoundRectRgn(0, 0, s.width + 1, s.height + 1,
                                             corner, corner);
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
    const DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(s.window, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
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
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i)
            if (std::wstring(argv[i]) == L"--self-test") selfTest = true;
        LocalFree(argv);
    }
    if (!createWindow(state, instance)) {
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
        DestroyWindow(state.window);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return (frameless && sizeValid && iconLoaded) ? 0 : 4;
    }

    startApp(state);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
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
