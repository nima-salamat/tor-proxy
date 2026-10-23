"""Named global-hotkey registry with native Win32 registration and unlock recovery."""
from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from collections.abc import Callable

LOGGER = logging.getLogger(__name__)
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 1, 2, 4, 8, 0x4000

_MODIFIERS = {
    "CTRL": ("Ctrl", MOD_CONTROL), "CONTROL": ("Ctrl", MOD_CONTROL),
    "ALT": ("Alt", MOD_ALT), "SHIFT": ("Shift", MOD_SHIFT),
    "WIN": ("Win", MOD_WIN), "WINDOWS": ("Win", MOD_WIN),
    "META": ("Win", MOD_WIN), "CMD": ("Win", MOD_WIN),
}
_KEYS = {
    "SPACE": ("Space", 0x20), "TAB": ("Tab", 0x09),
    "ENTER": ("Enter", 0x0D), "RETURN": ("Enter", 0x0D),
    "ESC": ("Esc", 0x1B), "ESCAPE": ("Esc", 0x1B),
    "INSERT": ("Insert", 0x2D), "DELETE": ("Delete", 0x2E),
    "HOME": ("Home", 0x24), "END": ("End", 0x23),
    "PAGEUP": ("PageUp", 0x21), "PAGEDOWN": ("PageDown", 0x22),
    "UP": ("Up", 0x26), "DOWN": ("Down", 0x28),
    "LEFT": ("Left", 0x25), "RIGHT": ("Right", 0x27),
}


@dataclass(frozen=True)
class ParsedHotkey:
    text: str
    modifiers: int
    virtual_key: int


def parse_hotkey(shortcut: str) -> ParsedHotkey:
    """Validate a single chord and return a normalized portable representation."""
    if not isinstance(shortcut, str):
        raise ValueError("Shortcut must be text, e.g. Ctrl+Alt+P.")
    parts = [part.strip() for part in shortcut.strip().split("+")]
    if len(parts) < 2 or any(not part for part in parts):
        raise ValueError("A global shortcut needs a modifier and a key, e.g. Ctrl+Alt+P.")

    modifiers = 0
    labels: dict[int, str] = {}
    keys: list[str] = []
    for part in parts:
        item = _MODIFIERS.get(part.upper())
        if item is None:
            keys.append(part)
            continue
        label, bit = item
        if modifiers & bit:
            raise ValueError(f"Modifier '{label}' is repeated.")
        modifiers |= bit
        labels[bit] = label
    if not modifiers:
        raise ValueError("A global shortcut must include Ctrl, Alt, Shift, or Win.")
    if len(keys) != 1:
        raise ValueError("Choose exactly one non-modifier key.")

    token = keys[0].upper()
    if len(token) == 1 and token.isascii() and token.isalpha():
        key, vk = token, ord(token)
    elif len(token) == 1 and token.isascii() and token.isdigit():
        key, vk = token, ord(token)
    elif token.startswith("F") and token[1:].isdigit():
        number = int(token[1:])
        if not 1 <= number <= 24 or number == 12:
            raise ValueError("Use F1–F11 or F13–F24; F12 is reserved by Windows.")
        key, vk = f"F{number}", 0x70 + number - 1
    elif token in _KEYS:
        key, vk = _KEYS[token]
    else:
        raise ValueError(f"'{keys[0]}' is not a supported global shortcut key.")

    ordered = [labels[b] for b in (MOD_CONTROL, MOD_ALT, MOD_SHIFT, MOD_WIN) if b in labels]
    return ParsedHotkey("+".join((*ordered, key)), modifiers | MOD_NOREPEAT, vk)


@dataclass
class _Binding:
    shortcut: str
    callback: Callable[[], None]


class HotkeyManager:
    """A named registry so new application shortcuts can share one backend."""

    def __init__(self, on_error: Callable[[str], None] | None = None):
        self._bindings: dict[str, _Binding] = {}
        self._lock = threading.RLock()
        self._on_error = on_error or (lambda message: LOGGER.warning("%s", message))
        self._backend = _WindowsBackend(self._report_error) if os.name == "nt" else _KeyboardBackend(self._report_error)

    def _report_error(self, message: str) -> None:
        LOGGER.warning("%s", message)
        try:
            self._on_error(message)
        except Exception:
            LOGGER.exception("Hotkey error callback failed.")

    def register(self, name: str, shortcut: str, callback: Callable[[], None]) -> str:
        if not name or not callable(callback):
            raise ValueError("A hotkey name and callable callback are required.")
        parsed = parse_hotkey(shortcut)
        with self._lock:
            previous = self._bindings.get(name)
            self._bindings[name] = _Binding(parsed.text, callback)
            snapshot = self._snapshot()
        try:
            self._backend.set_bindings(snapshot)
        except Exception:
            with self._lock:
                if previous is None:
                    self._bindings.pop(name, None)
                else:
                    self._bindings[name] = previous
                rollback = self._snapshot()
            try:
                self._backend.set_bindings(rollback)
            except Exception:
                LOGGER.exception("Could not restore global-hotkey registrations after a failed add.")
            raise
        return parsed.text

    def update_shortcut(self, name: str, shortcut: str) -> str:
        parsed = parse_hotkey(shortcut)
        with self._lock:
            if name not in self._bindings:
                raise KeyError(f"Unknown hotkey action: {name}")
            previous = self._bindings[name].shortcut
            self._bindings[name].shortcut = parsed.text
            snapshot = self._snapshot()
        try:
            self._backend.set_bindings(snapshot)
        except Exception:
            with self._lock:
                self._bindings[name].shortcut = previous
                rollback = self._snapshot()
            try:
                self._backend.set_bindings(rollback)
            except Exception:
                LOGGER.exception("Could not restore the previous global-hotkey registration.")
            raise
        return parsed.text

    def get_shortcut(self, name: str) -> str:
        with self._lock:
            return self._bindings[name].shortcut

    def _snapshot(self) -> dict[str, tuple[str, Callable[[], None]]]:
        return {name: (item.shortcut, item.callback) for name, item in self._bindings.items()}

    def start(self) -> None:
        try:
            self._backend.start()
        except Exception as exc:
            self._report_error(f"Native global-hotkey backend could not start: {exc}")
            if os.name != "nt" or isinstance(self._backend, _KeyboardBackend):
                raise
            # Retain a best-effort fallback if an unusual Windows installation
            # blocks native window creation. Native registration remains primary.
            fallback = _KeyboardBackend(self._report_error)
            fallback.set_bindings(self._snapshot())
            fallback.start()
            self._backend = fallback

    def stop(self) -> None:
        self._backend.stop()


class _KeyboardBackend:
    """Fallback backend for platforms without the Win32 registration API."""

    def __init__(self, on_error: Callable[[str], None]):
        self._on_error = on_error
        self._bindings: dict[str, tuple[str, Callable[[], None]]] = {}
        self._handles: dict[str, object] = {}
        self._started = False
        self._lock = threading.RLock()

    def set_bindings(self, bindings: dict[str, tuple[str, Callable[[], None]]]) -> None:
        with self._lock:
            previous = dict(self._bindings)
            self._bindings = dict(bindings)
            if not self._started:
                return
            try:
                self._apply(strict=True)
            except Exception:
                self._bindings = previous
                try:
                    self._apply(strict=False)
                except Exception:
                    LOGGER.exception("Could not restore global shortcuts after a failed update.")
                raise

    def start(self) -> None:
        with self._lock:
            self._started = True
            self._apply(strict=False)

    def _apply(self, *, strict: bool) -> None:
        import keyboard
        for handle in self._handles.values():
            try:
                keyboard.remove_hotkey(handle)
            except (KeyError, ValueError):
                pass
        self._handles.clear()
        errors = []
        for name, (shortcut, callback) in self._bindings.items():
            try:
                self._handles[name] = keyboard.add_hotkey(
                    shortcut.lower(), callback, suppress=False, trigger_on_release=False
                )
            except Exception as exc:
                message = f"Could not register global shortcut '{shortcut}' ({name}): {exc}"
                errors.append(message)
                self._on_error(message)
        if errors and strict:
            raise RuntimeError("; ".join(errors))

    def stop(self) -> None:
        with self._lock:
            self._started = False
            try:
                import keyboard
            except ImportError:
                return
            for handle in self._handles.values():
                try:
                    keyboard.remove_hotkey(handle)
                except (KeyError, ValueError):
                    pass
            self._handles.clear()


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t
    )

    class _WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT), ("lpfnWndProc", _WNDPROC),
            ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
            ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
            ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
            ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
        ]

    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND), ("message", wintypes.UINT),
            ("wParam", ctypes.c_size_t), ("lParam", ctypes.c_ssize_t),
            ("time", wintypes.DWORD), ("pt", wintypes.POINT),
            ("lPrivate", wintypes.DWORD),
        ]

    class _WindowsBackend:
        WM_HOTKEY, WM_CLOSE, WM_DESTROY = 0x0312, 0x0010, 0x0002
        WM_WTSSESSION_CHANGE, WM_POWERBROADCAST, WM_APP_RECONFIGURE = 0x02B1, 0x0218, 0x8001
        WTS_SESSION_UNLOCK, PBT_APMRESUMEAUTOMATIC = 0x0008, 0x0012

        def __init__(self, on_error: Callable[[str], None]):
            self._on_error = on_error
            self._bindings: dict[str, tuple[str, Callable[[], None]]] = {}
            self._registered: set[int] = set()
            self._id_to_name: dict[int, str] = {}
            self._lock = threading.RLock()
            self._started = threading.Event()
            self._thread: threading.Thread | None = None
            self._hwnd = None
            self._user32 = None
            self._wts = None
            self._wndproc = None
            self._startup_error: str | None = None
            self._reconfigure_done = threading.Event()
            self._reconfigure_errors: list[str] = []
            self._recovery_timers: list[threading.Timer] = []
            self._recovery_lock = threading.Lock()
            self._class_name = f"TorProxyHotkeyWindow_{os.getpid()}"

        def set_bindings(self, bindings: dict[str, tuple[str, Callable[[], None]]]) -> None:
            with self._lock:
                self._bindings = dict(bindings)
                hwnd, user32 = self._hwnd, self._user32
            if not hwnd or not user32:
                return

            self._reconfigure_done.clear()
            if not user32.PostMessageW(hwnd, self.WM_APP_RECONFIGURE, 0, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            if not self._reconfigure_done.wait(4):
                raise RuntimeError("Timed out while applying the global shortcut registration.")
            if self._reconfigure_errors:
                raise RuntimeError("; ".join(self._reconfigure_errors))

        def start(self) -> None:
            if self._thread and self._thread.is_alive():
                return
            self._started.clear()
            self._startup_error = None
            self._thread = threading.Thread(target=self._run, name="TorProxyNativeHotkeys", daemon=True)
            self._thread.start()
            if not self._started.wait(8):
                raise RuntimeError("Timed out while starting the Windows hotkey manager.")
            if self._startup_error:
                raise RuntimeError(self._startup_error)

        def _apply_hotkeys(self) -> list[str]:
            with self._lock:
                bindings = dict(self._bindings)
            for hotkey_id in tuple(self._registered):
                self._user32.UnregisterHotKey(self._hwnd, hotkey_id)
            self._registered.clear()
            self._id_to_name.clear()
            errors = []
            for hotkey_id, (name, (shortcut, _callback)) in enumerate(bindings.items(), start=1):
                try:
                    parsed = parse_hotkey(shortcut)
                except ValueError as exc:
                    message = f"Invalid shortcut for '{name}': {exc}"
                    errors.append(message)
                    self._on_error(message)
                    continue
                if not self._user32.RegisterHotKey(self._hwnd, hotkey_id, parsed.modifiers, parsed.virtual_key):
                    code = ctypes.get_last_error()
                    message = (
                        f"Could not register '{parsed.text}' for '{name}' (Win32 error {code}). "
                        "Choose another shortcut if another app already owns it."
                    )
                    errors.append(message)
                    self._on_error(message)
                    continue
                self._registered.add(hotkey_id)
                self._id_to_name[hotkey_id] = name
            LOGGER.info(
                "Registered %d of %d Windows global shortcuts.",
                len(self._registered),
                len(bindings),
            )
            return errors

        def _post_reconfigure(self) -> None:
            hwnd, user32 = self._hwnd, self._user32
            if hwnd and user32:
                try:
                    user32.PostMessageW(hwnd, self.WM_APP_RECONFIGURE, 0, 0)
                except Exception:
                    LOGGER.debug("Could not post a hotkey recovery retry.", exc_info=True)

        def _schedule_recovery_retries(self) -> None:
            """Retry after the Windows shell and user desktop finish restoring."""
            with self._recovery_lock:
                for timer in self._recovery_timers:
                    timer.cancel()
                self._recovery_timers.clear()
                for delay in (0.8, 2.5, 6.0):
                    timer = threading.Timer(delay, self._post_reconfigure)
                    timer.daemon = True
                    self._recovery_timers.append(timer)
                    timer.start()

        def _window_proc(self, hwnd, message, wparam, lparam):
            if message == self.WM_HOTKEY:
                name = self._id_to_name.get(int(wparam))
                with self._lock:
                    binding = self._bindings.get(name) if name else None
                if binding is not None:
                    try:
                        binding[1]()
                    except Exception:
                        LOGGER.exception("Global hotkey callback failed for %s.", name)
                return 0
            if message == self.WM_APP_RECONFIGURE:
                self._reconfigure_errors = self._apply_hotkeys()
                self._reconfigure_done.set()
                return 0
            if message == self.WM_WTSSESSION_CHANGE and int(wparam) == self.WTS_SESSION_UNLOCK:
                LOGGER.info("Windows session unlocked; refreshing global shortcuts.")
                self._apply_hotkeys()
                self._schedule_recovery_retries()
                return 0
            if message == self.WM_POWERBROADCAST and int(wparam) == self.PBT_APMRESUMEAUTOMATIC:
                LOGGER.info("Windows resumed; refreshing global shortcuts.")
                self._apply_hotkeys()
                self._schedule_recovery_retries()
                return 1
            if message == self.WM_CLOSE:
                with self._recovery_lock:
                    for timer in self._recovery_timers:
                        timer.cancel()
                    self._recovery_timers.clear()
                for hotkey_id in tuple(self._registered):
                    self._user32.UnregisterHotKey(hwnd, hotkey_id)
                self._registered.clear()
                if self._wts is not None:
                    self._wts.WTSUnRegisterSessionNotification(hwnd)
                self._user32.DestroyWindow(hwnd)
                return 0
            if message == self.WM_DESTROY:
                self._user32.PostQuitMessage(0)
                return 0
            return self._user32.DefWindowProcW(hwnd, message, wparam, lparam)

        def _run(self) -> None:
            try:
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                self._wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
                self._user32 = user32

                user32.DefWindowProcW.restype = ctypes.c_ssize_t
                user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t]
                user32.CreateWindowExW.restype = wintypes.HWND
                user32.CreateWindowExW.argtypes = [
                    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                    wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ]
                user32.RegisterClassW.restype = ctypes.c_ushort
                user32.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASSW)]
                user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
                user32.RegisterHotKey.restype = wintypes.BOOL
                user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
                user32.UnregisterHotKey.restype = wintypes.BOOL
                user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t]
                user32.PostMessageW.restype = wintypes.BOOL
                user32.DestroyWindow.argtypes = [wintypes.HWND]
                user32.DestroyWindow.restype = wintypes.BOOL
                user32.GetMessageW.argtypes = [ctypes.POINTER(_MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
                user32.GetMessageW.restype = ctypes.c_int
                user32.TranslateMessage.argtypes = [ctypes.POINTER(_MSG)]
                user32.DispatchMessageW.argtypes = [ctypes.POINTER(_MSG)]
                user32.PostQuitMessage.argtypes = [ctypes.c_int]
                kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
                kernel32.GetModuleHandleW.restype = ctypes.c_void_p
                self._wts.WTSRegisterSessionNotification.argtypes = [wintypes.HWND, wintypes.DWORD]
                self._wts.WTSRegisterSessionNotification.restype = wintypes.BOOL
                self._wts.WTSUnRegisterSessionNotification.argtypes = [wintypes.HWND]
                self._wts.WTSUnRegisterSessionNotification.restype = wintypes.BOOL

                instance = kernel32.GetModuleHandleW(None)
                self._wndproc = _WNDPROC(self._window_proc)
                wc = _WNDCLASSW(0, self._wndproc, 0, 0, instance, None, None, None, None, self._class_name)
                if not user32.RegisterClassW(ctypes.byref(wc)):
                    error = ctypes.get_last_error()
                    if error != 1410:  # ERROR_CLASS_ALREADY_EXISTS
                        raise ctypes.WinError(error)
                hwnd = user32.CreateWindowExW(
                    0, self._class_name, "TorProxy shortcut receiver", 0,
                    0, 0, 0, 0, None, None, instance, None,
                )
                if not hwnd:
                    raise ctypes.WinError(ctypes.get_last_error())
                self._hwnd = hwnd
                if not self._wts.WTSRegisterSessionNotification(hwnd, 0):
                    self._on_error(f"Could not subscribe to Windows unlock notifications (Win32 error {ctypes.get_last_error()}).")
                self._apply_hotkeys()
                self._started.set()

                msg = _MSG()
                while True:
                    result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                    if result == 0:
                        break
                    if result == -1:
                        LOGGER.error("GetMessageW failed in the global hotkey thread.")
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
            except Exception as exc:
                self._startup_error = str(exc)
                LOGGER.exception("Native Windows hotkey backend failed.")
                self._started.set()
            finally:
                self._hwnd = None

        def stop(self) -> None:
            hwnd, user32 = self._hwnd, self._user32
            if hwnd and user32:
                user32.PostMessageW(hwnd, self.WM_CLOSE, 0, 0)
            thread = self._thread
            if thread and thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=3)
            self._thread = None
