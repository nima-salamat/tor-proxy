"""Lightweight runtime localization for TorProxy's Qt interface.

The application keeps its existing left-to-right layout in every language.
Only user-facing text is translated; protocol values, paths, ports, and logs
remain unchanged.
"""
from __future__ import annotations

import weakref
from typing import Any

from PySide6.QtCore import QObject, QEvent, QTimer, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QComboBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QWidget,
)
from PySide6.QtGui import QAction


_FA = {
    "TorProxy": "تورپراکسی",
    "Home": "خانه",
    "Settings": "تنظیمات",
    "Appearance": "ظاهر",
    "Color theme": "پوستهٔ رنگی",
    "Follow your operating system appearance, or choose a fixed light or dark theme.": "از ظاهر سیستم‌عامل پیروی کنید یا پوستهٔ روشن یا تیره را انتخاب کنید.",
    "System follows your desktop setting and updates when it changes.": "حالت سیستم با تغییر ظاهر دسکتاپ به‌روزرسانی می‌شود.",
    "System": "سیستم",
    "Light": "روشن",
    "Dark": "تیره",
    "Follow the operating system appearance": "پیروی از ظاهر سیستم‌عامل",
    "Always use the light theme": "همیشه از پوستهٔ روشن استفاده شود",
    "Always use the dark theme": "همیشه از پوستهٔ تیره استفاده شود",
    "Language": "زبان",
    "Application language": "زبان برنامه",
    "Choose the language used by TorProxy. The layout direction remains unchanged.": "زبان مورد استفاده در تورپراکسی را انتخاب کنید. جهت چیدمان برنامه تغییر نمی‌کند.",
    "English": "انگلیسی",
    "Persian": "فارسی",
    "فارسی": "فارسی",
    "Exit confirmation": "تأیید خروج",
    "Ask before shutting down TorProxy. This setting is saved and can be changed later.": "پیش از بستن تورپراکسی تأیید گرفته شود. این تنظیم ذخیره می‌شود.",
    "Ask before exit": "پیش از خروج سؤال شود",
    "Circuit behavior": "رفتار مدار",
    "These values are used when Tor starts. Changing them while connected applies them on the next connection.": "این مقادیر هنگام شروع Tor استفاده می‌شوند. تغییر آن‌ها هنگام اتصال، از اتصال بعدی اعمال می‌شود.",
    "Max circuit dirtiness (seconds)": "حداکثر عمر استفاده از مدار (ثانیه)",
    "New circuit period (seconds)": "فاصلهٔ ساخت مدار جدید (ثانیه)",
    "How long a circuit may be reused before Tor considers building another one.": "مدتی که یک مدار پیش از ساخت مدار جایگزین قابل استفاده است.",
    "Tor's circuit-building interval; this does not automatically request NEWNYM.": "فاصلهٔ زمانی ساخت مدار در Tor؛ این گزینه به‌طور خودکار NEWNYM درخواست نمی‌کند.",
    "Identity changes remain manual. Tor rate-limits NEWNYM; requesting it does not guarantee a new exit IP.": "تغییر هویت همچنان دستی است. Tor تعداد درخواست‌های NEWNYM را محدود می‌کند و درخواست آن، IP خروجی جدید را تضمین نمی‌کند.",
    "Bridge configuration": "پیکربندی پل",
    "Paste complete Tor bridge records below. TorProxy detects adjacent records, fixes spacing, and stores one bridge per line. Each saved bridge appears as its own card so you can copy or remove it separately.": "رکوردهای کامل پل Tor را در این قسمت وارد کنید. تورپراکسی رکوردهای متوالی را تشخیص می‌دهد، فاصله‌ها را اصلاح می‌کند و هر پل را در یک خط ذخیره می‌کند.",
    "WebTunnel SNI imitation (optional)": "شبیه‌سازی SNI در WebTunnel (اختیاری)",
    "Updates": "به‌روزرسانی‌ها",
    "System Tunnel": "تونل سیستم",
    "Keyboard Shortcuts": "میانبرهای صفحه‌کلید",
    "Statistics": "آمار",
    "Custom Tor": "Tor سفارشی",
    "Developer Tor": "Tor توسعه‌دهنده",
    "Connect": "اتصال",
    "Disconnect": "قطع اتصال",
    "Connecting": "در حال اتصال",
    "Connected": "متصل",
    "Disconnected": "قطع‌شده",
    "Connection": "اتصال",
    "Connection status": "وضعیت اتصال",
    "Status": "وضعیت",
    "Start": "شروع",
    "Stop": "توقف",
    "Restart": "راه‌اندازی مجدد",
    "Reconnect": "اتصال مجدد",
    "New Identity": "هویت جدید",
    "Request a new Tor circuit": "درخواست مدار جدید Tor",
    "Copy": "کپی",
    "Copied": "کپی شد",
    "Cancel": "لغو",
    "Save": "ذخیره",
    "Apply": "اعمال",
    "Close": "بستن",
    "Exit": "خروج",
    "Quit": "خروج",
    "Open": "باز کردن",
    "Browse": "مرور",
    "Refresh": "تازه‌سازی",
    "Retry": "تلاش دوباره",
    "Try again": "تلاش دوباره",
    "Open logs": "باز کردن گزارش‌ها",
    "Logs": "گزارش‌ها",
    "General": "عمومی",
    "Network": "شبکه",
    "Advanced": "پیشرفته",
    "Privacy": "حریم خصوصی",
    "Security": "امنیت",
    "About": "درباره",
    "Help": "راهنما",
    "Enabled": "فعال",
    "Disabled": "غیرفعال",
    "Enable": "فعال‌سازی",
    "Disable": "غیرفعال‌سازی",
    "Automatic": "خودکار",
    "Manual": "دستی",
    "Optional": "اختیاری",
    "Required": "ضروری",
    "Default": "پیش‌فرض",
    "None": "هیچ‌کدام",
    "Unknown": "نامشخص",
    "Available": "در دسترس",
    "Unavailable": "در دسترس نیست",
    "Loading": "در حال بارگذاری",
    "Please wait": "لطفاً صبر کنید",
    "Ready": "آماده",
    "Error": "خطا",
    "Warning": "هشدار",
    "Information": "اطلاعات",
    "Success": "موفق",
    "Failed": "ناموفق",
    "Details": "جزئیات",
    "Name": "نام",
    "Type": "نوع",
    "Port": "درگاه",
    "Host": "میزبان",
    "Address": "نشانی",
    "Path": "مسیر",
    "Value": "مقدار",
    "Description": "توضیحات",
    "Enabled status": "وضعیت فعال‌بودن",
    "Proxy": "پراکسی",
    "HTTP proxy": "پراکسی HTTP",
    "SOCKS proxy": "پراکسی SOCKS",
    "SOCKS5": "SOCKS5",
    "DNS": "DNS",
    "Tor": "Tor",
    "Tor services": "سرویس‌های Tor",
    "Bridge": "پل",
    "Bridges": "پل‌ها",
    "Use bridges": "استفاده از پل‌ها",
    "Add bridge": "افزودن پل",
    "Remove": "حذف",
    "Delete": "حذف",
    "Edit": "ویرایش",
    "Test": "آزمایش",
    "Test connection": "آزمایش اتصال",
    "Check": "بررسی",
    "Check for updates": "بررسی به‌روزرسانی‌ها",
    "Download": "بارگیری",
    "Install": "نصب",
    "Update": "به‌روزرسانی",
    "Version": "نسخه",
    "Current version": "نسخهٔ فعلی",
    "Latest version": "آخرین نسخه",
    "No updates available.": "به‌روزرسانی جدیدی موجود نیست.",
    "Settings could not be saved": "تنظیمات ذخیره نشد",
    "Settings could not be saved.": "تنظیمات ذخیره نشد.",
    "Theme preference": "تنظیم پوسته",
    "Could not save the theme preference.": "ذخیرهٔ تنظیم پوسته انجام نشد.",
    "Could not save exit confirmation preference.": "ذخیرهٔ تنظیم تأیید خروج انجام نشد.",
    "Could not save the language preference.": "ذخیرهٔ تنظیم زبان انجام نشد.",
    "Configuration error": "خطای پیکربندی",
    "Configuration could not be loaded.": "بارگذاری پیکربندی انجام نشد.",
    "Are you sure?": "آیا مطمئن هستید؟",
    "Are you sure you want to exit TorProxy?": "آیا از خروج از تورپراکسی مطمئن هستید؟",
    "No": "خیر",
    "Yes": "بله",
    "OK": "تأیید",
    "Confirm": "تأیید",
    "Back": "بازگشت",
    "Next": "بعدی",
    "Previous": "قبلی",
    "Search": "جست‌وجو",
    "Filter": "فیلتر",
    "Clear": "پاک کردن",
    "Select all": "انتخاب همه",
    "Select": "انتخاب",
    "Import": "درون‌ریزی",
    "Export": "برون‌بری",
    "Reset": "بازنشانی",
    "Restore defaults": "بازگردانی پیش‌فرض‌ها",
    "System proxy": "پراکسی سیستم",
    "Set system proxy": "تنظیم پراکسی سیستم",
    "Do not change system proxy": "پراکسی سیستم تغییر نکند",
    "Clear system proxy": "پاک کردن تنظیم پراکسی سیستم",
    "Follow system": "پیروی از سیستم",
    "Use the system proxy": "استفاده از پراکسی سیستم",
    "Kill switch": "قطع اضطراری ارتباط",
    "Enable kill switch": "فعال‌سازی قطع اضطراری ارتباط",
    "Verify Tor signatures": "بررسی امضای Tor",
    "Confirm before exit": "تأیید پیش از خروج",
    "Global shortcut": "میانبر سراسری",
    "Keyboard shortcut": "میانبر صفحه‌کلید",
    "Press the key combination you want to use. The preview updates while you press and hold keys; release the main key, then press Enter to save.": "ترکیب کلید موردنظر را فشار دهید. پیش‌نمایش هنگام فشردن کلیدها به‌روزرسانی می‌شود؛ کلید اصلی را رها کنید و برای ذخیره Enter را بزنید.",
    "Private connections, simplified": "اتصال خصوصی، ساده‌تر",
    "Couldn't start TorProxy": "تورپراکسی شروع نشد",
    "The desktop process stopped before it became ready.": "فرایند برنامه پیش از آماده‌شدن متوقف شد.",
    "The desktop experience is preparing.": "محیط برنامه در حال آماده‌سازی است.",
    "Preparing the desktop experience": "در حال آماده‌سازی محیط برنامه",
    "Preparing TorProxy…": "در حال آماده‌سازی تورپراکسی…",
    "Loading Python and desktop components…": "در حال بارگذاری پایتون و اجزای دسکتاپ…",
    "Preparing TorProxy settings…": "در حال آماده‌سازی تنظیمات تورپراکسی…",
    "Startup needs attention": "شروع برنامه به بررسی نیاز دارد",
    "Try Close again to attempt cleanup.": "برای تلاش دوباره جهت پاک‌سازی، روی بستن کلیک کنید.",
    "Startup is taking longer than usual — still starting…": "شروع برنامه بیشتر از حد معمول طول کشیده است؛ همچنان در حال شروع…",
    "TorProxy reported a startup failure. Open the log for details.": "تورپراکسی خطایی هنگام شروع گزارش کرد. برای جزئیات، گزارش را باز کنید.",
    "TorProxy exited before its main window reported READY": "تورپراکسی پیش از اعلام آماده‌بودن پنجرهٔ اصلی خارج شد",
    "Could not prepare TorProxy's per-user startup paths.": "آماده‌سازی مسیرهای شروع برنامه برای کاربر انجام نشد.",
    "Could not locate the TorProxy launcher.": "لانچر تورپراکسی پیدا نشد.",
    "The launcher has retained its process reference.": "لانچر همچنان مرجع فرایند را نگه داشته است.",
    "TorProxy": "تورپراکسی",
}

def translate_text(value: Any, language: str = "en") -> str:
    """Translate a complete UI string; preserve unknown and technical text."""
    text = str(value or "")
    if language != "fa" or not text:
        return text
    translated = _FA.get(text)
    if translated is not None:
        return translated
    if text.startswith("Loading "):
        subject = text[8:]
        suffix = ""
        if subject.endswith("…"):
            subject, suffix = subject[:-1], "…"
        return f"در حال بارگذاری {translate_text(subject, language)}{suffix}"
    if text.startswith("Preparing "):
        subject = text[10:]
        suffix = ""
        if subject.endswith("…"):
            subject, suffix = subject[:-1], "…"
        return f"در حال آماده‌سازی {translate_text(subject, language)}{suffix}"
    if text.endswith(" is queued"):
        subject = text[:-10]
        return f"{translate_text(subject, language)} در صف قرار دارد"
    if text.startswith("Loading ") and text.endswith("…"):
        return "در حال بارگذاری " + text[8:-1] + "…"
    return text


def _get_source(obj: QObject, name: str, current: str) -> str:
    source_name = f"_torproxy_i18n_source_{name}"
    rendered_name = f"_torproxy_i18n_rendered_{name}"
    source = getattr(obj, source_name, None)
    rendered = getattr(obj, rendered_name, None)
    if source is None or current != rendered:
        source = current
        setattr(obj, source_name, source)
    return source


class LanguageManager(QObject):
    """Translate visible Qt text without changing widget geometry or layout flow."""

    def __init__(self, app: QApplication, language: str = "en") -> None:
        super().__init__(app)
        self._app_ref = weakref.ref(app)
        self._language = "fa" if language == "fa" else "en"
        self._translating = False
        self._tracked: weakref.WeakSet[QObject] = weakref.WeakSet()
        self._original_font = QFont(app.font())
        app.installEventFilter(self)
        self._apply_application_preferences()

    @property
    def language(self) -> str:
        return self._language

    def _apply_application_preferences(self) -> None:
        app = self._app_ref()
        if app is None:
            return
        # Persian is a text-only localization. Keep the application and all
        # inherited widgets left-to-right so navigation and control placement
        # remain identical to the English interface.
        app.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        if self._language == "fa":
            font = QFont(self._original_font)
            try:
                font.setFamilies(["Noto Sans Arabic", "Segoe UI", "Arial", "sans-serif"])
            except AttributeError:
                font.setFamily("Segoe UI")
            app.setFont(font)
        else:
            app.setFont(self._original_font)

    @staticmethod
    def _read(obj: Any, getter: str) -> str:
        try:
            return str(getattr(obj, getter)())
        except (AttributeError, RuntimeError, TypeError):
            return ""

    @staticmethod
    def _write(obj: Any, setter: str, value: str) -> None:
        try:
            getattr(obj, setter)(value)
        except (AttributeError, RuntimeError, TypeError):
            pass

    def _translate_property(self, obj: QObject, getter: str, setter: str) -> None:
        current = self._read(obj, getter)
        if not current:
            return
        source = _get_source(obj, getter, current)
        translated = translate_text(source, self._language)
        self._write(obj, setter, translated)
        setattr(obj, f"_torproxy_i18n_rendered_{getter}", translated)

    def _translate_sequence(self, obj: QObject, getter: str, setter: str, count: int) -> None:
        try:
            current = [str(getattr(obj, getter)(i)) for i in range(count)]
        except (AttributeError, RuntimeError, TypeError, IndexError):
            return
        source_name = f"_torproxy_i18n_source_{getter}"
        rendered_name = f"_torproxy_i18n_rendered_{getter}"
        source = getattr(obj, source_name, None)
        rendered = getattr(obj, rendered_name, None)
        if source is None or current != rendered:
            source = current
            setattr(obj, source_name, source)
        for index, value in enumerate(source):
            translated = translate_text(value, self._language)
            if index < len(current) and current[index] != translated:
                try:
                    getattr(obj, setter)(index, translated)
                except (AttributeError, RuntimeError, TypeError, IndexError):
                    break
        setattr(obj, rendered_name, [translate_text(value, self._language) for value in source])

    def _translate_object(self, obj: QObject) -> None:
        if self._translating:
            return
        self._translating = True
        try:
            if isinstance(obj, QAction):
                self._translate_property(obj, "text", "setText")
                self._translate_property(obj, "toolTip", "setToolTip")
                self._translate_property(obj, "statusTip", "setStatusTip")
                return

            if not isinstance(obj, QWidget):
                return

            self._tracked.add(obj)
            if obj.isWindow():
                self._translate_property(obj, "windowTitle", "setWindowTitle")
        except RuntimeError:
            return
        finally:
            self._translating = False

        self._translating = True
        try:
            if isinstance(obj, QLabel):
                self._translate_property(obj, "text", "setText")
            elif isinstance(obj, QAbstractButton):
                self._translate_property(obj, "text", "setText")
            elif isinstance(obj, QGroupBox):
                self._translate_property(obj, "title", "setTitle")
            elif isinstance(obj, QLineEdit):
                self._translate_property(obj, "placeholderText", "setPlaceholderText")
            elif isinstance(obj, (QTextEdit, QPlainTextEdit)):
                self._translate_property(obj, "placeholderText", "setPlaceholderText")

            self._translate_property(obj, "toolTip", "setToolTip")
            self._translate_property(obj, "statusTip", "setStatusTip")
            self._translate_property(obj, "whatsThis", "setWhatsThis")

            if isinstance(obj, QComboBox):
                self._translate_sequence(obj, "itemText", "setItemText", obj.count())
            if isinstance(obj, QTabWidget):
                self._translate_sequence(obj, "tabText", "setTabText", obj.count())
            if isinstance(obj, QListWidget):
                for index in range(obj.count()):
                    item = obj.item(index)
                    if item is None:
                        continue
                    current = item.text()
                    source = getattr(item, "_torproxy_i18n_source", None)
                    rendered = getattr(item, "_torproxy_i18n_rendered", None)
                    if source is None or current != rendered:
                        source = current
                        setattr(item, "_torproxy_i18n_source", source)
                    translated = translate_text(source, self._language)
                    item.setText(translated)
                    setattr(item, "_torproxy_i18n_rendered", translated)
            if isinstance(obj, QTreeWidget):
                self._translate_tree_items(obj)
        except RuntimeError:
            pass
        finally:
            self._translating = False

    def _translate_tree_items(self, tree: QTreeWidget) -> None:
        def visit(item):
            for column in range(tree.columnCount()):
                current = item.text(column)
                source = item.data(column, Qt.ItemDataRole.UserRole + 733)
                rendered = item.data(column, Qt.ItemDataRole.UserRole + 734)
                if source is None or current != rendered:
                    source = current
                    item.setData(column, Qt.ItemDataRole.UserRole + 733, source)
                translated = translate_text(source, self._language)
                if current != translated:
                    item.setText(column, translated)
                item.setData(column, Qt.ItemDataRole.UserRole + 734, translated)
            for child_index in range(item.childCount()):
                visit(item.child(child_index))
        for index in range(tree.topLevelItemCount()):
            visit(tree.topLevelItem(index))

    def translate_tree(self, root: QObject) -> None:
        pending = [root]
        seen: set[int] = set()
        while pending:
            obj = pending.pop()
            if obj is None or id(obj) in seen:
                continue
            seen.add(id(obj))
            try:
                self._translate_object(obj)
                pending.extend(obj.children())
            except RuntimeError:
                continue

    def set_language(self, language: str) -> None:
        selected = "fa" if str(language).lower() in {"fa", "fa-ir", "persian"} else "en"
        if selected == self._language:
            self.retranslate_all()
            return
        self._language = selected
        self._apply_application_preferences()
        self.retranslate_all()

    def retranslate_all(self) -> None:
        app = self._app_ref()
        if app is None:
            return
        for widget in app.topLevelWidgets():
            self.translate_tree(widget)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if self._translating:
            return False
        event_type = event.type()
        if event_type == QEvent.Type.ChildAdded:
            child = event.child()
            if child is not None:
                QTimer.singleShot(0, lambda target=child: self.translate_tree(target))
        elif event_type in (QEvent.Type.Show, QEvent.Type.Polish):
            self.translate_tree(watched)
        elif event_type == QEvent.Type.Paint and self._language == "fa":
            # A text-bearing widget may receive new status text after it has
            # been shown (for example after an async Tor operation). Reconcile
            # only that widget immediately before it is painted; no polling
            # timer or repeated full-window traversal is required.
            if isinstance(watched, (QLabel, QAbstractButton, QGroupBox, QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QTabWidget, QListWidget, QTreeWidget)):
                self._translate_object(watched)
        return False


def install_language_support(app: QApplication, language: str = "en") -> LanguageManager:
    """Install one shared translator for the application, returning its manager."""
    manager = getattr(app, "_torproxy_language_manager", None)
    if manager is None:
        manager = LanguageManager(app, language)
        setattr(app, "_torproxy_language_manager", manager)
    else:
        manager.set_language(language)
    return manager


def get_language_manager(app: QApplication | None = None) -> LanguageManager | None:
    app = app or QApplication.instance()
    if app is None:
        return None
    manager = getattr(app, "_torproxy_language_manager", None)
    return manager if isinstance(manager, LanguageManager) else None


def set_application_language(language: str) -> None:
    app = QApplication.instance()
    if app is None:
        return
    manager = get_language_manager(app) or install_language_support(app, language)
    manager.set_language(language)
