"""Lightweight runtime localization for TorProxy's Qt interface.

The application keeps its existing left-to-right layout in every language.
Only user-facing text is translated; protocol values, paths, ports, and logs
remain unchanged.
"""
from __future__ import annotations

import weakref
from typing import Any

from PySide6.QtCore import QEvent, QObject, QTimer, Qt
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QComboBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QMenuBar,
    QPlainTextEdit,
    QProgressBar,
    QSystemTrayIcon,
    QTabWidget,
    QTableWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QWidget,
)


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
    "This section will prepare automatically after Home is ready.": "این بخش پس از آماده‌شدن صفحهٔ خانه به‌صورت خودکار آماده می‌شود.",
    "Hide window": "پنهان‌کردن پنجره",
    "SYSTEM PROXY": "پراکسی سیستم",
    "Blocked Hosts": "میزبان‌های مسدودشده",
    "Excluded Hosts": "میزبان‌های مستثناشده",
    "Manage Tor bundles and the system tunnel": "مدیریت بسته‌های Tor و تونل سیستم",
    "UPDATES": "به‌روزرسانی‌ها",
    "Download and manage Tor Expert Bundles": "دریافت و مدیریت بسته‌های تخصصی Tor",
    "Install and manage the system tunnel engine": "نصب و مدیریت موتور تونل سیستم",
    "Exit TorProxy": "خروج از تورپراکسی",
    "Exit TorProxy (Ctrl+Q)": "خروج از تورپراکسی (Ctrl+Q)",
    "● Checking Tor state…": "● در حال بررسی وضعیت Tor…",
    "Open the Home Event Log when Tor reports a failure.": "هنگام گزارش خطا از سوی Tor، گزارش رویدادهای خانه را باز کنید.",
    "Notifications": "اعلان‌ها",
    "Clear all": "پاک‌کردن همه",
    "Toggle light/dark appearance": "تغییر پوستهٔ روشن/تیره",
    "New TorProxy activity will appear here.": "فعالیت‌های جدید تورپراکسی در اینجا نمایش داده می‌شوند.",
    "No new notifications": "اعلان جدیدی وجود ندارد",
    "● Initializing": "● در حال راه‌اندازی",
    "Open live proxy traffic statistics and charts": "نمایش زندهٔ آمار ترافیک پراکسی و نمودارها",
    "BOOTSTRAP": "راه‌اندازی اولیه",
    "Tor bootstrap progress": "پیشرفت راه‌اندازی Tor",
    "System tunnel is not installed · Manage it in Updates": "تونل سیستم نصب نشده است · آن را از بخش به‌روزرسانی‌ها مدیریت کنید",
    "Manage": "مدیریت",
    "TOR EXIT IP": "IP خروجی Tor",
    "Not checked yet": "هنوز بررسی نشده است",
    "Request a new Tor circuit identity.": "درخواست هویت جدید برای مدار Tor.",
    "Event Log": "گزارش رویدادها",
    "Show or hide the live Tor and proxy event log.": "نمایش یا پنهان‌کردن گزارش زندهٔ رویدادهای Tor و پراکسی.",
    "Check Exit IP": "بررسی IP خروجی",
    "Check the public IP observed through the Tor HTTP proxy.": "بررسی IP عمومی مشاهده‌شده از طریق پراکسی HTTP تور.",
    "ADDRESS": "نشانی",
    "Copy IP address": "کپی نشانی IP",
    "PORT": "درگاه",
    "Copy port": "کپی درگاه",
    "Copy the complete host:port endpoint": "کپی کامل نشانی میزبان و درگاه",
    "Open Browser": "بازکردن مرورگر",
    "Unavailable · Tor is not ready": "در دسترس نیست · Tor آماده نیست",
    "Unavailable · HTTP proxy is disabled": "در دسترس نیست · پراکسی HTTP غیرفعال است",
    "Checking via Tor proxy…": "در حال بررسی از طریق پراکسی Tor…",
    "Unverified": "تأییدنشده",
    "Could not display result · See Event Log": "نمایش نتیجه ممکن نبود · گزارش رویدادها را ببینید",
    "Check failed · no direct fallback used": "بررسی ناموفق بود · از اتصال مستقیم جایگزین استفاده نشد",
    "System proxy setting": "تنظیم پراکسی سیستم",
    "Will apply the system proxy automatically after Tor connects.": "پس از اتصال Tor، پراکسی سیستم به‌صورت خودکار اعمال می‌شود.",
    "TorProxy will not change the system proxy automatically.": "تورپراکسی پراکسی سیستم را به‌صورت خودکار تغییر نمی‌دهد.",
    "Clearing the system proxy…": "در حال پاک‌کردن تنظیم پراکسی سیستم…",
    "System proxy cleared; direct mode is active.": "تنظیم پراکسی سیستم پاک شد؛ حالت اتصال مستقیم فعال است.",
    "Could not clear the system proxy. Check the event log.": "پاک‌کردن پراکسی سیستم ممکن نبود. گزارش رویدادها را بررسی کنید.",
    "Connection preflight": "بررسی‌های پیش از اتصال",
    "Start failed: {e}": "شروع ناموفق بود: {e}",
    "System proxy active at 127.0.0.1:{self.proxy.port}": "پراکسی سیستم در نشانی 127.0.0.1:{self.proxy.port} فعال است",
    "Proxy Error": "خطای پراکسی",
    "Failed to set proxy: {err}": "تنظیم پراکسی ناموفق بود: {err}",
    "System proxy: original settings restored": "پراکسی سیستم: تنظیمات اولیه بازیابی شدند",
    "Failed to clear proxy: {err}": "پاک‌کردن پراکسی ناموفق بود: {err}",
    "Use the hostname in url= (default; no override)": "استفاده از نام میزبان در url= (پیش‌فرض؛ بدون بازنویسی)",
    "Use Tor bridges": "استفاده از پل‌های Tor",
    "Saved bridge cards": "پل‌های ذخیره‌شده",
    "Import bridges from QR code": "درون‌ریزی پل‌ها از کد QR",
    "Copy full bridge record": "کپی رکورد کامل پل",
    "Remove this bridge": "حذف این پل",
    "Copied one complete bridge record to the clipboard.": "یک رکورد کامل پل در حافظهٔ موقت کپی شد.",
    "Local HTTP proxy": "پراکسی HTTP محلی",
    "Enable local HTTP proxy": "فعال‌سازی پراکسی HTTP محلی",
    "HTTP proxy status will appear here.": "وضعیت پراکسی HTTP در اینجا نمایش داده می‌شود.",
    "Test HTTP CONNECT": "آزمایش HTTP CONNECT",
    "Listener ports": "درگاه‌های شنونده",
    "Port 1–65535": "درگاه ۱ تا ۶۵۵۳۵",
    "Fixed": "ثابت",
    "Main Tor SOCKS Gateway": "درگاه SOCKS اصلی Tor",
    "SOCKS username": "نام کاربری SOCKS",
    "Generated when LAN access is enabled": "هنگام فعال‌سازی دسترسی شبکهٔ محلی ساخته می‌شود",
    "SOCKS password": "گذرواژهٔ SOCKS",
    "Stored outside config.json": "خارج از config.json ذخیره می‌شود",
    "Show": "نمایش",
    "Generate new credentials": "ساخت اطلاعات ورود جدید",
    "Save credentials": "ذخیرهٔ اطلاعات ورود",
    "Main SOCKS gateway is restricted to this device by default.": "درگاه SOCKS اصلی به‌طور پیش‌فرض فقط برای همین دستگاه قابل دسترسی است.",
    "AUTO": "خودکار",
    "Main SOCKS gateway": "درگاه SOCKS اصلی",
    "Main SOCKS credentials": "اطلاعات ورود SOCKS اصلی",
    "HTTP listener change failed · ": "تغییر شنوندهٔ HTTP ناموفق بود · ",
    "HTTP proxy LAN access": "دسترسی شبکهٔ محلی به پراکسی HTTP",
    "Connect to Tor and start the HTTP proxy before running this test.": "پیش از اجرای این آزمایش، به Tor متصل شوید و پراکسی HTTP را راه‌اندازی کنید.",
    "Testing…": "در حال آزمایش…",
    "Verified · HTTP CONNECT reached an external HTTPS endpoint through Tor.": "تأیید شد · درخواست HTTP CONNECT از طریق Tor به یک مقصد HTTPS خارجی رسید.",
    "Test incomplete · no Tor exit response was verified.": "آزمایش کامل نشد · پاسخ خروجی Tor تأیید نشد.",
    "HTTP CONNECT test failed · ": "آزمایش HTTP CONNECT ناموفق بود · ",
    "Optional publisher signature verification": "بررسی اختیاری امضای ناشر",
    "OpenPGP verification is OFF by default. Enable it only when you explicitly want the additional publisher-signature check.": "بررسی OpenPGP به‌صورت پیش‌فرض خاموش است. تنها در صورت نیاز به بررسی اضافهٔ امضای ناشر آن را فعال کنید.",
    "System tunnel recovery": "بازیابی تونل سیستم",
    "Emergency sing-box cleanup": "پاک‌سازی اضطراری sing-box",
    "Check / clean up": "بررسی / پاک‌سازی",
    "The system tunnel manager is unavailable.": "مدیر تونل سیستم در دسترس نیست.",
    "Inspecting saved process identity and TUN state…": "در حال بررسی هویت فرایند ذخیره‌شده و وضعیت TUN…",
    "Cleanup could not be verified. See Event Log.": "تأیید پاک‌سازی ممکن نبود. گزارش رویدادها را ببینید.",
    "Bridge records could not be saved. Your previous settings were preserved.": "ذخیرهٔ رکوردهای پل ممکن نبود. تنظیمات قبلی شما حفظ شدند.",
    "No bridge addresses saved.": "هیچ نشانی پلی ذخیره نشده است.",
    "SNI setting could not be saved. The previous setting remains active.": "ذخیرهٔ تنظیم SNI ممکن نبود. تنظیم قبلی همچنان فعال است.",
    "System Tunnel · sing-box": "تونل سیستم · sing-box",
    "Install and manage the system-wide Tor tunnel engine.": "موتور تونل سراسری مبتنی بر Tor را نصب و مدیریت کنید.",
    "Official releases": "نسخه‌های رسمی",
    "Available releases": "نسخه‌های موجود",
    "Check latest": "بررسی آخرین نسخه",
    "Check GitHub for the latest stable sing-box release.": "برای یافتن آخرین نسخهٔ پایدار sing-box، گیت‌هاب را بررسی کنید.",
    "Checking engine installation…": "در حال بررسی نصب موتور…",
    "WHAT THE TUNNEL DOES": "عملکرد تونل",
    "Install selected version": "نصب نسخهٔ انتخاب‌شده",
    "Start system tunnel": "شروع تونل سیستم",
    "Test traffic": "آزمایش ترافیک",
    "Select a verified version to install or manage the tunnel.": "برای نصب یا مدیریت تونل، یک نسخهٔ تأییدشده انتخاب کنید.",
    "Tunnel state is unavailable · inspect the event log": "وضعیت تونل در دسترس نیست · گزارش رویدادها را بررسی کنید",
    "Status unavailable": "وضعیت در دسترس نیست",
    "Verifying the local sing-box archive and engine files…": "در حال تأیید بایگانی محلی sing-box و فایل‌های موتور…",
    "Not installed · Download the selected engine to enable the tunnel.": "نصب نشده است · برای فعال‌کردن تونل، موتور انتخاب‌شده را دریافت کنید.",
    "Stop / reconcile tunnel": "توقف / همگام‌سازی وضعیت تونل",
    "Unsupported platform": "سیستم‌عامل پشتیبانی نمی‌شود",
    "Install engine first": "ابتدا موتور را نصب کنید",
    "TorProxy is busy": "تورپراکسی مشغول است",
    "Waiting for Tor": "در انتظار Tor",
    "Could not verify the local sing-box installation: {error}": "تأیید نصب محلی sing-box ممکن نبود: {error}",
    "Tunnel engine": "موتور تونل",
    "Wait for the current Tor or tunnel recovery operation to finish.": "منتظر بمانید تا عملیات فعلی Tor یا بازیابی تونل تمام شود.",
    "Tor executable unavailable": "فایل اجرایی Tor در دسترس نیست",
    "Choose a verified Tor Expert Bundle first.": "ابتدا یک بستهٔ تخصصی تأییدشدهٔ Tor انتخاب کنید.",
    "{operation.title()} failed: {detail}": "عملیات {operation} ناموفق بود: {detail}",
    "System tunnel": "تونل سیستم",
    "Checking the official sing-box stable release…": "در حال بررسی آخرین نسخهٔ پایدار رسمی sing-box…",
    "The upstream release response was not valid.": "پاسخ نسخه از منبع اصلی معتبر نبود.",
    "Tor Bundles & Updates": "بسته‌ها و به‌روزرسانی‌های Tor",
    "Official source": "منبع رسمی",
    "Copy the official Tor release index URL": "کپی نشانی فهرست رسمی انتشار Tor",
    "Search versions…": "جست‌وجوی نسخه‌ها…",
    "Include alpha prereleases": "نمایش نسخه‌های پیش‌انتشار آلفا",
    "Refresh to retrieve the official Tor release directories.": "برای دریافت فهرست پوشه‌های انتشار رسمی Tor، تازه‌سازی کنید.",
    "Refresh to retrieve official Tor release directories. Stable releases are sorted before alpha prereleases.": "برای دریافت فهرست پوشه‌های انتشار رسمی Tor، تازه‌سازی کنید. نسخه‌های پایدار پیش از نسخه‌های آلفا مرتب می‌شوند.",
    "Installed bundles": "بسته‌های نصب‌شده",
    "Import .tar.gz": "درون‌ریزی .tar.gz",
    "Rescan": "اسکن دوباره",
    "Use as default": "استفاده به‌عنوان پیش‌فرض",
    "Ready. Select a release to check whether a signed bundle is available.": "آماده است. یک نسخه انتخاب کنید تا وجود بستهٔ امضاشده بررسی شود.",
    "Get GnuPG": "دریافت GnuPG",
    "Open the official GnuPG download page.": "بازکردن صفحهٔ رسمی دریافت GnuPG.",
    "Transfer details, speed and estimated time remain available here during an operation.": "هنگام انجام عملیات، جزئیات انتقال، سرعت و زمان تخمینی در اینجا نمایش داده می‌شوند.",
    "Copied the official Tor release index URL to the clipboard.": "نشانی فهرست رسمی انتشار Tor در حافظهٔ موقت کپی شد.",
    "CHECKING LOCAL BUNDLES": "در حال بررسی بسته‌های محلی",
    "No compatible bundle installed": "هیچ بستهٔ سازگاری نصب نشده است",
    "Default: not configured": "پیش‌فرض: پیکربندی نشده",
    "Checking installed bundle metadata and archive digests…": "در حال بررسی فرادادهٔ بسته‌های نصب‌شده و چکیدهٔ بایگانی…",
    "Bundle inspection failed": "بررسی بسته ناموفق بود",
    "Could not verify local bundle metadata. Rescan or inspect the application log.": "تأیید فرادادهٔ بستهٔ محلی ممکن نبود. دوباره اسکن کنید یا گزارش برنامه را بررسی کنید.",
    "Select a bundle": "انتخاب بسته",
    "Select an installed bundle first.": "ابتدا یک بستهٔ نصب‌شده انتخاب کنید.",
    "Bundle unavailable": "بسته در دسترس نیست",
    "This bundle is not in the latest compatible scan. Rescan the list.": "این بسته در آخرین اسکن سازگاری وجود ندارد. فهرست را دوباره اسکن کنید.",
    "Default bundle saved. Restart Tor if a process is already running.": "بستهٔ پیش‌فرض ذخیره شد. اگر Tor در حال اجراست، آن را دوباره راه‌اندازی کنید.",
    "Could not select bundle": "انتخاب بسته ممکن نبود",
    "Select an installed bundle to delete.": "برای حذف، یک بستهٔ نصب‌شده انتخاب کنید.",
    "Select a local verified bundle to delete.": "برای حذف، یک بستهٔ محلی و تأییدشده انتخاب کنید.",
    "Bundle deleted.": "بسته حذف شد.",
    "Could not delete bundle": "حذف بسته ممکن نبود",
    "Invalid Tor bundle": "بستهٔ Tor نامعتبر است",
    "Importing local Tor bundle…": "در حال درون‌ریزی بستهٔ محلی Tor…",
    "The local bundle was not installed.": "بستهٔ محلی نصب نشد.",
    "Local Tor bundle import failed": "درون‌ریزی بستهٔ محلی Tor ناموفق بود",
    "Contacting the official Tor distribution index…": "در حال ارتباط با فهرست رسمی توزیع Tor…",
    "Discovering release directories. Artifact checks happen only when a release is selected.": "در حال یافتن پوشه‌های انتشار. بررسی فایل‌ها فقط پس از انتخاب یک نسخه انجام می‌شود.",
    "Release directory found. Select to check a compatible Expert Bundle using the current Advanced signature-verification setting.": "پوشهٔ انتشار پیدا شد. آن را انتخاب کنید تا سازگاری بستهٔ تخصصی با تنظیم فعلی بررسی امضای پیشرفته بررسی شود.",
    "Choose a release to check compatible artifact availability and the selected trust method.": "برای بررسی موجودبودن فایل سازگار و روش اعتماد انتخاب‌شده، یک نسخه انتخاب کنید.",
    "The official release list could not be retrieved.": "دریافت فهرست رسمی انتشار ممکن نبود.",
    "Tor release discovery failed": "یافتن نسخه‌های Tor ناموفق بود",
    "A release directory alone does not mean a compatible archive is available.": "وجود پوشهٔ انتشار به‌تنهایی به معنای موجودبودن بایگانی سازگار نیست.",
    "No compatible bundle": "بستهٔ سازگاری وجود ندارد",
    "Download cancelled before starting.": "بارگیری پیش از شروع لغو شد.",
    "Preparing Tor bundle download…": "در حال آماده‌سازی بارگیری بستهٔ Tor…",
    "Cancellation requested; waiting for the current network read to return.": "درخواست لغو ثبت شد؛ در انتظار پایان خواندن فعلی شبکه.",
    "The partial archive will not be installed or marked as verified.": "بایگانی ناقص نصب یا به‌عنوان تأییدشده علامت‌گذاری نمی‌شود.",
    "Operation cancelled. Temporary download files were removed; no bundle was installed.": "عملیات لغو شد. فایل‌های موقت بارگیری حذف شدند و هیچ بسته‌ای نصب نشد.",
    "Download or installation failed. The bundle was not reported as installed.": "بارگیری یا نصب ناموفق بود. بسته به‌عنوان نصب‌شده ثبت نشد.",
    "Tor bundle operation failed": "عملیات بستهٔ Tor ناموفق بود",
    "Back to Home": "بازگشت به خانه",
    "Traffic statistics": "آمار ترافیک",
    "Live throughput · persistent traffic history across restarts": "گذر‌دهی زنده · تاریخچهٔ پایدار ترافیک میان راه‌اندازی‌های مجدد",
    "TRAFFIC HISTORY": "تاریخچهٔ ترافیک",
    "PROXY STOPPED": "پراکسی متوقف است",
    "lifetime": "کل دوره",
    "session": "نشست",
    "upload": "بارگذاری",
    "download": "بارگیری",
    "current": "فعلی",
    "peak": "اوج",
    "Keyboard shortcuts": "میانبرهای صفحه‌کلید",
    "F1  ·  SHORTCUTS": "F1 · میانبرها",
    "Change": "تغییر",
    "Copy the complete message to the clipboard": "کپی کامل پیام در حافظهٔ موقت",
    "Copy text": "کپی متن",
    "Don't ask me again": "دوباره سؤال نکن",
    "CURRENT  ·  {current_shortcut}": "فعلی · {current_shortcut}",
    "●  LISTENING FOR INPUT": "● در انتظار ورودی",
    "Press a modifier and a key…": "یک کلید کمکی و سپس یک کلید را فشار دهید…",
    "✓  COMBINATION CAPTURED": "✓ ترکیب کلید ثبت شد",
    "●  KEYS HELD": "● کلیدها نگه داشته شده‌اند",
    "Modifier detected. Keep it held and press the main key.": "کلید کمکی تشخیص داده شد. آن را نگه دارید و کلید اصلی را فشار دهید.",
    "●  TRY ANOTHER KEY": "● کلید دیگری را امتحان کنید",
    "●  INPUT PREVIEW": "● پیش‌نمایش ورودی",
    "●  COMBINATION HELD": "● ترکیب کلید نگه داشته شده است",
    "Custom Tor configuration": "پیکربندی Tor سفارشی",
    "Settings are saved automatically when changed.": "با هر تغییر، تنظیمات به‌صورت خودکار ذخیره می‌شوند.",
    "Primary connection health": "سلامت اتصال اصلی",
    "Primary Tor pool is not running.": "مجموعهٔ Tor اصلی در حال اجرا نیست.",
    "Manage custom Tor services": "مدیریت سرویس‌های Tor سفارشی",
    "Create profiles, assign listener ports, start or stop Tor processes and inspect live logs from the Custom Tor page.": "از صفحهٔ Tor سفارشی، پروفایل بسازید، درگاه شنونده اختصاص دهید، فرایندهای Tor را شروع یا متوقف کنید و گزارش زنده را ببینید.",
    "Open Custom Tor": "بازکردن Tor سفارشی",
    "e.g. personal or work": "برای نمونه: شخصی یا کاری",
    "A readable name": "یک نام خوانا",
    "Use Main Tor's default bundle": "استفاده از بستهٔ پیش‌فرض Tor اصلی",
    "0 disables DNSPort": "مقدار ۰، DNSPort را غیرفعال می‌کند",
    "Enable bridges for this profile": "فعال‌سازی پل‌ها برای این پروفایل",
    "Browse…": "مرور…",
    "Advanced network options": "گزینه‌های پیشرفتهٔ شبکه",
    "Network options": "گزینه‌های شبکه",
    "Direct · no upstream proxy": "مستقیم · بدون پراکسی بالادستی",
    "127.0.0.1 or proxy.example.net": "127.0.0.1 یا proxy.example.net",
    "Allow IPv4": "اجازهٔ IPv4",
    "Allow IPv6": "اجازهٔ IPv6",
    "Independent Tor profiles": "پروفایل‌های مستقل Tor",
    "Primary connection redundancy": "افزونگی اتصال اصلی",
    "Main Tor instances": "نمونه‌های Tor اصلی",
    "Number of Tor workers backing the primary connection. Allowed range: 1–4.": "تعداد فرایندهای Tor پشتیبان اتصال اصلی. بازهٔ مجاز: ۱ تا ۴.",
    "Parallel bridge checks": "بررسی موازی پل‌ها",
    "Concurrent bridge probes": "آزمایش‌های هم‌زمان پل",
    "Maximum parallel bridge checks. Allowed range: 1–8.": "حداکثر تعداد بررسی موازی پل‌ها. بازهٔ مجاز: ۱ تا ۸.",
    "Service operations": "عملیات سرویس",
    "Concurrent service operations": "عملیات هم‌زمان سرویس‌ها",
    "Create service": "ایجاد سرویس",
    "Create a new isolated Custom Tor profile.": "ساخت پروفایل مستقل جدید برای Tor سفارشی.",
    "Start all": "شروع همه",
    "Stop all": "توقف همه",
    "Service concurrency": "هم‌زمانی سرویس‌ها",
    "Proxy credentials unavailable": "اطلاعات ورود پراکسی در دسترس نیست",
    "Duplicate profile": "پروفایل تکراری",
    "Cannot edit active service": "سرویس فعال قابل ویرایش نیست",
    "Tor profile could not be saved": "ذخیرهٔ پروفایل Tor ممکن نبود",
    "Cannot remove active service": "سرویس فعال قابل حذف نیست",
    "Profile could not be removed": "حذف پروفایل ممکن نبود",
    "Tor service operation failed": "عملیات سرویس Tor ناموفق بود",
    "Tor service stop": "توقف سرویس Tor",
    "Tor service force-stop failed": "توقف اجباری سرویس Tor ناموفق بود",
    "Tor service stop failed": "توقف سرویس Tor ناموفق بود",
    "Create an isolated Tor profile before using Start all.": "پیش از استفاده از «شروع همه»، یک پروفایل مستقل Tor بسازید.",
    "Restoring saved profiles before starting them…": "پیش از شروع، پروفایل‌های ذخیره‌شده در حال بازیابی هستند…",
    "No isolated Tor profiles yet. Add one to create a separate Tor instance.": "هنوز پروفایل مستقلی برای Tor وجود ندارد. برای ساخت یک نمونهٔ جداگانه، پروفایلی اضافه کنید.",
    "TOR VERIFIED": "اتصال Tor تأیید شد",
    "SOCKS REACHABLE · UNVERIFIED": "SOCKS در دسترس است · تأییدنشده",
    "NO TOR EGRESS": "خروجی Tor وجود ندارد",
    "DEGRADED": "دارای اختلال",
    "CHECKING NETWORK": "در حال بررسی شبکه",
    "PROCESS EXITED · STOP TO RECONCILE": "فرایند خارج شده است · برای همگام‌سازی وضعیت، توقف را بزنید",
    "PREVIOUS SESSION PROCESS · STOP TO RECONCILE": "فرایند نشست قبلی · برای همگام‌سازی وضعیت، توقف را بزنید",
    "PROCESS IDENTITY UNVERIFIED · MANUAL INSPECTION": "هویت فرایند تأیید نشده است · بررسی دستی لازم است",
    "Copy SOCKS endpoint": "کپی نشانی SOCKS",
    "Copy the loopback SOCKS endpoint for this isolated Tor profile.": "کپی نشانی محلی SOCKS برای این پروفایل مستقل Tor.",
    "Stop this service, including cancelling an ongoing startup.": "این سرویس را متوقف کنید؛ فرایند شروع در حال اجرا نیز لغو می‌شود.",
    "Force stop": "توقف اجباری",
    "Immediately terminate the managed Tor process. Use if normal Stop does not complete.": "فرایند مدیریت‌شدهٔ Tor را فوراً خاتمه می‌دهد. اگر توقف عادی کامل نشد از آن استفاده کنید.",
    "View this service's live Tor log, including startup output.": "گزارش زندهٔ Tor این سرویس، شامل خروجی شروع، را مشاهده کنید.",
    "My local website": "وب‌سایت محلی من",
    "Persistent · keep the same Onion address": "پایدار · حفظ همان نشانی Onion",
    "Temporary · remove when TorProxy exits": "موقت · هنگام خروج از تورپراکسی حذف شود",
    "Public · anyone with the address": "عمومی · برای هرکسی که نشانی را دارد",
    "Private · requires a client authorization key": "خصوصی · نیازمند کلید مجوزدهی کاربر",
    "Start this service automatically when Developer Tor starts": "با شروع Tor توسعه‌دهنده، این سرویس نیز خودکار شروع شود",
    "Service name required": "نام سرویس الزامی است",
    "Enter a name for this Onion Service.": "برای این سرویس Onion نامی وارد کنید.",
    "Local address required": "نشانی محلی الزامی است",
    "Enter 127.0.0.1 or ::1 as the local target.": "برای مقصد محلی، 127.0.0.1 یا ::1 را وارد کنید.",
    "Invalid port mappings": "نگاشت درگاه‌ها نامعتبر است",
    "Connection and bridges": "اتصال و پل‌ها",
    "Direct connection": "اتصال مستقیم",
    "Use custom Developer Tor bridges": "استفاده از پل‌های سفارشی Tor توسعه‌دهنده",
    "Reuse the saved Main Tor bridge list": "استفادهٔ مجدد از فهرست پل‌های ذخیره‌شدهٔ Tor اصلی",
    "Use the hostname from each WebTunnel url= field": "استفاده از نام میزبان فیلد url= هر WebTunnel",
    "Advanced network": "شبکهٔ پیشرفته",
    "Upstream proxy (optional)": "پراکسی بالادستی (اختیاری)",
    "No upstream proxy": "بدون پراکسی بالادستی",
    "Proxy host required": "میزبان پراکسی الزامی است",
    "Enter the upstream proxy host.": "میزبان پراکسی بالادستی را وارد کنید.",
    "Proxy authentication": "احراز هویت پراکسی",
    "Enter both username and password, or leave both empty.": "هر دو نام کاربری و گذرواژه را وارد کنید یا هر دو را خالی بگذارید.",
    "HTTP CONNECT proxy credentials cannot contain a colon.": "اطلاعات ورود پراکسی HTTP CONNECT نمی‌تواند شامل دونقطه باشد.",
    "DEVELOPER TOR RUNTIME": "محیط اجرای Tor توسعه‌دهنده",
    "STOPPED": "متوقف",
    "Developer Tor is stopped.": "Tor توسعه‌دهنده متوقف است.",
    "Start runtime": "شروع محیط اجرا",
    "Stop runtime": "توقف محیط اجرا",
    "Tor runtime logs": "گزارش‌های محیط اجرای Tor",
    "Bytes received from Onion visitors by the hosted applications.": "بایت‌های دریافت‌شده از بازدیدکنندگان Onion توسط برنامه‌های میزبانی‌شده.",
    "Bytes sent from the hosted applications back to Onion visitors.": "بایت‌های ارسال‌شده از برنامه‌های میزبانی‌شده به بازدیدکنندگان Onion.",
    "Detected plaintext HTTP sessions, one first request line per TCP connection.": "نشست‌های HTTP متنی شناسایی‌شده؛ یک خط نخست درخواست برای هر اتصال TCP.",
    "Onion Services": "سرویس‌های Onion",
    "Filter services…": "فیلتر سرویس‌ها…",
    "All states": "همهٔ وضعیت‌ها",
    "Running": "در حال اجرا",
    "Stopped": "متوقف",
    "Errors": "خطاها",
    "Create Onion Service": "ایجاد سرویس Onion",
    "Developer Tor operation cancelled.": "عملیات Tor توسعه‌دهنده لغو شد.",
    "Starting the independent Developer Tor process…": "در حال شروع فرایند مستقل Tor توسعه‌دهنده…",
    "Developer Tor is ready.": "Tor توسعه‌دهنده آماده است.",
    "Stopping Onion Services and Developer Tor…": "در حال توقف سرویس‌های Onion و Tor توسعه‌دهنده…",
    "Developer Tor has stopped.": "Tor توسعه‌دهنده متوقف شد.",
    "Restarting Developer Tor…": "در حال راه‌اندازی مجدد Tor توسعه‌دهنده…",
    "Developer Tor restarted.": "Tor توسعه‌دهنده دوباره راه‌اندازی شد.",
    "Developer Tor settings unavailable": "تنظیمات Tor توسعه‌دهنده در دسترس نیست",
    "Developer Tor settings saved. They will apply on the next start.": "تنظیمات Tor توسعه‌دهنده ذخیره شد و از شروع بعدی اعمال می‌شوند.",
    "Developer Tor settings saved. Restart the runtime to apply them.": "تنظیمات Tor توسعه‌دهنده ذخیره شد. برای اعمال آن‌ها محیط اجرا را دوباره راه‌اندازی کنید.",
    "Could not save Developer Tor settings": "ذخیرهٔ تنظیمات Tor توسعه‌دهنده ممکن نبود",
    "Onion Service profile saved.": "پروفایل سرویس Onion ذخیره شد.",
    "Could not create Onion Service": "ایجاد سرویس Onion ممکن نبود",
    "Stop before editing": "پیش از ویرایش متوقف کنید",
    "Stop this Onion Service before changing its settings.": "پیش از تغییر تنظیمات این سرویس Onion، آن را متوقف کنید.",
    "Onion Service settings saved.": "تنظیمات سرویس Onion ذخیره شد.",
    "Could not update Onion Service": "به‌روزرسانی سرویس Onion ممکن نبود",
    "Checking the local web server and creating the Onion Service…": "در حال بررسی وب‌سرور محلی و ایجاد سرویس Onion…",
    "Rotating the Onion Service identity…": "در حال تغییر هویت سرویس Onion…",
    "Rules that prevent selected hosts from using the TorProxy route.": "قواعدی که مانع استفادهٔ میزبان‌های انتخاب‌شده از مسیر تورپراکسی می‌شوند.",
    "Search blocked hosts…": "جست‌وجوی میزبان‌های مسدودشده…",
    "No blocked hosts yet. Add a hostname below to create your first rule.": "هنوز میزبان مسدودشده‌ای وجود ندارد. برای ساخت نخستین قاعده، نام میزبان را در پایین وارد کنید.",
    "Add a host rule": "افزودن قاعدهٔ میزبان",
    "Examples: *.ir, *.x.com, *-api.example.com; =host matches exactly.": "نمونه‌ها: ‎*.ir، ‎*.x.com، ‎*-api.example.com؛ ‎=host فقط همان میزبان را تطبیق می‌دهد.",
    "*.example.com or *-api.example.com": "‎*.example.com یا ‎*-api.example.com",
    "Add rule": "افزودن قاعده",
    "Changes are saved to the current host-rule list.": "تغییرات در فهرست فعلی قواعد میزبان ذخیره می‌شوند.",
    "No rules match this search. Try another hostname.": "هیچ قاعده‌ای با این جست‌وجو مطابقت ندارد. نام میزبان دیگری را امتحان کنید.",
    "Could not remove rule": "حذف قاعده ممکن نبود",
    "Enter a hostname first.": "ابتدا نام میزبان را وارد کنید.",
    "Invalid host rule": "قاعدهٔ میزبان نامعتبر است",
    "Rules for destinations that should bypass the TorProxy routing policy.": "قواعد مقصدهایی که باید از سیاست مسیریابی تورپراکسی عبور نکنند.",
    "Search excluded hosts…": "جست‌وجوی میزبان‌های مستثناشده…",
    "No excluded hosts yet. Add a hostname below to create your first rule.": "هنوز میزبان مستثناشده‌ای وجود ندارد. برای ساخت نخستین قاعده، نام میزبان را در پایین وارد کنید.",
    "Add an exclusion": "افزودن استثنا",
    "Direct bypass (outside Tor). Patterns: *.ir, *.x.com, *-api.example.com; =host is exact.": "عبور مستقیم (خارج از Tor). الگوها: ‎*.ir، ‎*.x.com، ‎*-api.example.com؛ ‎=host فقط میزبان دقیق است.",
    "Excluded rules connect directly outside Tor. host.com: host and subdomains; =host.com: exact; *.host.com: subdomains only; *-api.host.com: wildcard within one DNS label.": "قواعد مستثناشده خارج از Tor مستقیماً متصل می‌شوند. host.com: میزبان و زیردامنه‌ها؛ =host.com: فقط میزبان دقیق؛ *.host.com: فقط زیردامنه‌ها؛ *-api.host.com: الگو در یک بخش نام دامنه.",
    "Onion URL copied.": "نشانی Onion کپی شد.",
    "Direct mode does not configure Bridge records.": "حالت مستقیم، رکوردهای Bridge را پیکربندی نمی‌کند.",
    "Bridge list required": "فهرست پل الزامی است",
    "Add at least one complete Bridge record or choose another connection mode.": "حداقل یک رکورد کامل Bridge اضافه کنید یا حالت اتصال دیگری انتخاب کنید.",
    "Invalid WebTunnel SNI": "SNI مربوط به WebTunnel نامعتبر است",
    "Address family required": "نوع نشانی الزامی است",
    "Enable IPv4, IPv6, or both.": "IPv4، IPv6 یا هر دو را فعال کنید.",
    "The default browser must be configured to route .onion addresses through Tor.": "مرورگر پیش‌فرض باید برای مسیریابی نشانی‌های ‎.onion از طریق Tor پیکربندی شده باشد.",
    "Request logs": "گزارش درخواست‌ها",
    "Open request and traffic history for this Onion Service": "بازکردن تاریخچهٔ درخواست‌ها و ترافیک این سرویس Onion",
    "New address": "نشانی جدید",
    "Copy Onion address": "کپی نشانی Onion",
    "Show Onion address as a QR code": "نمایش نشانی Onion به‌صورت کد QR",
    "Copy client key": "کپی کلید کاربر",
    "Open address": "بازکردن نشانی",
    "Client authorization unavailable": "مجوزدهی کاربر در دسترس نیست",
    "Network diagnostics unavailable.": "عیب‌یابی شبکه در دسترس نیست.",
    "Dashboard refresh failed: {error}": "تازه‌سازی داشبورد ناموفق بود: {error}",
    "connected": "متصل",
    "connecting": "در حال اتصال",
    "disconnected": "قطع‌شده",
    "ready": "آماده",
    "failed": "ناموفق",
    "active": "فعال",
    "waiting": "در انتظار",
    "inactive": "غیرفعال",
    "username": "نام کاربری",
    "password": "گذرواژه",
    "SOCKS5 proxy": "پراکسی SOCKS5",
    "HTTP CONNECT proxy": "پراکسی HTTP CONNECT",
    "Stored separately from config.json": "جدا از config.json ذخیره می‌شود",
    "Primary Tor pool": "مجموعهٔ Tor اصلی",
    "Tor service": "سرویس Tor",
    "Tor profile": "پروفایل Tor",
    "System proxy active": "پراکسی سیستم فعال است",
    "Tunnel state is unavailable": "وضعیت تونل در دسترس نیست",
    "Connection state": "وضعیت اتصال",
    "Proxy stopped": "پراکسی متوقف است",
    "PROXY RUNNING": "پراکسی در حال اجرا",
    "PROXY CONNECTING": "پراکسی در حال اتصال",
    "Tor bootstrap": "راه‌اندازی اولیهٔ Tor",
    "Bootstrap": "راه‌اندازی اولیه",
    "No bridge addresses saved": "هیچ نشانی پلی ذخیره نشده است",
    "System proxy unchanged": "پراکسی سیستم بدون تغییر باقی می‌ماند",
    "System proxy cleared": "پراکسی سیستم پاک شد",
    "Traffic history": "تاریخچهٔ ترافیک",
    "Current throughput": "گذر‌دهی فعلی",
    "Network diagnostics": "عیب‌یابی شبکه",
    "Runtime status": "وضعیت محیط اجرا",
    "Restart runtime": "راه‌اندازی مجدد محیط اجرا",
    "Open event log": "بازکردن گزارش رویدادها",
    "Event log": "گزارش رویدادها",
    "Exit IP": "IP خروجی",
    "Public IP": "IP عمومی",
    "Connection details": "جزئیات اتصال",
    "Local HTTP endpoint": "نقطهٔ پایانی HTTP محلی",
    "Main Tor SOCKS endpoint": "نقطهٔ پایانی SOCKS مربوط به Tor اصلی",
    "Open official source": "بازکردن منبع رسمی",
    "View logs": "مشاهدهٔ گزارش‌ها",
    "Show logs": "نمایش گزارش‌ها",
    "Hide logs": "پنهان‌کردن گزارش‌ها",
    "Apply changes": "اعمال تغییرات",
    "Use selected version": "استفاده از نسخهٔ انتخاب‌شده",
    "Selected version": "نسخهٔ انتخاب‌شده",
    "Installed version": "نسخهٔ نصب‌شده",
    "No compatible release found": "نسخهٔ سازگاری پیدا نشد",
    "No bundles installed": "هیچ بسته‌ای نصب نشده است",
    "No profiles yet": "هنوز پروفایلی وجود ندارد",
    "No services yet": "هنوز سرویسی وجود ندارد",
    "No rules yet": "هنوز قاعده‌ای وجود ندارد",
    "10–86400 seconds": "۱۰ تا ۸۶۴۰۰ ثانیه",
    "host.com: host and subdomains; =host.com: exact host; *.host.com: subdomains only; *-api.host.com: wildcard within one DNS label.": "host.com: میزبان و زیردامنه‌ها؛ =host.com: فقط میزبان دقیق؛ *.host.com: فقط زیردامنه‌ها؛ *-api.host.com: الگو در یک بخش نام دامنه.",
    "0 bridges": "0 پل",
    "0 profiles": "0 پروفایل",
    "0 services": "0 سرویس",
    "0 rules": "0 قاعده",
    "Tor bootstrap completed": "راه‌اندازی Tor کامل شد",
    "Global shortcut issue": "مشکل میانبر سراسری",
}

def _translate_dynamic(text: str, language: str) -> str:
    if language != "fa":
        return text

    # Fast paths for the few strings containing runtime values. Most UI labels
    # are exact dictionary lookups and never enter these branches.
    count_patterns = {
        "bridge": "پل",
        "bridges": "پل",
        "profile": "پروفایل",
        "profiles": "پروفایل",
        "service": "سرویس",
        "services": "سرویس",
        "rule": "قاعده",
        "rules": "قاعده",
    }
    if text and text[0].isdigit():
        parts = text.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1] in count_patterns:
            return f"{parts[0]} {count_patterns[parts[1]]}"
        if len(parts) == 3 and parts[0].isdigit() and parts[1:] == ["installed", "bundle(s)"]:
            return f"{parts[0]} بستهٔ نصب‌شده"
        if len(parts) == 4 and parts[0].isdigit() and parts[1] == "/" and parts[2].isdigit() and parts[3] == "rules":
            return f"{parts[0]} / {parts[2]} قاعده"

    if text.startswith("(") and text.rstrip().endswith(" sec)"):
        seconds = text.rstrip()[1:-5].strip()
        if seconds.isdigit():
            return f"({seconds} ثانیه)"

    if text.startswith("Default: "):
        return "پیش‌فرض: " + text[len("Default: "):]

    dynamic_prefixes = (
        ("Could not load service activity: ", "بارگذاری فعالیت سرویس ممکن نبود: "),
        ("Dashboard refresh failed: ", "تازه‌سازی داشبورد ناموفق بود: "),
        ("Could not restore saved Tor profiles: ", "بازیابی پروفایل‌های ذخیره‌شدهٔ Tor ممکن نبود: "),
        ("Failed to set proxy: ", "تنظیم پراکسی ناموفق بود: "),
        ("Failed to clear proxy: ", "پاک‌کردن پراکسی ناموفق بود: "),
        ("Start failed: ", "شروع ناموفق بود: "),
        ("HTTP listener change failed · ", "تغییر شنوندهٔ HTTP ناموفق بود · "),
    )
    for source, translated in dynamic_prefixes:
        if text.startswith(source):
            return translated + text[len(source):]
    if text.startswith("Could not save "):
        return "ذخیرهٔ تنظیمات ممکن نبود: " + text[len("Could not save "):]
    if text.startswith("Saved "):
        return "ذخیره شد: " + text[6:]
    if text.startswith("Data: "):
        return "داده‌ها: " + text[6:]
    if text.endswith(" copied to the clipboard"):
        return text[:-len(" copied to the clipboard")] + " در حافظهٔ موقت کپی شد"
    if text.endswith(" is queued"):
        subject = text[:-10]
        return f"{_FA.get(subject, subject)} در صف قرار دارد"
    if text.endswith(" is already in the blocked-host list."):
        host = text[:-len(" is already in the blocked-host list.")]
        return f"میزبان {host} از قبل در فهرست میزبان‌های مسدودشده وجود دارد."
    if text.endswith(" is already in the excluded-host list."):
        host = text[:-len(" is already in the excluded-host list.")]
        return f"میزبان {host} از قبل در فهرست میزبان‌های مستثناشده وجود دارد."
    if text.startswith("A Tor service with ID '") and text.endswith("' already exists."):
        service_id = text[len("A Tor service with ID '"):-len("' already exists.")]
        return f"سرویسی با شناسهٔ '{service_id}' از قبل وجود دارد."
    if text.startswith("Saved profile '") and text.endswith("'."):
        profile = text[len("Saved profile '"):-2]
        return f"پروفایل '{profile}' ذخیره شد."
    if text.startswith("Removed profile '") and text.endswith(". Its DataDirectory and logs were preserved."):
        profile = text[len("Removed profile '"):-len("'. Its DataDirectory and logs were preserved.")]
        return f"پروفایل '{profile}' حذف شد. پوشهٔ داده و گزارش‌های آن حفظ شدند."
    if text.startswith("System proxy active at "):
        return "پراکسی سیستم فعال است: " + text[len("System proxy active at "):]
    if text.startswith("v") and " · unavailable" in text:
        return text.replace(" · unavailable", " · در دسترس نیست")
    if text.endswith(" · DEFAULT"):
        return text[:-len(" · DEFAULT")] + " · پیش‌فرض"
    if text.startswith("sing-box ") and "\n" in text:
        lines = text.splitlines()
        if len(lines) >= 3:
            lines[1] = lines[1].replace("Released ", "انتشار: ", 1)
            lines[2] = lines[2].replace("TorProxy-pinned SHA-256", "SHA-256 تأییدشده توسط تورپراکسی")
            return "\n".join(lines)
    if "% · " in text:
        progress, message = text.split("% · ", 1)
        return f"{progress}٪ · {message}"
    return text

def translate_text(value: Any, language: str = "en") -> str:
    """Translate a complete UI string; preserve unknown and technical text."""
    text = str(value or "")
    if language != "fa" or not text:
        return text
    translated = _FA.get(text)
    if translated is not None:
        return translated
    dynamic = _translate_dynamic(text, language)
    if dynamic != text:
        return dynamic
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
        if current != translated:
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
            if isinstance(obj, QSystemTrayIcon):
                self._translate_property(obj, "toolTip", "setToolTip")
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
                self._watch_item_model(obj)
            if isinstance(obj, (QListWidget, QTreeWidget, QTableWidget)):
                self._watch_item_model(obj)
            if isinstance(obj, QMenu):
                self._translate_property(obj, "title", "setTitle")
            if isinstance(obj, (QMenu, QMenuBar, QToolBar)):
                for action in obj.actions():
                    self._translate_property(action, "text", "setText")
                    self._translate_property(action, "toolTip", "setToolTip")
                    self._translate_property(action, "statusTip", "setStatusTip")
            if isinstance(obj, QProgressBar):
                self._translate_property(obj, "format", "setFormat")
            if isinstance(obj, QTabWidget):
                self._translate_sequence(obj, "tabText", "setTabText", obj.count())
            if isinstance(obj, QListWidget):
                for index in range(obj.count()):
                    item = obj.item(index)
                    if item is None:
                        continue
                    current = item.text()
                    source = item.data(Qt.ItemDataRole.UserRole + 733)
                    rendered = item.data(Qt.ItemDataRole.UserRole + 734)
                    if source is None or current != rendered:
                        source = current
                        item.setData(Qt.ItemDataRole.UserRole + 733, source)
                    translated = translate_text(source, self._language)
                    if current != translated:
                        item.setText(translated)
                    if item.data(Qt.ItemDataRole.UserRole + 734) != translated:
                        item.setData(Qt.ItemDataRole.UserRole + 734, translated)
            if isinstance(obj, QTreeWidget):
                self._translate_tree_items(obj)
            if isinstance(obj, QTableWidget):
                self._translate_table_items(obj)
        except RuntimeError:
            pass
        finally:
            self._translating = False

    @staticmethod
    def _translate_item_text(item, column: int, language: str) -> None:
        # QTreeWidgetItem uses column-aware methods, while QTableWidgetItem
        # exposes a single text/data column. Support both without wrapping or
        # replacing the original item object (which could carry user metadata).
        try:
            current = item.text(column)
            tree_item = True
        except TypeError:
            current = item.text()
            tree_item = False

        def read_role(role):
            try:
                return item.data(column, role)
            except TypeError:
                return item.data(role)

        def write_role(role, value):
            try:
                item.setData(column, role, value)
            except TypeError:
                item.setData(role, value)

        source_role = Qt.ItemDataRole.UserRole + 733
        rendered_role = Qt.ItemDataRole.UserRole + 734
        source = read_role(source_role)
        rendered = read_role(rendered_role)
        if source is None or current != rendered:
            source = current
            if read_role(source_role) != source:
                write_role(source_role, source)
        translated = translate_text(source, language)
        if current != translated:
            if tree_item:
                item.setText(column, translated)
            else:
                item.setText(translated)
        if read_role(rendered_role) != translated:
            write_role(rendered_role, translated)

    def _translate_table_items(self, table: QTableWidget) -> None:
        for column in range(table.columnCount()):
            header = table.horizontalHeaderItem(column)
            if header is not None:
                self._translate_item_text(header, 0, self._language)
        for row in range(table.rowCount()):
            vertical_header = table.verticalHeaderItem(row)
            if vertical_header is not None:
                self._translate_item_text(vertical_header, 0, self._language)
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None:
                    self._translate_item_text(item, 0, self._language)

    def _schedule_model_translation(self, target_ref) -> None:
        target = target_ref()
        if target is None or getattr(target, "_torproxy_i18n_pending", False):
            return
        setattr(target, "_torproxy_i18n_pending", True)

        def translate_pending():
            widget = target_ref()
            if widget is None:
                return
            setattr(widget, "_torproxy_i18n_pending", False)
            self.translate_tree(widget)

        QTimer.singleShot(0, translate_pending)

    def _watch_item_model(self, widget: QWidget) -> None:
        if getattr(widget, "_torproxy_i18n_model_watched", False):
            return
        try:
            model = widget.model()
        except (AttributeError, RuntimeError):
            return
        target_ref = weakref.ref(widget)

        def schedule_inserted(*_args):
            self._schedule_model_translation(target_ref)

        def schedule_changed(_top_left, _bottom_right, roles):
            if roles and Qt.ItemDataRole.DisplayRole not in roles and Qt.ItemDataRole.EditRole not in roles:
                return
            self._schedule_model_translation(target_ref)

        try:
            model.rowsInserted.connect(schedule_inserted)
            model.modelReset.connect(schedule_inserted)
            model.dataChanged.connect(schedule_changed)
            if hasattr(model, "headerDataChanged"):
                model.headerDataChanged.connect(schedule_inserted)
            setattr(widget, "_torproxy_i18n_model_watched", True)
        except (AttributeError, RuntimeError, TypeError):
            return

    def _translate_tree_items(self, tree: QTreeWidget) -> None:
        header = tree.headerItem()
        if header is not None:
            for column in range(tree.columnCount()):
                self._translate_item_text(header, column, self._language)

        def visit(item):
            for column in range(tree.columnCount()):
                self._translate_item_text(item, column, self._language)
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
            if isinstance(watched, (
                QLabel, QAbstractButton, QGroupBox, QLineEdit,
                QTextEdit, QPlainTextEdit, QProgressBar,
            )):
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
