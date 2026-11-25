import json
import os
import queue
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

try:
    import winreg
except ImportError:
    winreg = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object
    Observer = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:
    pystray = None
    Image = ImageDraw = None

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

VERSION = "2.1"
MAX_LOG_ENTRIES = 5000
MAX_ALERTS_SHOWN = 100
TIME_FMT = "%d/%m/%Y %H:%M:%S"
DANGEROUS_EXT = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".scr", ".js")
SUSPICIOUS_WORDS = ("hack", "virus", "malware", "crack", "keylog", "ransom", "trojan", "độc", "lừa")

ACTION_TEXT = {"them": "THÊM", "sua": "SỬA", "xoa": "XÓA"}
FILTERS = {"Tất cả": None, "Thêm": "them", "Sửa": "sua", "Xóa": "xoa", "Cảnh báo": "canhbao"}
TRAY_COLORS = {"running": "#2ecc71", "paused": "#f39c12", "stopped": "#95a5a6", "alert": "#e74c3c"}
DEDUPE_SECONDS = 0.2  # Gần như tức thì
DRAIN_MS = 10  # Quét hàng đợi siêu nhanh
DRAIN_BUDGET = 0.05  # Xử lý tối đa 50ms mỗi lượt để không đơ UI

ROOT_EXCLUDED = {"windows", "program files", "program files (x86)", "programdata",
                 "$recycle.bin", "system volume information", "recovery", "msocache"}
ANYWHERE_EXCLUDED = {"appdata", "$recycle.bin", "system volume information",
                     "__pycache__", ".git", "node_modules"}
NOISE_EXT = (".tmp", ".crdownload", ".part", ".partial", ".swp", ".lock", ".temp",
             ".log", ".vmdk", ".vhd", ".vhdx", ".vdi", ".db-journal", ".db-wal", ".db-shm")
EMULATOR_PREFIXES = ("ldplayer", "leidian", "bluestacks", "memu", "nox")
NOISE_NAMES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "thumbs.db", "desktop.ini"}

USER_EXCLUDED = []
USER_WATCH_DIRS = []


def set_user_excluded(paths):
    global USER_EXCLUDED
    USER_EXCLUDED = [os.path.normcase(os.path.normpath(p)).lower().rstrip(os.sep) for p in paths]
    dir_excluded.cache_clear()


def set_watch_dirs(paths):
    global USER_WATCH_DIRS
    USER_WATCH_DIRS = [os.path.normpath(p) for p in paths]


def config_path():
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "config.json")


CONFIG_NORM = os.path.normcase(config_path()).lower()


def fmt_time(ts=None):
    return datetime.fromtimestamp(ts if ts else time.time()).strftime(TIME_FMT)


# ---------- Khởi động cùng Windows ----------
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "GiamSat"
LEGACY_APP_NAME = "FolderMonitorApp"


def startup_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --minimized'
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pyw):
        exe = pyw
    return f'"{exe}" "{os.path.abspath(__file__)}" --minimized'


def get_autostart_value(name=APP_NAME):
    if winreg is None: return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def set_autostart(enabled):
    if winreg is None: return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, startup_command())
            to_delete = (LEGACY_APP_NAME,)
        else:
            to_delete = (APP_NAME, LEGACY_APP_NAME)
        for name in to_delete:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


# ---------- Lọc nhiễu ----------
@lru_cache(maxsize=50000)
def dir_excluded(low_dir):
    for folder in USER_EXCLUDED:
        if low_dir == folder or low_dir.startswith(folder + os.sep): return True
    parts = low_dir.split(os.sep)
    if any(part.startswith(EMULATOR_PREFIXES) for part in parts): return True
    return any(part in ANYWHERE_EXCLUDED for part in parts)


def is_excluded(path):
    low = os.path.normcase(path).lower()
    if low == CONFIG_NORM: return True
    name = os.path.basename(low)
    if name in NOISE_NAMES or name.endswith(NOISE_EXT) or name.startswith("~$"): return True
    top = low.split(os.sep, 2)
    if len(top) > 1 and top[1] in ROOT_EXCLUDED: return True
    if dir_excluded(os.path.dirname(low)): return True
    if name.startswith(EMULATOR_PREFIXES) or name in ANYWHERE_EXCLUDED: return True
    return low in USER_EXCLUDED


def fixed_drives():
    if os.name != "nt": return [os.path.expanduser("~")]
    import ctypes
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                drives.append(root)
    return drives


class MachineHandler(FileSystemEventHandler):
    def __init__(self, event_queue):
        super().__init__()
        self.queue = event_queue

    def push(self, kind, path, is_dir):
        path = os.path.normpath(path)
        if is_excluded(path): return
        try:
            self.queue.put_nowait((kind, path, is_dir, time.time()))
        except queue.Full:
            pass

    def on_created(self, event):
        self.push("them", event.src_path, event.is_directory)

    def on_modified(self, event):
        if not event.is_directory: self.push("sua", event.src_path, False)

    def on_deleted(self, event):
        self.push("xoa", event.src_path, event.is_directory)

    def on_moved(self, event):
        self.push("xoa", event.src_path, event.is_directory)
        self.push("them", event.dest_path, event.is_directory)


# ---------- Tiện ích ----------
def nearest_existing_dir(path):
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    while folder and not os.path.isdir(folder):
        parent = os.path.dirname(folder)
        if parent == folder: return None
        folder = parent
    return folder or None


def open_location(path):
    try:
        if os.name == "nt":
            if os.path.isfile(path):
                subprocess.Popen(["explorer", f"/select,{path}"])
            else:
                folder = nearest_existing_dir(path)
                if folder: os.startfile(folder)
        else:
            folder = nearest_existing_dir(path)
            if folder:
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.Popen([opener, folder])
    except OSError:
        pass


def describe_where(paths, limit=3):
    if not paths: return "(không rõ)"
    counts = {}
    for p in paths:
        folder = os.path.dirname(p)
        counts[folder] = counts.get(folder, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    if len(paths) == 1: return ranked[0][0]
    text = ", ".join(f"{folder} ({n})" for folder, n in ranked[:limit])
    if len(ranked) > limit: text += f", … +{len(ranked) - limit} nơi khác"
    return text


def find_processes_with_file(path, budget=1.5):
    if psutil is None: return []
    target = os.path.normcase(path).lower()
    found = []
    t0 = time.time()
    for proc in psutil.process_iter(["pid", "name"]):
        if time.time() - t0 > budget: break
        try:
            for opened in proc.open_files():
                if os.path.normcase(opened.path).lower() == target:
                    found.append((proc.info["name"] or "?", proc.info["pid"]))
                    break
        except (psutil.Error, OSError):
            continue
    return found


def make_tray_image(color):
    if Image is None: return None
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((4, 4, 60, 60), radius=14, fill=color)
    draw.ellipse((16, 20, 48, 44), fill="white")
    draw.ellipse((26, 26, 38, 38), fill="#1f2933")
    return img


# ---------- Cửa sổ phụ ----------
class IgnoreWindow(ctk.CTkToplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Thư mục bỏ qua")
        self.geometry("540x400")
        ctk.CTkLabel(self, justify="left", wraplength=500,
                     text="Mọi thay đổi trong các thư mục dưới đây (kể cả thư mục con) sẽ không bị ghi nhật ký hay cảnh báo."
                     ).pack(padx=14, pady=(14, 6), anchor="w")
        self.body = ctk.CTkScrollableFrame(self)
        self.body.pack(fill="both", expand=True, padx=14, pady=6)
        ctk.CTkButton(self, text="+ Thêm thư mục", width=150, command=self.add).pack(pady=12)
        self.render()
        self.after(100, self.lift)

    def render(self):
        for child in self.body.winfo_children(): child.destroy()
        if not self.app.ignored:
            ctk.CTkLabel(self.body, text="(chưa có thư mục nào)", text_color=("gray40", "gray60")).pack(pady=10)
        for path in self.app.ignored:
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkButton(row, text="X", width=26, height=24, fg_color="gray40", hover_color="#d64545",
                          command=lambda p=path: self.remove(p)).pack(side="right")
            shown = path if len(path) <= 56 else "…" + path[-55:]
            ctk.CTkLabel(row, text=shown, anchor="w").pack(side="left", fill="x")

    def add(self):
        folder = filedialog.askdirectory(title="Chọn thư mục cần BỎ QUA")
        if folder:
            self.app.add_ignored(folder)
            self.render()

    def remove(self, path):
        self.app.remove_ignored(path)
        self.render()


class WatchDirWindow(ctk.CTkToplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Thư mục giám sát cụ thể")
        self.geometry("540x400")
        ctk.CTkLabel(self, justify="left", wraplength=500, text_color=("#b57503", "#d98e04"),
                     text="Nếu có thư mục trong danh sách này, ứng dụng CHỈ giám sát các thư mục này (nhanh, chính xác).\nNếu để trống, ứng dụng sẽ giám sát TOÀN MÁY."
                     ).pack(padx=14, pady=(14, 6), anchor="w")
        self.body = ctk.CTkScrollableFrame(self)
        self.body.pack(fill="both", expand=True, padx=14, pady=6)
        ctk.CTkButton(self, text="+ Thêm thư mục giám sát", width=180, command=self.add).pack(pady=12)
        self.render()
        self.after(100, self.lift)

    def render(self):
        for child in self.body.winfo_children(): child.destroy()
        if not self.app.watch_dirs:
            ctk.CTkLabel(self.body, text="(Đang giám sát toàn máy)", text_color="gray").pack(pady=10)
        for path in self.app.watch_dirs:
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkButton(row, text="X", width=26, height=24, fg_color="gray40", hover_color="#d64545",
                          command=lambda p=path: self.remove(p)).pack(side="right")
            shown = path if len(path) <= 56 else "…" + path[-55:]
            ctk.CTkLabel(row, text=shown, anchor="w").pack(side="left", fill="x")

    def add(self):
        folder = filedialog.askdirectory(title="Chọn thư mục cần GIÁM SÁT")
        if folder:
            self.app.add_watch_dir(folder)
            self.render()

    def remove(self, path):
        self.app.remove_watch_dir(path)
        self.render()


# ---------- Ứng dụng chính ----------
class FolderMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"Dự Án Giám Sát {VERSION}")
        self.geometry("1000x720")
        self.minsize(900, 600)

        # Cấu hình font chữ
        self.font_title = ctk.CTkFont(family="Segoe UI", size=18, weight="bold")
        self.font_big = ctk.CTkFont(family="Segoe UI", size=15, weight="bold")
        self.font_normal = ctk.CTkFont(family="Segoe UI", size=13)
        self.font_small = ctk.CTkFont(family="Segoe UI", size=12)

        self.running = False
        self.paused = False
        self.count = {"them": 0, "sua": 0, "xoa": 0}
        self.alert_count = 0
        self.log_entries = deque(maxlen=MAX_LOG_ENTRIES)
        self.alert_entries = []
        self.unread_alerts = 0
        self.hidden = False
        self.session_created = set()
        self.recent_keys = {}
        self.observer = None
        self.event_queue = None
        self.watching = False
        self.attr_queue = queue.Queue()
        self.attr_executor = ThreadPoolExecutor(max_workers=1)
        self.attr_pending = 0
        self.attr_seen = {}
        self.tray = None
        self.tray_queue = queue.Queue()
        self.tray_state = None
        self.hint_shown = False
        self.ignored = []
        self.watch_dirs = []
        self.ignore_win = None
        self.watch_win = None
        self._closing = False
        self._drain_job = None

        self.build_ui()
        self.load_config()
        self.sync_autostart()
        self.setup_tray()
        self.tick_clock()
        self.pump_background()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        if Observer is None:
            self.after(400, lambda: messagebox.showerror("Thiếu thư viện", "Cần cài: pip install watchdog"))
        else:
            if "--minimized" in sys.argv:
                self.after(700, self.hide_window)
            if self.auto_monitor_var.get():
                self.after(500, lambda: self.start_monitor(silent=True))

    def build_ui(self):
        # === HEADER (Trạng thái + Đồng hồ) ===
        header = ctk.CTkFrame(self, fg_color=("#e0e0e0", "#2b2b2b"), corner_radius=0, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)

        self.status_label = ctk.CTkLabel(header, text="", anchor="w", font=self.font_big)
        self.status_label.pack(side="left", padx=20, pady=10)

        self.clock_label = ctk.CTkLabel(header, text="", anchor="e", font=self.font_normal)
        self.clock_label.pack(side="right", padx=20, pady=10)

        # === MAIN BODY ===
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=15, pady=(10, 0))

        # --- SIDEBAR (Bên trái) ---
        sidebar = ctk.CTkFrame(body, width=250, fg_color=("#f0f0f0", "#1e1e1e"), corner_radius=10)
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.pack_propagate(False)

        # Nhóm nút điều khiển
        ctrl_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        ctrl_frame.pack(pady=(15, 5), padx=15, fill="x")

        self.toggle_btn = ctk.CTkButton(ctrl_frame, text="▶ Bắt đầu giám sát", height=40,
                                        fg_color="#2e8b57", hover_color="#236b43",
                                        font=self.font_normal, command=self.toggle_monitor)
        self.toggle_btn.pack(fill="x", pady=5)

        self.pause_btn = ctk.CTkButton(ctrl_frame, text="⏸ Tạm dừng cảnh báo", height=35,
                                       fg_color="gray40", hover_color="gray30",
                                       font=self.font_small, command=self.toggle_pause)
        self.pause_btn.pack(fill="x", pady=5)

        self.restart_btn = ctk.CTkButton(ctrl_frame, text="↺ Làm mới", height=35,
                                         fg_color="gray40", hover_color="gray30",
                                         font=self.font_small, command=self.restart_watch)
        self.restart_btn.pack(fill="x", pady=5)

        # Nhóm tùy chọn
        ctk.CTkLabel(sidebar, text="Tùy chọn", font=self.font_small, text_color="gray").pack(pady=(15, 5), anchor="w",
                                                                                             padx=15)

        self.beep_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(sidebar, text="Phát tiếng bíp", variable=self.beep_var,
                        font=self.font_small, command=self.save_config).pack(pady=3, anchor="w", padx=15)

        self.guard_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(sidebar, text="Cảnh báo file mới", variable=self.guard_var,
                        font=self.font_small, command=self.save_config).pack(pady=3, anchor="w", padx=15)

        self.attr_var = ctk.BooleanVar(value=True)
        self.attr_cb = ctk.CTkCheckBox(sidebar, text="Hiện tiến trình", variable=self.attr_var,
                                       font=self.font_small, command=self.save_config)
        self.attr_cb.pack(pady=3, anchor="w", padx=15)
        if psutil is None:
            self.attr_var.set(False)
            self.attr_cb.configure(state="disabled", text="Hiện tiến trình (cần psutil)")

        self.autostart_var = ctk.BooleanVar(value=False)
        self.autostart_cb = ctk.CTkCheckBox(sidebar, text="Khởi động cùng Windows",
                                            variable=self.autostart_var, font=self.font_small,
                                            command=self.toggle_autostart)
        self.autostart_cb.pack(pady=3, anchor="w", padx=15)

        self.auto_monitor_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(sidebar, text="Tự động giám sát", variable=self.auto_monitor_var,
                        font=self.font_small, command=self.save_config).pack(pady=3, anchor="w", padx=15)

        # --- CONTENT (Bên phải - Tabs) ---
        content = ctk.CTkFrame(body, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True)

        self.tabs = ctk.CTkTabview(content, corner_radius=10)
        self.tabs.pack(fill="both", expand=True)

        log_tab = self.tabs.add("Nhật ký")
        alert_tab = self.tabs.add("Cảnh báo")

        # Cấu hình màu tab Cảnh báo nổi bật
        self.tabs._segmented_button.configure(text_color=("black", "white"))

        # Tab Nhật ký
        tools = ctk.CTkFrame(log_tab, fg_color="transparent")
        tools.pack(fill="x", pady=(0, 5))

        self.search_entry = ctk.CTkEntry(tools, width=220, placeholder_text="🔍 Tìm kiếm...", font=self.font_small)
        self.search_entry.pack(side="left")
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_log())

        self.filter_btn = ctk.CTkSegmentedButton(tools, values=list(FILTERS.keys()),
                                                 command=lambda v: self.refresh_log(), font=self.font_small)
        self.filter_btn.set("Tất cả")
        self.filter_btn.pack(side="right")

        self.log_box = ctk.CTkTextbox(log_tab, wrap="none", font=self.font_small, corner_radius=8)
        self.log_box.pack(fill="both", expand=True)

        # Tab Cảnh báo
        ctk.CTkLabel(alert_tab, text="Nhấp đúp: Mở thư mục  |  Chuột phải: Bỏ qua thư mục",
                     font=self.font_small, text_color="gray").pack(fill="x", pady=(0, 5), anchor="w")

        self.alert_box = ctk.CTkTextbox(alert_tab, wrap="none", font=self.font_small,
                                        fg_color=("#fff5f5", "#2c1a1a"), corner_radius=8)
        self.alert_box.pack(fill="both", expand=True)
        self.alert_box.bind("<Double-Button-1>", self.on_alert_double_click)
        self.alert_box.bind("<Button-3>", self.on_alert_right_click)

        # Cấu hình thẻ màu cho textbox
        for box in (self.log_box, self.alert_box):
            box.tag_config("them", foreground="#2e8b57")
            box.tag_config("sua", foreground="#d98e04")
            box.tag_config("xoa", foreground="#d64545")
            box.tag_config("info", foreground="#4a90d9")
            box.tag_config("canhbao", foreground="#e02020")
            box.configure(state="disabled")

        # === BOTTOM BAR (Thanh dưới cùng) ===
        bottom = ctk.CTkFrame(self, fg_color=("#e0e0e0", "#2b2b2b"), corner_radius=0, height=50)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        self.stats_label = ctk.CTkLabel(bottom, text=self.stats_text(), font=self.font_small)
        self.stats_label.pack(side="left", padx=20, pady=10)

        self.alert_label = ctk.CTkLabel(bottom, text="⚠ Cảnh báo: 0", font=self.font_small)
        self.alert_label.pack(side="left", padx=20)

        ctk.CTkButton(bottom, text="Thoát hẳn", width=90, height=30, fg_color="#b03a3a", hover_color="#8c2d2d",
                      font=self.font_small, command=self.confirm_quit).pack(side="right", padx=10, pady=10)
        ctk.CTkButton(bottom, text="Xóa cảnh báo", width=100, height=30, fg_color="gray40", hover_color="gray30",
                      font=self.font_small, command=self.clear_alerts).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="Xóa nhật ký", width=100, height=30, fg_color="gray40", hover_color="gray30",
                      font=self.font_small, command=self.clear_log).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="Lưu nhật ký", width=100, height=30,
                      font=self.font_small, command=self.save_log).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="📁 Chọn thư mục GS", width=130, height=30, fg_color="#4a90d9", hover_color="#357abd",
                      font=self.font_small, command=self.open_watch_window).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="🚫 Thư mục bỏ qua", width=130, height=30, fg_color="gray40", hover_color="gray30",
                      font=self.font_small, command=self.open_ignore_window).pack(side="right", padx=5)

    def setup_tray(self):
        if pystray is None or Image is None:
            if "--minimized" not in sys.argv:
                self.after(1000, lambda: messagebox.showwarning(
                    "Thiếu thư viện khay hệ thống",
                    "Để chạy ngầm dưới khay hệ thống (thay vì taskbar), vui lòng cài:\n\npip install pystray Pillow"))
            return

        put = self.tray_queue.put
        menu = pystray.Menu(
            pystray.MenuItem("Mở Dự Án Giám Sát", lambda: put("show"), default=True),
            pystray.MenuItem("Bắt đầu / Dừng", lambda: put("toggle")),
            pystray.MenuItem("Tạm dừng cảnh báo", lambda: put("pause"), checked=lambda item: self.paused),
            pystray.MenuItem("Làm mới giám sát", lambda: put("restart")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Thoát hẳn", lambda: put("quit")),
        )
        try:
            self.tray = pystray.Icon("GiamSat", make_tray_image(TRAY_COLORS["stopped"]), "Dự Án Giám Sát", menu)
            try:
                self.tray.run_detached()
            except AttributeError:
                import threading
                threading.Thread(target=self.tray.run, daemon=True).start()
        except Exception as e:
            print(f"Lỗi tạo khay: {e}")
            self.tray = None

    def update_tray(self, state, text):
        if self.tray is None or state == self.tray_state: return
        self.tray_state = state
        try:
            self.tray.icon = make_tray_image(TRAY_COLORS[state])
            self.tray.title = "Dự Án Giám Sát - " + text.replace("● ", "")
            self.tray.update_menu()
        except Exception:
            pass

    def show_window(self):
        self.hidden = False
        self.unread_alerts = 0
        self.deiconify()
        self.state("normal")
        self.lift()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def hide_window(self):
        self.hidden = True
        if self.tray is not None:
            self.withdraw()
        else:
            self.iconify()

    def on_close(self):
        self.hide_window()
        if self.tray is not None and not self.hint_shown:
            self.hint_shown = True
            try:
                self.tray.notify("Ứng dụng vẫn đang chạy ngầm ở khay hệ thống.", "Dự Án Giám Sát")
            except Exception:
                pass

    def confirm_quit(self):
        if messagebox.askyesno("Thoát hẳn", "Thoát hẳn sẽ ngừng giám sát.\nBạn có chắc không?"):
            self.quit_app()

    def quit_app(self):
        self._closing = True
        self.running = False
        self.stop_watch()
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.attr_executor.shutdown(wait=False)
        self.save_config()
        self.destroy()

    def tick_clock(self):
        if self._closing: return
        try:
            now = datetime.now()
            days = ["Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy", "Chủ Nhật"]
            self.clock_label.configure(text=f"{days[now.weekday()]}, {now:%d/%m/%Y}   {now:%H:%M:%S}")
            self.refresh_status()
            self.after(1000, self.tick_clock)
        except tk.TclError:
            pass

    def refresh_status(self):
        if not self.running:
            text, color, state = ("● Chưa giám sát", "#d98e04", "stopped")
        elif self.paused:
            text, color, state = "● Đang giám sát - TẠM DỪNG", "#d98e04", "paused"
        elif self.unread_alerts > 0:
            text, color, state = (f"● Có {self.unread_alerts} cảnh báo mới", "#d64545", "alert")
        else:
            text, color, state = "● Đang giám sát", "#2e8b57", "running"
        backlog = self.event_queue.qsize() if (self.watching and self.event_queue is not None) else 0
        if backlog > 300: text += f" (đang xử lý {backlog} sự kiện tồn)"
        self.status_label.configure(text=text, text_color=color)
        self.update_tray(state, text)

    def save_config(self):
        data = {
            "beep": bool(self.beep_var.get()), "auto_monitor": bool(self.auto_monitor_var.get()),
            "guard": bool(self.guard_var.get()), "attribution": bool(self.attr_var.get()),
            "ignored_dirs": self.ignored, "watch_dirs": self.watch_dirs,
        }
        try:
            with open(config_path(), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def load_config(self):
        try:
            with open(config_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        self.beep_var.set(data.get("beep", False))
        self.auto_monitor_var.set(data.get("auto_monitor", True))
        self.guard_var.set(data.get("guard", False))
        if psutil is not None: self.attr_var.set(data.get("attribution", True))
        self.ignored = [p for p in data.get("ignored_dirs", []) if isinstance(p, str)]
        self.watch_dirs = [p for p in data.get("watch_dirs", []) if isinstance(p, str)]
        set_user_excluded(self.ignored)
        set_watch_dirs(self.watch_dirs)

    def sync_autostart(self):
        if winreg is None:
            self.autostart_var.set(False)
            self.autostart_cb.configure(state="disabled", text="Khởi động cùng Windows (chỉ Windows)")
            return
        value = get_autostart_value() or get_autostart_value(LEGACY_APP_NAME)
        self.autostart_var.set(value is not None)
        if value is not None and (value != startup_command() or get_autostart_value() is None):
            try:
                set_autostart(True)
            except OSError:
                pass

    def toggle_autostart(self):
        enabled = bool(self.autostart_var.get())
        try:
            set_autostart(enabled)
        except OSError as err:
            self.autostart_var.set(not enabled)
            messagebox.showerror("Lỗi", f"Không thay đổi được:\n{err}")
            return
        if enabled: self.auto_monitor_var.set(True)
        self.save_config()

    def add_ignored(self, folder):
        path = os.path.normpath(folder)
        if path not in self.ignored: self.ignored.append(path)
        set_user_excluded(self.ignored)
        self.save_config()
        self.write_log(f"Đã bỏ qua: {path}", "info")

    def remove_ignored(self, folder):
        if folder in self.ignored: self.ignored.remove(folder)
        set_user_excluded(self.ignored)
        self.save_config()
        self.write_log(f"Đã gỡ bỏ qua: {folder}", "info")

    def ignore_from_alert(self, path):
        start = nearest_existing_dir(path) or os.path.expanduser("~")
        folder = filedialog.askdirectory(initialdir=start, title="Chọn thư mục cần BỎ QUA")
        if folder: self.add_ignored(folder)

    def open_ignore_window(self):
        if self.ignore_win is not None and self.ignore_win.winfo_exists():
            self.ignore_win.lift()
            return
        self.ignore_win = IgnoreWindow(self)

    def add_watch_dir(self, folder):
        path = os.path.normpath(folder)
        if path not in self.watch_dirs: self.watch_dirs.append(path)
        set_watch_dirs(self.watch_dirs)
        self.save_config()
        self.write_log(f"Thêm giám sát: {path}", "info")
        if self.running:
            self.stop_monitor()
            self.start_monitor(silent=True)

    def remove_watch_dir(self, folder):
        if folder in self.watch_dirs: self.watch_dirs.remove(folder)
        set_watch_dirs(self.watch_dirs)
        self.save_config()
        self.write_log(f"Bỏ giám sát: {folder}", "info")
        if self.running:
            self.stop_monitor()
            self.start_monitor(silent=True)

    def open_watch_window(self):
        if self.watch_win is not None and self.watch_win.winfo_exists():
            self.watch_win.lift()
            return
        self.watch_win = WatchDirWindow(self)

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            self.pause_btn.configure(text="▶ Tiếp tục cảnh báo", fg_color="#d98e04", hover_color="#b57503")
            self.write_log("Đã TẠM DỪNG cảnh báo.", "info")
        else:
            self.pause_btn.configure(text="⏸ Tạm dừng cảnh báo", fg_color="gray40", hover_color="gray30")
            self.write_log("Đã bật lại cảnh báo.", "info")
        self.refresh_status()
        if self.tray is not None:
            try:
                self.tray.update_menu()
            except Exception:
                pass

    def restart_watch(self):
        if not self.running:
            messagebox.showinfo("Chưa giám sát", "Hãy bấm 'Bắt đầu giám sát' trước.")
            return
        dropped = self.event_queue.qsize() if self.event_queue is not None else 0
        self.stop_watch()
        self.recent_keys.clear()
        self.start_watch()
        self.write_log(f"Đã làm mới giám sát (bỏ {dropped} sự kiện tồn đọng).", "info")

    def toggle_monitor(self):
        if self.running:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self, silent=False):
        if self.running: return
        if Observer is None:
            if not silent: messagebox.showerror("Lỗi", "Cần cài watchdog.")
            return
        self.running = True
        self.start_watch()
        self.toggle_btn.configure(text="⏹ Dừng giám sát", fg_color="#d64545", hover_color="#a83333")
        self.refresh_status()

    def stop_monitor(self):
        self.running = False
        self.stop_watch()
        self.toggle_btn.configure(text="▶ Bắt đầu giám sát", fg_color="#2e8b57", hover_color="#236b43")
        self.refresh_status()
        self.write_log("Đã dừng giám sát.", "info")

    def start_watch(self):
        if self.watching: return
        self.event_queue = queue.Queue(maxsize=20000)
        self.session_created = set()
        self.observer = Observer()
        handler = MachineHandler(self.event_queue)
        watched = []

        roots = USER_WATCH_DIRS if USER_WATCH_DIRS else fixed_drives()

        for root in roots:
            try:
                self.observer.schedule(handler, root, recursive=True)
                watched.append(root)
            except OSError as err:
                self.write_log(f"Không theo dõi được {root}: {err}", "info")
        self.observer.start()
        self.watching = True
        self.write_log("Bắt đầu giám sát: " + ", ".join(watched), "info")
        self._drain_job = self.after(DRAIN_MS, self.drain_events)

    def stop_watch(self):
        self.watching = False
        if self._drain_job is not None:
            try:
                self.after_cancel(self._drain_job)
            except Exception:
                pass
            self._drain_job = None
        if self.observer is not None:
            try:
                self.observer.stop()
                self.observer.join(timeout=1)
            except Exception:
                pass
            self.observer = None

    def drain_events(self):
        if not self.watching or self._closing: return
        try:
            started = time.time()
            while time.time() - started < DRAIN_BUDGET:
                batch = []
                try:
                    while len(batch) < 100: batch.append(self.event_queue.get_nowait())
                except queue.Empty:
                    pass
                if not batch: break
                self.process_events(batch)
            self._drain_job = self.after(DRAIN_MS, self.drain_events)
        except tk.TclError:
            pass

    def dedupe_events(self, events):
        now = time.time()
        fresh = []
        for ev in events:
            key = (ev[0], ev[1])
            if now - self.recent_keys.get(key, 0) < DEDUPE_SECONDS: continue
            self.recent_keys[key] = now
            fresh.append(ev)
        if len(self.recent_keys) > 20000:
            self.recent_keys = {k: t for k, t in self.recent_keys.items() if now - t < DEDUPE_SECONDS}
        return fresh

    def find_reasons(self, kind, path, is_dir):
        reasons = []
        action = ACTION_TEXT[kind]
        what = "Thư mục" if is_dir else "File"

        # 1. Cảnh báo khi SỬA hoặc XÓA (trừ file tự tạo trong phiên này)
        if kind in ("sua", "xoa") and path not in self.session_created:
            reasons.append(f"{what} bị {action}")

        # 2. Cảnh báo khi THÊM MỚI (Thư mục luôn cảnh báo, File phụ thuộc tùy chọn)
        if kind == "them" and (is_dir or self.guard_var.get()):
            reasons.append(f"{what} mới được THÊM")

        # 3. Cảnh báo file thực thi
        if not is_dir and kind in ("them", "sua") and path.lower().endswith(DANGEROUS_EXT):
            reasons.append(f"File thực thi bị {action}")

        # 4. Cảnh báo tên đáng ngờ
        if kind in ("them", "sua"):
            name = os.path.basename(path).lower()
            for word in SUSPICIOUS_WORDS:
                if word in name:
                    reasons.append(f"Tên đáng ngờ (chứa '{word}')")
                    break

        return reasons

    def process_events(self, events):
        events = self.dedupe_events(events)
        if not events: return

        groups = {}
        log_lines = []
        for kind, path, is_dir, ts in events:
            self.count[kind] += 1
            name = os.path.basename(path) or path
            what = "thư mục " if is_dir else ""
            log_lines.append((f"[{ACTION_TEXT[kind]}] {what}{name} | Nơi: {os.path.dirname(path)}", kind, ts))
            if not self.paused:
                for reason in self.find_reasons(kind, path, is_dir):
                    group = groups.setdefault(reason, {"paths": [], "ts": ts})
                    group["paths"].append(path)
            if kind == "them" and not is_dir:
                self.session_created.add(path)

        if log_lines:
            self.log_box.configure(state="normal")
            for msg, tag, ts in log_lines:
                entry = (fmt_time(ts), tag, msg)
                self.log_entries.append(entry)
                if self.entry_matches(entry):
                    self.log_box.insert("end", f"{entry[0]}  {msg}\n", tag)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

        self.stats_label.configure(text=self.stats_text())

        if groups:
            self.alert_box.configure(state="normal")
            for reason, g in groups.items():
                self.raise_alert_batch(reason, g["paths"], g["ts"])
            self.alert_box.see("end")
            self.alert_box.configure(state="disabled")

            if self.hidden:
                self.unread_alerts += len(groups)
            if self.beep_var.get(): self.bell()
            for g in list(groups.values())[:3]:
                self.request_attribution(g["paths"][0], g)

    def raise_alert_batch(self, reason, paths, ts, proc_text=""):
        self.alert_count += 1
        if len(paths) == 1:
            message = f"{reason} -> {os.path.basename(paths[0])} | Nơi: {describe_where(paths)}"
        else:
            names = ", ".join(os.path.basename(p) for p in paths[:3])
            if len(paths) > 3: names += "…"
            message = f"{reason}: {len(paths)} mục (vd: {names}) | Nơi: {describe_where(paths)}"

        if proc_text:
            message += f" | Tiến trình: {proc_text}"

        self.alert_entries.append({"text": message, "path": paths[0], "ts": ts})

        if len(self.alert_entries) > MAX_ALERTS_SHOWN:
            self.alert_entries.pop(0)
            self.alert_box.delete("1.0", "2.0")

        self.alert_box.insert("end", f"{fmt_time(ts)}  ⚠ {message}\n", "canhbao")
        self.alert_label.configure(text=f"⚠ Cảnh báo: {self.alert_count}", text_color="#e02020")
        return message

    def stats_text(self):
        c = self.count
        return f"Thêm: {c['them']} | Sửa: {c['sua']} | Xóa: {c['xoa']}"

    def request_attribution(self, path, group_data):
        if (psutil is None or not self.attr_var.get() or not self.running or not os.path.isfile(path)):
            return
        now = time.time()
        if self.attr_pending >= 4 or now - self.attr_seen.get(path, 0) < 30: return
        if len(self.attr_seen) > 2000:
            self.attr_seen = {k: t for k, t in self.attr_seen.items() if now - t < 30}
        self.attr_seen[path] = now
        self.attr_pending += 1
        self.attr_executor.submit(self.attribution_job, path, group_data)

    def attribution_job(self, path, group_data):
        try:
            procs = find_processes_with_file(path)
        except Exception:
            procs = []
        text = ""
        if procs:
            text = ", ".join(f"{n} (PID {pid})" for n, pid in procs[:2])
        self.attr_queue.put((path, text, group_data))

    def pump_background(self):
        if self._closing: return
        try:
            while True:
                command = self.tray_queue.get_nowait()
                if command == "show":
                    self.show_window()
                elif command == "toggle":
                    self.toggle_monitor()
                elif command == "pause":
                    self.toggle_pause()
                elif command == "restart":
                    self.restart_watch()
                elif command == "quit":
                    self.quit_app()
                    return
        except queue.Empty:
            pass
        try:
            while True:
                path, text, group_data = self.attr_queue.get_nowait()
                self.attr_pending = max(0, self.attr_pending - 1)
                if text and not self._closing and self.alert_entries:
                    for entry in reversed(self.alert_entries):
                        if entry["path"] == path and "Tiến trình" not in entry["text"]:
                            entry["text"] += f" | Tiến trình: {text}"
                            break
                    self.refresh_alerts()
        except queue.Empty:
            pass
        try:
            self.after(300, self.pump_background)
        except tk.TclError:
            pass

    def refresh_alerts(self):
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        for entry in self.alert_entries[-MAX_ALERTS_SHOWN:]:
            self.alert_box.insert("end", f"{fmt_time(entry['ts'])}  ⚠ {entry['text']}\n", "canhbao")
        self.alert_box.see("end")
        self.alert_box.configure(state="disabled")

    def alert_path_at(self, event):
        try:
            line = int(self.alert_box.index(f"@{event.x},{event.y}").split(".")[0]) - 1
            start_idx = max(0, len(self.alert_entries) - MAX_ALERTS_SHOWN)
            if 0 <= line < len(self.alert_entries) - start_idx:
                return self.alert_entries[start_idx + line]["path"]
        except Exception:
            pass
        return None

    def on_alert_double_click(self, event):
        path = self.alert_path_at(event)
        if path: open_location(path)

    def on_alert_right_click(self, event):
        path = self.alert_path_at(event)
        if not path: return
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Mở nơi file xuất hiện", command=lambda: open_location(path))
        menu.add_command(label="Bỏ qua thư mục này...", command=lambda: self.ignore_from_alert(path))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def write_to(self, box, message, tag, ts=None):
        box.configure(state="normal")
        box.insert("end", f"{fmt_time(ts)}  {message}\n", tag)
        box.see("end")
        box.configure(state="disabled")

    def entry_matches(self, entry):
        _time, kind, text = entry
        wanted = FILTERS[self.filter_btn.get()]
        if wanted is not None and kind != wanted: return False
        keyword = self.search_entry.get().strip().lower()
        return keyword in text.lower()

    def write_log(self, message, tag="info", ts=None):
        entry = (fmt_time(ts), tag, message)
        self.log_entries.append(entry)
        if self.entry_matches(entry): self.insert_entry(entry)

    def insert_entry(self, entry):
        time_str, tag, text = entry
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{time_str}  {text}\n", tag)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def refresh_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        for entry in self.log_entries:
            if self.entry_matches(entry): self.insert_entry(entry)

    def save_log(self):
        if not self.log_entries:
            messagebox.showinfo("Trống", "Chưa có nhật ký.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")],
                                            initialfile=f"nhat_ky_{datetime.now():%Y%m%d_%H%M%S}.txt")
        if file:
            alerts = self.alert_box.get("1.0", "end").strip()
            with open(file, "w", encoding="utf-8") as f:
                f.write("===== NHẬT KÝ =====\n")
                for time_str, _tag, text in self.log_entries: f.write(f"{time_str}  {text}\n")
                f.write("\n===== CẢNH BÁO =====\n" + (alerts or "(không có)") + "\n")
            messagebox.showinfo("Thành công", f"Đã lưu:\n{file}")

    def clear_alerts(self):
        self.alert_entries.clear()
        self.alert_count = 0
        self.unread_alerts = 0
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.configure(state="disabled")
        self.alert_label.configure(text="Cảnh báo: 0", text_color=("black", "white"))
        self.refresh_status()

    def clear_log(self):
        self.log_entries.clear()
        self.count = {"them": 0, "sua": 0, "xoa": 0}
        self.stats_label.configure(text=self.stats_text())
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self.clear_alerts()


if __name__ == "__main__":
    if "--install-startup" in sys.argv or "--remove-startup" in sys.argv:
        try:
            set_autostart("--install-startup" in sys.argv)
        except Exception:
            sys.exit(1)
        sys.exit(0)
    app = FolderMonitorApp()
    app.mainloop()