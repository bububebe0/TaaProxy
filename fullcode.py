#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Taa Proxy — клиент для работы с прокси-серверами VLESS и Hysteria2.
"""

DEBUG_ENABLED = False

_singleton_mutex = None

def _bring_existing_window_to_front():
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, None)
    found = ctypes.c_int(0)

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)

    def _enum_cb(hwnd, lParam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
            if "Taa" in title or "taa" in title.lower():
                SW_RESTORE = 9
                user32.ShowWindow(hwnd, SW_RESTORE)
                user32.SetForegroundWindow(hwnd)
                found.value = hwnd
                return False
        return True

    cb = EnumWindowsProc(_enum_cb)
    user32.EnumWindows(cb, 0)

def is_already_running(mutex_name="TaaClient_Singleton_Mutex"):
    try:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexW(None, False, mutex_name)
        if mutex:
            error = ctypes.get_last_error()
            if error == 183:
                kernel32.CloseHandle(mutex)
                return True
            global _singleton_mutex
            _singleton_mutex = mutex
        return False
    except Exception:
        return False

if is_already_running():
    _bring_existing_window_to_front()
    sys.exit(0)

_debug_logger = None
_error_logger = None

def _get_log_base():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def _make_rotating_logger(name, filename, level, max_bytes=5 * 1024 * 1024, backup_count=2):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        try:
            handler = logging.handlers.RotatingFileHandler(
                os.path.join(_get_log_base(), filename),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
            ))
            logger.addHandler(handler)
        except Exception:
            pass
    return logger

def _get_debug_logger():
    global _debug_logger
    if _debug_logger is None:
        _debug_logger = _make_rotating_logger('taa.debug', 'debug.log', logging.DEBUG)
    return _debug_logger

def _get_error_logger():
    global _error_logger
    if _error_logger is None:
        _error_logger = _make_rotating_logger('taa.error', 'error.log', logging.ERROR)
    return _error_logger

def debug_log(message):
    if not DEBUG_ENABLED:
        return
    try:
        _get_debug_logger().debug(message)
    except Exception:
        pass

class DebugStream:
    def write(self, msg):
        if DEBUG_ENABLED and msg.strip():
            debug_log(f"STREAM: {msg}")
    def flush(self):
        pass

sys.stdout = DebugStream()
sys.stderr = DebugStream()

def global_exception_handler(exc_type, exc_value, exc_traceback):
    import traceback
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    if DEBUG_ENABLED:
        debug_log(error_msg)
    try:
        _get_error_logger().error(error_msg)
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = global_exception_handler

def set_system_proxy(enable=True, port=1080):
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as key:
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
    except:
        pass

def _safe_delete_config():
    try:
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
            debug_log("config.json удалён")
    except Exception as e:
        debug_log(f"Не удалось удалить config.json: {e}")

def check_and_clear_stale_proxy():
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            if enable == 1 and server.startswith("127.0.0.1:"):
                set_system_proxy(False)
                debug_log("Обнаружен и сброшен остаточный системный прокси")
    except Exception as e:
        debug_log(f"Ошибка при проверке остаточного прокси: {e}")

atexit.register(lambda: set_system_proxy(False))
atexit.register(lambda: set_kill_switch(False))

def set_kill_switch(enable=True):
    rule_name = "TaaProxy_KillSwitch"
    flags = subprocess.CREATE_NO_WINDOW
    try:
        if enable:
            debug_log("Kill Switch: активация")
            for proto in ["TCP", "UDP"]:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=out", "action=block",
                     f"protocol={proto}", "remoteaddress=any"],
                    capture_output=True, creationflags=flags
                )
        else:
            debug_log("Kill Switch: деактивация")
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, creationflags=flags
            )
    except Exception as e:
        debug_log(f"Ошибка Kill Switch: {e}")

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    buf_in  = (ctypes.c_char * len(plaintext))(*plaintext)
    blob_in = DATA_BLOB(len(plaintext), buf_in)
    blob_out = DATA_BLOB()

    ok = crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0,
        ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError(f"CryptProtectData failed: {ctypes.GetLastError()}")

    encrypted = bytes(blob_out.pbData[:blob_out.cbData])
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return encrypted

def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    buf_in  = (ctypes.c_char * len(ciphertext))(*ciphertext)
    blob_in = DATA_BLOB(len(ciphertext), buf_in)
    blob_out = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0,
        ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")

    decrypted = bytes(blob_out.pbData[:blob_out.cbData])
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return decrypted

def _restrict_file_acl(filepath: str):
    try:
        flags = subprocess.CREATE_NO_WINDOW
        domain = os.environ.get("USERDOMAIN", "")
        user   = os.environ.get("USERNAME", "")
        computername = os.environ.get("COMPUTERNAME", "")
        if domain and domain != computername:
            full_user = f"{domain}\\{user}"
        elif user:
            full_user = user
        else:
            debug_log("_restrict_file_acl: не удалось определить имя пользователя")
            return
        r1 = subprocess.run(
            ["icacls", filepath, "/inheritance:r",
             "/remove:g", "Everyone",
             "/remove:g", "Users",
             "/remove:g", "Authenticated Users"],
            capture_output=True, creationflags=flags
        )
        r2 = subprocess.run(
            ["icacls", filepath, "/grant:r", f"{full_user}:(F)"],
            capture_output=True, creationflags=flags
        )
        if r1.returncode != 0 or r2.returncode != 0:
            debug_log(f"ACL предупреждение для {filepath}: "
                      f"icacls вернул {r1.returncode}/{r2.returncode}")
        else:
            debug_log(f"ACL ограничен для {filepath} (пользователь: {full_user})")
    except Exception as e:
        debug_log(f"Ошибка установки ACL для {filepath}: {e}")

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def data_path(relative_path=""):
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)

class ProxyApp(ctk.CTk):
    def __init__(self):
        debug_log("Начало инициализации ProxyApp")
        try:
            super().__init__()
            debug_log("super().__init__() выполнен")

            os.makedirs(ROUTES_DIR, exist_ok=True)
            os.makedirs(DATA_DIR, exist_ok=True)
            debug_log("Папки созданы")

            self.app_settings = self.load_app_settings()
            self.lang = self.app_settings.get("language", "ru")
            debug_log(f"Настройки загружены, язык: {self.lang}")

            global DEBUG_ENABLED
            DEBUG_ENABLED = self.app_settings.get("debug_mode", False)
            debug_log(f"Режим отладки: {'включён' if DEBUG_ENABLED else 'выключен'}")

            self.minimize_on_close = self.app_settings.get("minimize_on_close", True)

            self.title(self.tr("title"))
            try:
                self.iconbitmap(resource_path("ico.ico"))
                debug_log("Иконка окна установлена")
            except Exception as e:
                debug_log(f"Не удалось загрузить иконку окна: {e}")

            try:
                self.icon_on = Image.open(resource_path("ico.ico"))
                self.icon_off = Image.open(resource_path("off.ico"))
                debug_log("Иконки трея загружены")
            except Exception as e:
                debug_log(f"Ошибка загрузки иконок трея: {e}")
                self.icon_on = Image.new('RGB', (64, 64), color=(79, 70, 229))
                self.icon_off = Image.new('RGB', (64, 64), color=(100, 100, 100))

            self.geometry("1200x700")
            saved_geometry = self.app_settings.get("window_geometry")
            saved_state = self.app_settings.get("window_state", "normal")
            if saved_geometry:
                self.geometry(saved_geometry)
            else:
                self.center_window(self, 1200, 700)
            if saved_state == "zoomed":
                self.state("zoomed")
            debug_log("Геометрия окна установлена")

            self.minsize(860, 620)
            self.configure(fg_color=BG_COLOR)

            self.proxy_process = None
            self.servers = []
            self.server_frames = []
            self.server_name_labels = []
            self.selected_server_index = -1
            self.connected_server_index = -1

            self._proxy_port = secrets.randbelow(50000) + 10000
            debug_log(f"Локальный прокси: порт {self._proxy_port}")

            self._proxy_user     = secrets.token_hex(8)
            self._proxy_password = secrets.token_hex(16)
            debug_log("Локальный прокси: учётные данные сгенерированы")

            self._monitor_stop_event = threading.Event()

            self._country_cache: dict = {}
            self._flag_seq: int = 0

            self._anim_after_id = None
            self._anim_phase = 0

            self._status_fade_id = None
            self._status_fade_step = 0
            self._status_fade_steps = 20
            self._status_fade_callback = None

            self.hide_host_var = ctk.BooleanVar(value=True)
            self.split_tunnel_var = ctk.BooleanVar(value=self.app_settings.get("split_tunneling", True))
            self.autostart_var = ctk.BooleanVar(value=self.check_autostart())
            self.kill_switch_enabled = self.app_settings.get("kill_switch", False)
            self.auto_reconnect_enabled = self.app_settings.get("auto_reconnect", False)
            self._auto_reconnect_attempts = 0
            self._no_network = False

            self._ping_anim_after_id = None
            self._ping_anim_phase = 0

            self.font_title = ctk.CTkFont(family="Segoe UI", size=24, weight="bold")
            self.font_main = ctk.CTkFont(family="Segoe UI", size=14)
            self.font_bold = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")
            self.font_small = ctk.CTkFont(family="Segoe UI", size=12)

            self.current_routes_file = "routes.txt"
            self.routes_list = []
            self.app_exceptions = self.app_settings.get("app_exceptions", [])
            self.domain_exceptions = self.app_settings.get("domain_exceptions", [])

            debug_log("Создание сайдбара")
            self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=SIDEBAR_COLOR)
            self.sidebar_frame.pack(side="left", fill="y")
            self.sidebar_frame.pack_propagate(False)

            self.logo_label = ctk.CTkLabel(self.sidebar_frame, text=self.tr("app_name"), font=self.font_title, text_color=TEXT_MAIN)
            self.logo_label.pack(pady=(35, 25), padx=25, anchor="w")

            self.add_btn = ctk.CTkButton(
                self.sidebar_frame, text=self.tr("add_from_clipboard"), font=self.font_bold,
                fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, corner_radius=10, height=45,
                command=self.add_from_clipboard
            )
            self.add_btn.pack(pady=(0, 15), padx=20, fill="x")

            self.btn_import = ctk.CTkButton(
                self.sidebar_frame, text=self.tr("import_configs"), font=self.font_main,
                fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
                text_color=TEXT_MAIN, corner_radius=10, height=40, command=self.show_import_panel
            )
            self.btn_import.pack(pady=(0, 5), padx=20, fill="x")

            self.btn_settings = ctk.CTkButton(
                self.sidebar_frame, text=self.tr("settings"), font=self.font_main,
                fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
                text_color=TEXT_MAIN, corner_radius=10, height=40, command=self.show_settings_panel
            )
            self.btn_settings.pack(pady=(0, 15), padx=20, fill="x")

            self.server_list_frame = ctk.CTkScrollableFrame(self.sidebar_frame, fg_color="transparent")
            self.server_list_frame.pack(pady=5, padx=10, fill="both", expand=True)

            self.btn_quit = ctk.CTkButton(
                self.sidebar_frame, text=self.tr("btn_exit"), font=self.font_main,
                fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
                text_color=DANGER_COLOR, corner_radius=10, height=40, command=self.cleanup_and_exit
            )
            self.btn_quit.pack(side="bottom", pady=(5, 25), padx=20, fill="x")

            self.taa_label = ctk.CTkLabel(
                self.sidebar_frame, text="Taaproxy.ru", font=self.font_main, text_color=ACCENT_COLOR, cursor="hand2"
            )
            self.taa_label.pack(side="bottom", pady=(0, 5))
            self.taa_label.bind("<Button-1>", lambda e: webbrowser.open("https://taaproxy.ru/allversion"))

            self.main_container = ctk.CTkFrame(self, fg_color="transparent")
            self.main_container.pack(side="right", fill="both", expand=True, padx=35, pady=35)

            self.servers_panel = ctk.CTkFrame(self.main_container, fg_color="transparent")
            self.init_servers_panel()
            self.servers_panel.pack(fill="both", expand=True)

            self.settings_panel = ctk.CTkFrame(self.main_container, fg_color="transparent")
            self.init_settings_panel()

            self.import_panel = ctk.CTkFrame(self.main_container, fg_color="transparent")
            self.init_import_panel()

            self.current_panel = "servers"
            self.show_panel("servers")

            self.refresh_routes_list()
            self.load_servers_from_file()
            self.load_routes()
            self.toggle_split_state()
            self.select_default_server_on_start()

            self.create_tray_icon()
            self.protocol("WM_DELETE_WINDOW", self.hide_window)
            self.bind("<Map>", self._on_map)

            self._resize_job = None
            self.bind("<Configure>", self._on_window_configure, add="+")
            self.after(200, self._patch_scrollable_frames)

            debug_log("Инициализация ProxyApp завершена успешно")
        except Exception as e:
            debug_log(f"Критическая ошибка при инициализации: {e}")
            import traceback
            debug_log(traceback.format_exc())
            raise

    def init_servers_panel(self):
        self.server_info_card = ctk.CTkFrame(self.servers_panel, corner_radius=16, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.server_info_card.pack(fill="x", pady=(0, 15))

        self.name_var = ctk.StringVar(value=self.tr("server_not_selected"))
        self.host_var = ctk.StringVar(value="—")

        info_header = ctk.CTkFrame(self.server_info_card, fg_color="transparent")
        info_header.pack(fill="x", padx=25, pady=(20, 15))
        ctk.CTkLabel(info_header, text=self.tr("connection_info"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left")

        self.delete_btn = ctk.CTkButton(
            info_header, text=self.tr("btn_delete"), font=self.font_small,
            fg_color="transparent", text_color=DANGER_COLOR, hover_color=BORDER_COLOR,
            height=28, width=80, corner_radius=6, command=self.delete_current_server, state="disabled"
        )
        self.delete_btn.pack(side="right")

        details_frame = ctk.CTkFrame(self.server_info_card, fg_color="transparent")
        details_frame.pack(fill="x", padx=25, pady=(0, 20))

        name_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        name_row.pack(fill="x", pady=5)
        ctk.CTkLabel(name_row, text=self.tr("name"), font=self.font_main, text_color=TEXT_MUTED, anchor="w").pack(side="left")

        self._name_view_frame = ctk.CTkFrame(name_row, fg_color="transparent")
        self._name_view_frame.pack(side="left", padx=5)

        self._name_display_label = ctk.CTkLabel(
            self._name_view_frame, textvariable=self.name_var,
            font=self.font_bold, text_color=TEXT_MAIN
        )
        self._name_display_label.pack(side="left")

        self._rename_btn = ctk.CTkButton(
            self._name_view_frame, text=self.tr("rename_server"),
            font=self.font_small, fg_color="transparent",
            text_color=TEXT_MUTED, hover_color=BORDER_COLOR,
            width=24, height=24, corner_radius=6,
            command=self._start_rename, state="disabled"
        )
        self._rename_btn.pack(side="left", padx=(4, 0))

        self._name_edit_frame = ctk.CTkFrame(name_row, fg_color="transparent")

        self._name_entry = ctk.CTkEntry(
            self._name_edit_frame, font=self.font_bold,
            fg_color=SIDEBAR_COLOR, border_color=ACCENT_COLOR,
            text_color=TEXT_MAIN, width=180, height=28, corner_radius=6
        )
        self._name_entry.pack(side="left")
        self._name_entry.bind("<Return>", lambda e: self._confirm_rename())
        self._name_entry.bind("<Escape>", lambda e: self._cancel_rename())

        self._confirm_rename_btn = ctk.CTkButton(
            self._name_edit_frame, text=self.tr("rename_server_confirm"),
            font=self.font_bold, fg_color=SUCCESS_COLOR, hover_color="#059669",
            text_color=TEXT_MAIN, width=28, height=28, corner_radius=6,
            command=self._confirm_rename
        )
        self._confirm_rename_btn.pack(side="left", padx=(4, 0))

        self._cancel_rename_btn = ctk.CTkButton(
            self._name_edit_frame, text=self.tr("rename_server_cancel"),
            font=self.font_bold, fg_color="transparent",
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BORDER_COLOR,
            width=28, height=28, corner_radius=6,
            command=self._cancel_rename
        )
        self._cancel_rename_btn.pack(side="left", padx=(4, 0))

        host_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        host_row.pack(fill="x", pady=5)
        ctk.CTkLabel(host_row, text=self.tr("address"), font=self.font_main, text_color=TEXT_MUTED, anchor="w").pack(side="left")
        ctk.CTkLabel(host_row, textvariable=self.host_var, font=self.font_main, text_color=TEXT_MAIN).pack(side="left", padx=5)

        self.flag_label = ctk.CTkLabel(
            host_row, text="", font=ctk.CTkFont(family="Segoe UI", size=16),
            text_color=TEXT_MAIN
        )
        self.flag_label.pack(side="left", padx=(2, 0))

        self.hide_switch = ctk.CTkSwitch(
            host_row, text=self.tr("hide_ip"), font=self.font_small, text_color=TEXT_MUTED,
            variable=self.hide_host_var, command=self.update_host_display,
            onvalue=True, offvalue=False, switch_width=38, switch_height=20
        )
        self.hide_switch.pack(side="right")

        ping_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        ping_row.pack(fill="x", pady=(15, 5))
        self.ping_btn = ctk.CTkButton(
            ping_row, text=self.tr("check_ping"), font=self.font_main, height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            hover_color=SIDEBAR_COLOR, text_color=TEXT_MAIN, command=self.check_ping_thread, state="disabled"
        )
        self.ping_btn.pack(side="left")

        self.default_btn = ctk.CTkButton(
            ping_row, text=self.tr("set_default"), font=self.font_main, height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            hover_color=SIDEBAR_COLOR, text_color=DANGER_COLOR,
            command=self.set_current_as_default, state="disabled"
        )
        self.default_btn.pack(side="left", padx=10)

        self.ping_label = ctk.CTkLabel(ping_row, text="", font=self.font_bold)
        self.ping_label.pack(side="left", padx=10)

        self.status_card = ctk.CTkFrame(self.servers_panel, corner_radius=16, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.status_card.pack(fill="x", pady=(0, 15))

        self.status_connect_frame = ctk.CTkFrame(self.status_card, fg_color="transparent")
        self.status_connect_frame.pack(fill="x", padx=25, pady=(20, 20))

        self.status_label = ctk.CTkLabel(self.status_connect_frame, text=self.tr("status_disconnected"), font=self.font_title, text_color=TEXT_MUTED)
        self.status_label.pack(side="left")

        self.connect_btn = ctk.CTkButton(
            self.status_connect_frame, text=self.tr("btn_connect"), font=self.font_bold, fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER, height=50, width=220, corner_radius=10,
            command=self.toggle_connection, state="disabled"
        )
        self.connect_btn.pack(side="right")

        self.routing_card = ctk.CTkFrame(self.servers_panel, corner_radius=16, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.routing_card.pack(fill="both", expand=True, pady=(0, 15))

        route_header = ctk.CTkFrame(self.routing_card, fg_color="transparent")
        route_header.pack(fill="x", padx=25, pady=(20, 10))
        ctk.CTkLabel(route_header, text=self.tr("routing"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left")

        self.split_switch = ctk.CTkSwitch(
            route_header, text=self.tr("split_tunneling"), font=self.font_small, text_color=TEXT_MUTED,
            variable=self.split_tunnel_var, command=self.on_split_toggle,
            onvalue=True, offvalue=False, switch_width=38, switch_height=20
        )
        self.split_switch.pack(side="right")

        routes_control_frame = ctk.CTkFrame(self.routing_card, fg_color="transparent")
        routes_control_frame.pack(fill="x", padx=25, pady=(5, 10))

        self.routes_combo = ctk.CTkComboBox(
            routes_control_frame,
            values=[],
            command=self.on_routes_file_selected,
            width=250,
            height=32,
            fg_color=SIDEBAR_COLOR,
            border_color=BORDER_COLOR,
            border_width=1,
            button_color=BORDER_COLOR,
            button_hover_color=ACTIVE_ITEM_COLOR,
            dropdown_fg_color=SIDEBAR_COLOR,
            dropdown_hover_color=ACTIVE_ITEM_COLOR,
            dropdown_text_color=TEXT_MAIN,
            corner_radius=8,
            font=self.font_main,
            dropdown_font=self.font_main,
            state="readonly"
        )
        self.routes_combo.pack(side="left", padx=(0, 10))

        self.new_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("new_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, hover_color=SIDEBAR_COLOR,
            width=70, height=30, corner_radius=6, command=self.create_new_routes_file
        )
        self.new_routes_btn.pack(side="left", padx=2)

        self.delete_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("delete_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=DANGER_COLOR, hover_color=SIDEBAR_COLOR,
            width=70, height=30, corner_radius=6, command=self.delete_routes_file
        )
        self.delete_routes_btn.pack(side="left", padx=2)

        self.rename_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("rename_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, hover_color=SIDEBAR_COLOR,
            width=90, height=30, corner_radius=6, command=self.rename_routes_file
        )
        self.rename_routes_btn.pack(side="left", padx=2)

        self.routing_textbox = ctk.CTkTextbox(
            self.routing_card, font=self.font_main, fg_color=SIDEBAR_COLOR, text_color=TEXT_MAIN,
            corner_radius=10, border_width=1, border_color=BORDER_COLOR
        )
        self.routing_textbox.pack(fill="both", expand=True, padx=25, pady=(0, 25))

        def _routing_paste(event):
            try:
                text = self.clipboard_get()
                self.routing_textbox.insert("insert", text)
            except Exception:
                pass
            return "break"
        self.routing_textbox.bind("<Control-v>", _routing_paste)
        self.routing_textbox.bind("<Control-V>", _routing_paste)

    def init_settings_panel(self):
        top_frame = ctk.CTkFrame(self.settings_panel, fg_color="transparent")
        top_frame.pack(fill="x", pady=(0, 20))
        back_btn = ctk.CTkButton(
            top_frame, text=self.tr("back_to_servers"), font=self.font_main,
            fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=32, corner_radius=8,
            command=lambda: self.show_panel("servers")
        )
        back_btn.pack(side="left")
        ctk.CTkLabel(top_frame, text=self.tr("settings_title"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left", padx=20)

        settings_container = ctk.CTkFrame(self.settings_panel, fg_color=CARD_COLOR, corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        settings_container.pack(expand=True, fill="both", padx=0, pady=0)

        tabview = ctk.CTkTabview(
            settings_container,
            fg_color=CARD_COLOR,
            segmented_button_fg_color=SIDEBAR_COLOR,
            segmented_button_selected_color=ACCENT_COLOR,
            text_color=TEXT_MAIN
        )
        tabview.pack(expand=True, fill="both", padx=10, pady=10)

        try:
            tabview._segmented_button.configure(height=50)
            tabview._segmented_button.configure(font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"))
        except Exception as e:
            debug_log(f"Не удалось изменить стиль вкладок: {e}")

        tab_general = tabview.add(self.tr("tab_general"))
        tab_exceptions = tabview.add(self.tr("tab_exceptions"))
        tab_dns = tabview.add(self.tr("tab_dns"))

        switch = ctk.CTkSwitch(
            tab_general, text=self.tr("autostart"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.autostart_var, command=self.toggle_autostart, switch_width=38, switch_height=20
        )
        switch.pack(pady=(25, 15), padx=25, anchor="w")

        self.minimize_on_close_var = ctk.BooleanVar(value=self.minimize_on_close)
        minimize_switch = ctk.CTkSwitch(
            tab_general, text=self.tr("minimize_to_tray_on_close"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.minimize_on_close_var, command=self.toggle_minimize_on_close, switch_width=38, switch_height=20
        )
        minimize_switch.pack(pady=(0, 15), padx=25, anchor="w")

        debug_frame = ctk.CTkFrame(tab_general, fg_color="transparent")
        debug_frame.pack(fill="x", padx=25, pady=(0, 20))
        self.debug_mode_var = ctk.BooleanVar(value=self.app_settings.get("debug_mode", False))
        debug_switch = ctk.CTkSwitch(
            debug_frame, text=self.tr("debug_mode"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.debug_mode_var, command=self.toggle_debug_mode, switch_width=38, switch_height=20
        )
        debug_switch.pack(side="left")

        self.kill_switch_var = ctk.BooleanVar(value=self.app_settings.get("kill_switch", False))
        ks_switch = ctk.CTkSwitch(
            tab_general, text=self.tr("kill_switch"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.kill_switch_var, command=self.toggle_kill_switch_setting,
            switch_width=38, switch_height=20
        )
        ks_switch.pack(pady=(0, 15), padx=25, anchor="w")

        self.auto_reconnect_var = ctk.BooleanVar(value=self.app_settings.get("auto_reconnect", False))
        ar_switch = ctk.CTkSwitch(
            tab_general, text=self.tr("auto_reconnect"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.auto_reconnect_var, command=self.toggle_auto_reconnect_setting,
            switch_width=38, switch_height=20
        )
        ar_switch.pack(pady=(0, 15), padx=25, anchor="w")

        lang_frame = ctk.CTkFrame(tab_general, fg_color="transparent")
        lang_frame.pack(fill="x", padx=25, pady=(0, 20))
        ctk.CTkLabel(lang_frame, text=self.tr("language_label"), font=self.font_main, text_color=TEXT_MAIN).pack(side="left")
        self.lang_var = ctk.StringVar(value="Русский" if self.lang == "ru" else "English")
        lang_menu = ctk.CTkOptionMenu(
            lang_frame, variable=self.lang_var, values=["Русский", "English"], command=self.change_language,
            fg_color=SIDEBAR_COLOR, button_color=BORDER_COLOR, button_hover_color=ACTIVE_ITEM_COLOR,
            corner_radius=8
        )
        lang_menu.pack(side="right")

        btn_frame = ctk.CTkFrame(tab_general, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=(20, 25))
        logs_btn = ctk.CTkButton(
            btn_frame, text=self.tr("view_logs"), font=self.font_bold,
            fg_color="transparent", hover_color=SIDEBAR_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=38, corner_radius=8, command=self.view_logs
        )
        logs_btn.pack(side="left")

        tab_exceptions_scroll = ctk.CTkScrollableFrame(tab_exceptions, fg_color="transparent")
        tab_exceptions_scroll.pack(fill="both", expand=True)

        app_exceptions_frame = ctk.CTkFrame(tab_exceptions_scroll, fg_color="transparent", border_width=1, border_color=BORDER_COLOR, corner_radius=8)
        app_exceptions_frame.pack(fill="x", padx=25, pady=(25, 15))

        ctk.CTkLabel(app_exceptions_frame, text=self.tr("app_exceptions"), font=self.font_bold, text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(10, 5))
        ctk.CTkLabel(app_exceptions_frame, text=self.tr("app_exceptions_desc"), font=self.font_small, text_color=TEXT_MUTED).pack(anchor="w", padx=15, pady=(0, 10))

        self.app_exceptions_listbox = ctk.CTkScrollableFrame(app_exceptions_frame, fg_color=SIDEBAR_COLOR, height=150)
        self.app_exceptions_listbox.pack(fill="x", padx=15, pady=5)

        btn_frame_ex = ctk.CTkFrame(app_exceptions_frame, fg_color="transparent")
        btn_frame_ex.pack(fill="x", padx=15, pady=(5, 15))

        add_btn = ctk.CTkButton(
            btn_frame_ex, text=self.tr("add_app"), font=self.font_small,
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, height=34, corner_radius=8,
            command=self.show_add_app_menu
        )
        add_btn.pack(side="left", padx=(0, 10))

        self.remove_app_btn = ctk.CTkButton(
            btn_frame_ex, text=self.tr("remove_app"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=DANGER_COLOR, hover_color=SIDEBAR_COLOR, height=34, corner_radius=8,
            command=self.remove_app_exception, state="disabled"
        )
        self.remove_app_btn.pack(side="left")

        self.update_app_exceptions_ui()

        domain_exceptions_frame = ctk.CTkFrame(tab_exceptions_scroll, fg_color="transparent", border_width=1, border_color=BORDER_COLOR, corner_radius=8)
        domain_exceptions_frame.pack(fill="x", padx=25, pady=(0, 25))

        ctk.CTkLabel(domain_exceptions_frame, text=self.tr("domain_exceptions"), font=self.font_bold, text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(10, 5))
        ctk.CTkLabel(domain_exceptions_frame, text=self.tr("domain_exceptions_desc"), font=self.font_small, text_color=TEXT_MUTED).pack(anchor="w", padx=15, pady=(0, 10))

        self.domain_exceptions_listbox = ctk.CTkScrollableFrame(domain_exceptions_frame, fg_color=SIDEBAR_COLOR, height=120)
        self.domain_exceptions_listbox.pack(fill="x", padx=15, pady=5)

        btn_frame_dom = ctk.CTkFrame(domain_exceptions_frame, fg_color="transparent")
        btn_frame_dom.pack(fill="x", padx=15, pady=(5, 15))

        add_domain_btn = ctk.CTkButton(
            btn_frame_dom, text=self.tr("add_domain"), font=self.font_small,
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, height=34, corner_radius=8,
            command=self.add_domain_exception
        )
        add_domain_btn.pack(side="left", padx=(0, 10))

        self.remove_domain_btn = ctk.CTkButton(
            btn_frame_dom, text=self.tr("remove_domain"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=DANGER_COLOR, hover_color=SIDEBAR_COLOR, height=34, corner_radius=8,
            command=self.remove_domain_exception, state="disabled"
        )
        self.remove_domain_btn.pack(side="left")

        self.update_domain_exceptions_ui()

        dns_inner_frame = ctk.CTkFrame(tab_dns, fg_color="transparent", border_width=1, border_color=BORDER_COLOR, corner_radius=8)
        dns_inner_frame.pack(fill="x", padx=25, pady=(25, 25))

        ctk.CTkLabel(dns_inner_frame, text=self.tr("dns_settings"), font=self.font_bold, text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(10, 5))

        type_frame = ctk.CTkFrame(dns_inner_frame, fg_color="transparent")
        type_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(type_frame, text=self.tr("dns_type"), font=self.font_main, text_color=TEXT_MUTED).pack(side="left")
        self.dns_type_var = ctk.StringVar(value=self.app_settings.get("dns_type", "system"))
        dns_type_menu = ctk.CTkOptionMenu(
            type_frame, variable=self.dns_type_var,
            values=[self.tr("dns_system"), self.tr("dns_doh"), self.tr("dns_dot")],
            fg_color=SIDEBAR_COLOR, button_color=BORDER_COLOR, button_hover_color=ACTIVE_ITEM_COLOR,
            width=150, corner_radius=8
        )
        dns_type_menu.pack(side="right")

        addr_frame = ctk.CTkFrame(dns_inner_frame, fg_color="transparent")
        addr_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(addr_frame, text=self.tr("dns_server_address"), font=self.font_main, text_color=TEXT_MUTED).pack(side="left")
        self.dns_addr_var = ctk.StringVar(value=self.app_settings.get("dns_server", "https://1.1.1.1/dns-query"))
        self.dns_addr_entry = ctk.CTkEntry(addr_frame, textvariable=self.dns_addr_var, fg_color=SIDEBAR_COLOR, border_color=BORDER_COLOR, corner_radius=8)
        self.dns_addr_entry.pack(side="right", fill="x", expand=True, padx=(10, 0))

        self.dns_proxy_var = ctk.BooleanVar(value=self.app_settings.get("dns_through_proxy", True))
        dns_proxy_check = ctk.CTkCheckBox(
            dns_inner_frame, text=self.tr("dns_through_proxy"), variable=self.dns_proxy_var,
            font=self.font_small, text_color=TEXT_MAIN
        )
        dns_proxy_check.pack(anchor="w", padx=15, pady=5)

        self.dns_test_btn = ctk.CTkButton(
            dns_inner_frame, text=self.tr("dns_test"), font=self.font_small,
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, height=34, corner_radius=8,
            text_color=TEXT_MAIN
        )
        self.dns_test_btn.pack(anchor="w", padx=15, pady=(0, 10))
        self.dns_test_label = ctk.CTkLabel(dns_inner_frame, text="", font=self.font_small, text_color=TEXT_MUTED)
        self.dns_test_label.pack(anchor="w", padx=15, pady=(0, 10))

        def update_dns_fields(*args):
            selected = self.dns_type_var.get()
            if selected == self.tr("dns_system"):
                self.dns_addr_entry.configure(state="disabled")
                dns_proxy_check.configure(state="disabled")
                self.dns_test_btn.configure(state="disabled")
            else:
                self.dns_addr_entry.configure(state="normal")
                dns_proxy_check.configure(state="normal")
                self.dns_test_btn.configure(state="normal")
        self.dns_type_var.trace_add("write", update_dns_fields)
        update_dns_fields()

        def test_dns():
            dns_type = self.dns_type_var.get()
            if dns_type == self.tr("dns_system"):
                self.dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
                return
            server = self.dns_addr_var.get().strip()
            if not server:
                self.dns_test_label.configure(text=self.tr("dns_invalid_address"), text_color=DANGER_COLOR)
                return
            try:
                if dns_type == self.tr("dns_doh"):
                    response = requests.get(server, params={"name": "example.com", "type": "A"}, timeout=3)
                    if response.status_code == 200:
                        self.dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
                    else:
                        self.dns_test_label.configure(text=self.tr("dns_test_fail"), text_color=DANGER_COLOR)
                elif dns_type == self.tr("dns_dot"):
                    import ssl
                    context = ssl.create_default_context()
                    host = server.replace("tls://", "")
                    with socket.create_connection((host, 853), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            self.dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
            except Exception:
                self.dns_test_label.configure(text=self.tr("dns_test_fail"), text_color=DANGER_COLOR)
        self.dns_test_btn.configure(command=test_dns)

    def init_import_panel(self):
        top_frame = ctk.CTkFrame(self.import_panel, fg_color="transparent")
        top_frame.pack(fill="x", pady=(0, 20))
        back_btn = ctk.CTkButton(
            top_frame, text=self.tr("back_to_servers"), font=self.font_main,
            fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=32, corner_radius=8, command=lambda: self.show_panel("servers")
        )
        back_btn.pack(side="left")
        ctk.CTkLabel(top_frame, text=self.tr("import_title"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left", padx=20)

        container = ctk.CTkFrame(self.import_panel, fg_color=CARD_COLOR, corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        container.pack(expand=True, fill="both", padx=0, pady=0)

        btn1 = ctk.CTkButton(
            container, text=self.tr("import_file"), font=self.font_bold, fg_color=SIDEBAR_COLOR, hover_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=42, corner_radius=8, command=self.import_sites_from_file
        )
        btn1.pack(pady=(25, 15), padx=25, fill="x")

        btn2 = ctk.CTkButton(
            container, text=self.tr("import_clipboard"), font=self.font_bold, fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER,
            height=42, corner_radius=8, command=self.add_from_clipboard
        )
        btn2.pack(padx=25, fill="x")

    def show_panel(self, panel_name):
        if panel_name == "servers":
            self.servers_panel.pack(fill="both", expand=True)
            self.settings_panel.pack_forget()
            self.import_panel.pack_forget()
            self.current_panel = "servers"
        elif panel_name == "settings":
            self.servers_panel.pack_forget()
            self.settings_panel.pack(fill="both", expand=True)
            self.import_panel.pack_forget()
            self.current_panel = "settings"
        elif panel_name == "import":
            self.servers_panel.pack_forget()
            self.settings_panel.pack_forget()
            self.import_panel.pack(fill="both", expand=True)
            self.current_panel = "import"

    def show_settings_panel(self):
        self.show_panel("settings")

    def show_import_panel(self):
        self.show_panel("import")

    def refresh_routes_list(self):
        try:
            files = [f for f in os.listdir(ROUTES_DIR) if f.endswith('.txt')]
            if not files:
                default_file = "routes.txt"
                default_path = os.path.join(ROUTES_DIR, default_file)
                if not os.path.exists(default_path):
                    with open(default_path, 'w', encoding='utf-8') as f:
                        f.write("instagram.com\ntwitter.com\n2ip.ru")
                files = [default_file]
            self.routes_list = sorted(files)
            self.routes_combo.configure(values=self.routes_list)
            if self.current_routes_file not in self.routes_list:
                self.current_routes_file = self.routes_list[0]
            self.routes_combo.set(self.current_routes_file)
        except Exception as e:
            print(f"Ошибка обновления списка маршрутов: {e}")

    def on_routes_file_selected(self, choice):
        if choice != self.current_routes_file:
            self.save_current_routes()
            self.current_routes_file = choice
            self.load_routes_from_file(choice)
            self.restart_proxy_if_needed()

    def load_routes_from_file(self, filename):
        filepath = os.path.join(ROUTES_DIR, filename)
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                self.routing_textbox.delete("1.0", "end")
                self.routing_textbox.insert("1.0", content)
            else:
                self.routing_textbox.delete("1.0", "end")
        except Exception as e:
            print(f"Ошибка загрузки маршрутов из {filename}: {e}")

    def save_current_routes(self):
        self.save_routes_to_file(self.current_routes_file)

    def save_routes_to_file(self, filename):
        os.makedirs(ROUTES_DIR, exist_ok=True)
        filepath = os.path.join(ROUTES_DIR, filename)
        try:
            content = self.routing_textbox.get("1.0", "end-1c").strip()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"Ошибка сохранения маршрутов в {filename}: {e}")

    def create_new_routes_file(self):
        name = simpledialog.askstring(self.tr("new_routes_file"), self.tr("enter_name"),
                                      parent=self, initialvalue="new_list.txt")
        if not name:
            return
        if not name.endswith('.txt'):
            name += '.txt'
        if name in self.routes_list:
            messagebox.showerror(self.tr("error"), f"Файл {name} уже существует.")
            return
        filepath = os.path.join(ROUTES_DIR, name)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("")
            self.refresh_routes_list()
            self.save_current_routes()
            self.current_routes_file = name
            self.routes_combo.set(name)
            self.routing_textbox.delete("1.0", "end")
            self.restart_proxy_if_needed()
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось создать файл: {e}")

    def delete_routes_file(self):
        if len(self.routes_list) <= 1:
            messagebox.showerror(self.tr("error"), self.tr("cannot_delete_last"))
            return
        confirm = messagebox.askyesno(self.tr("confirm_delete"),
                                      self.tr("confirm_delete_text").format(self.current_routes_file))
        if not confirm:
            return
        filepath = os.path.join(ROUTES_DIR, self.current_routes_file)
        try:
            os.remove(filepath)
            self.refresh_routes_list()
            self.current_routes_file = self.routes_list[0]
            self.routes_combo.set(self.current_routes_file)
            self.load_routes_from_file(self.current_routes_file)
            self.restart_proxy_if_needed()
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось удалить файл: {e}")

    def rename_routes_file(self):
        old_name = self.current_routes_file
        new_name = simpledialog.askstring(self.tr("rename_routes_file"), self.tr("enter_name"),
                                          parent=self, initialvalue=old_name)
        if not new_name or new_name == old_name:
            return
        if not new_name.endswith('.txt'):
            new_name += '.txt'
        if new_name in self.routes_list:
            messagebox.showerror(self.tr("error"), f"Файл {new_name} уже существует.")
            return
        old_path = os.path.join(ROUTES_DIR, old_name)
        new_path = os.path.join(ROUTES_DIR, new_name)
        try:
            os.rename(old_path, new_path)
            self.refresh_routes_list()
            self.current_routes_file = new_name
            self.routes_combo.set(new_name)
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось переименовать файл: {e}")

    def restart_proxy_if_needed(self):
        if self.proxy_process is not None and self.selected_server_index != -1:
            self.stop_proxy()
            self.toggle_connection()

    def show_add_app_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label=self.tr("add_app_by_path"), command=self.add_app_exception_by_path)
        menu.add_command(label=self.tr("add_app_by_name"), command=self.add_app_exception_by_name)
        menu.post(self.winfo_pointerx(), self.winfo_pointery())

    def add_app_exception_by_path(self):
        filepath = filedialog.askopenfilename(
            title=self.tr("select_exe"),
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if not filepath:
            return
        for app in self.app_exceptions:
            if app.get("type") == "path" and app["value"].lower() == filepath.lower():
                return
        self.app_exceptions.append({
            "type": "path",
            "value": filepath,
            "name": os.path.basename(filepath)
        })
        self.save_app_exceptions()
        self.update_app_exceptions_ui()
        self.restart_proxy_if_needed()

    def add_app_exception_by_name(self):
        name = simpledialog.askstring(self.tr("add_app_by_name"), self.tr("enter_process_name"), parent=self)
        if not name:
            return
        name = name.strip()
        if not name.endswith('.exe'):
            name += '.exe'
        for app in self.app_exceptions:
            if app.get("type") == "name" and app["value"].lower() == name.lower():
                return
        self.app_exceptions.append({
            "type": "name",
            "value": name,
            "name": name
        })
        self.save_app_exceptions()
        self.update_app_exceptions_ui()
        self.restart_proxy_if_needed()

    def remove_app_exception(self):
        selected = self.get_selected_app_exception()
        if selected is None:
            return
        confirm = messagebox.askyesno(self.tr("confirm_delete"), f"Удалить исключение для {selected['name']}?")
        if confirm:
            self.app_exceptions.remove(selected)
            self.save_app_exceptions()
            self.update_app_exceptions_ui()
            self.restart_proxy_if_needed()

    def get_selected_app_exception(self):
        if hasattr(self, 'selected_app_index') and self.selected_app_index is not None and 0 <= self.selected_app_index < len(self.app_exceptions):
            return self.app_exceptions[self.selected_app_index]
        return None

    def update_app_exceptions_ui(self):
        for widget in self.app_exceptions_listbox.winfo_children():
            widget.destroy()
        if not self.app_exceptions:
            label = ctk.CTkLabel(self.app_exceptions_listbox, text="Нет исключений", font=self.font_small, text_color=TEXT_MUTED)
            label.pack(pady=10)
            self.remove_app_btn.configure(state="disabled")
            self.selected_app_index = None
            return

        self.selected_app_index = None
        for idx, app in enumerate(self.app_exceptions):
            frame = ctk.CTkFrame(self.app_exceptions_listbox, fg_color="transparent")
            frame.pack(fill="x", padx=5, pady=2)
            if app["type"] == "path":
                display_text = f"[Путь] {app['name']}"
            else:
                display_text = f"[Имя] {app['value']}"
            btn = ctk.CTkButton(
                frame, text=display_text, font=self.font_main,
                fg_color="transparent", hover_color=ACTIVE_ITEM_COLOR,
                anchor="w", height=30, corner_radius=6,
                command=lambda i=idx: self.select_app_exception(i)
            )
            btn.pack(side="left", fill="x", expand=True)
        self.remove_app_btn.configure(state="disabled")

    def select_app_exception(self, index):
        self.selected_app_index = index
        for i, frame in enumerate(self.app_exceptions_listbox.winfo_children()):
            if isinstance(frame, ctk.CTkFrame):
                for child in frame.winfo_children():
                    if isinstance(child, ctk.CTkButton):
                        if i == index:
                            child.configure(fg_color=ACTIVE_ITEM_COLOR)
                        else:
                            child.configure(fg_color="transparent")
        self.remove_app_btn.configure(state="normal")

    def save_app_exceptions(self):
        self.app_settings["app_exceptions"] = self.app_exceptions
        self.save_app_settings()

    def _normalize_domain_for_config(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not domain:
            return ""
        if domain.startswith('.'):
            domain = domain[1:]
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            pass
        return '.' + domain

    def _normalize_domain_for_storage(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not domain:
            return ""
        if not domain.startswith('.'):
            domain = '.' + domain
        return domain

    def add_domain_exception(self):
        domain = simpledialog.askstring(
            self.tr("add_domain"),
            self.tr("enter_domain"),
            parent=self
        )
        if not domain:
            return
        domain = domain.strip()
        if not domain:
            return
        norm_domain = self._normalize_domain_for_storage(domain)
        punycode_norm = self._normalize_domain_for_config(norm_domain)
        for existing in self.domain_exceptions:
            existing_puny = self._normalize_domain_for_config(existing)
            if existing_puny == punycode_norm:
                return
        self.domain_exceptions.append(norm_domain)
        self.save_domain_exceptions()
        self.update_domain_exceptions_ui()
        self.restart_proxy_if_needed()

    def remove_domain_exception(self):
        if not hasattr(self, 'selected_domain_index') or self.selected_domain_index is None:
            return
        if 0 <= self.selected_domain_index < len(self.domain_exceptions):
            domain = self.domain_exceptions[self.selected_domain_index]
            confirm = messagebox.askyesno(self.tr("confirm_delete"), f"Удалить исключение для домена {domain}?")
            if confirm:
                del self.domain_exceptions[self.selected_domain_index]
                self.selected_domain_index = None
                self.save_domain_exceptions()
                self.update_domain_exceptions_ui()
                self.restart_proxy_if_needed()

    def update_domain_exceptions_ui(self):
        for widget in self.domain_exceptions_listbox.winfo_children():
            widget.destroy()
        if not self.domain_exceptions:
            label = ctk.CTkLabel(self.domain_exceptions_listbox, text=self.tr("no_domain_exceptions"), font=self.font_small, text_color=TEXT_MUTED)
            label.pack(pady=10)
            self.remove_domain_btn.configure(state="disabled")
            self.selected_domain_index = None
            return

        self.selected_domain_index = None
        for idx, domain in enumerate(self.domain_exceptions):
            frame = ctk.CTkFrame(self.domain_exceptions_listbox, fg_color="transparent")
            frame.pack(fill="x", padx=5, pady=2)
            btn = ctk.CTkButton(
                frame, text=domain, font=self.font_main,
                fg_color="transparent", hover_color=ACTIVE_ITEM_COLOR,
                anchor="w", height=30, corner_radius=6,
                command=lambda i=idx: self.select_domain_exception(i)
            )
            btn.pack(side="left", fill="x", expand=True)
        self.remove_domain_btn.configure(state="disabled")

    def select_domain_exception(self, index):
        self.selected_domain_index = index
        for i, frame in enumerate(self.domain_exceptions_listbox.winfo_children()):
            if isinstance(frame, ctk.CTkFrame):
                for child in frame.winfo_children():
                    if isinstance(child, ctk.CTkButton):
                        child.configure(fg_color=ACTIVE_ITEM_COLOR if i == index else "transparent")
        self.remove_domain_btn.configure(state="normal")

    def save_domain_exceptions(self):
        self.app_settings["domain_exceptions"] = self.domain_exceptions
        self.save_app_settings()

    def refresh_all_server_colors(self):
        default_name = self.app_settings.get("default_server", "")
        for i, label in enumerate(self.server_name_labels):
            if i >= len(self.servers):
                continue
            is_default = self.servers[i]["name"] == default_name
            is_connected = (self.proxy_process is not None and self.connected_server_index == i)
            if is_connected:
                color = SUCCESS_COLOR
            elif is_default:
                color = DEFAULT_MARKER_COLOR
            else:
                color = TEXT_MAIN
            label.configure(text_color=color)

    def set_current_as_default(self):
        if self.selected_server_index != -1:
            server_name = self.servers[self.selected_server_index]["name"]
            current_default = self.app_settings.get("default_server", "")
            if current_default == server_name:
                self.app_settings["default_server"] = ""
                self.default_btn.configure(text_color=DANGER_COLOR)
            else:
                self.app_settings["default_server"] = server_name
                self.default_btn.configure(text_color=SUCCESS_COLOR)
            self.save_app_settings()
            self.update_server_list()

    def set_current_as_default_from_tray(self, icon, item):
        self.after(0, self.set_current_as_default)

    def select_default_server_on_start(self):
        default_name = self.app_settings.get("default_server")
        if default_name:
            for i, server in enumerate(self.servers):
                if server["name"] == default_name:
                    self.select_server(i)
                    break

    def build_tray_menu(self):
        server_items = []
        default_name = self.app_settings.get("default_server", "")
        for i, s in enumerate(self.servers):
            def make_callback(idx):
                return lambda icon, item: self.after(0, self.select_server, idx)
            def make_checked_condition(idx):
                return lambda item: self.selected_server_index == idx
            display_name = s["name"]
            server_items.append(
                pystray.MenuItem(
                    display_name[:35] + ("..." if len(display_name) > 35 else ""),
                    make_callback(i),
                    checked=make_checked_condition(i),
                    radio=True
                )
            )
        if not server_items:
            server_items.append(pystray.MenuItem("Пусто", lambda icon, item: None, enabled=False))
        def is_not_connected(item):
            return self.proxy_process is None and self.selected_server_index != -1
        def is_connected(item):
            return self.proxy_process is not None
        def get_status_text(item):
            return "Статус: Подключено" if self.proxy_process is not None else "Статус: Отключено"
        return pystray.Menu(
            pystray.MenuItem(get_status_text, lambda icon, item: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Подключиться", self.connect_from_tray, enabled=is_not_connected),
            pystray.MenuItem("Отключиться", self.disconnect_from_tray, enabled=is_connected),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self.tr("app_name"), pystray.Menu(*server_items)),
            pystray.MenuItem(
                self.tr("set_default"),
                self.set_current_as_default_from_tray,
                checked=lambda item: (self.selected_server_index != -1 and 
                                     self.servers[self.selected_server_index]["name"] == self.app_settings.get("default_server", ""))
            ),
            pystray.MenuItem(
                self.tr("split_tunneling"),
                self.toggle_routing_from_tray,
                checked=lambda item: self.split_tunnel_var.get()
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self.tr("tray_open"), self.show_window, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self.tr("tray_exit"), self.quit_app)
        )

    def update_tray_menu(self):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.menu = self.build_tray_menu()
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass
            self.after(200, self._delayed_tray_update)

    def _delayed_tray_update(self):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass

    def create_tray_icon(self):
        menu = self.build_tray_menu()
        self.tray_icon = pystray.Icon("MinimalProxyClient", self.icon_off, self.tr("title"), menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def hide_window(self):
        if self.minimize_on_close:
            self.withdraw()
        else:
            self.cleanup_and_exit()

    def _on_map(self, event=None):
        self.update_idletasks()
        self.update()

    def _on_window_configure(self, event):
        if event.widget is not self:
            return
        if self._resize_job is not None:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(80, self._on_resize_done)

    def _on_resize_done(self):
        self._resize_job = None
        self.update_idletasks()

    def _patch_scrollable_frames(self):
        targets = []
        for attr in ("server_list_frame", "app_exceptions_listbox", "domain_exceptions_listbox"):
            frame = getattr(self, attr, None)
            if frame is not None:
                targets.append(frame)

        for frame in targets:
            canvas = getattr(frame, "_parent_canvas", None)
            if canvas is None:
                continue
            _job = [None]
            _orig_bindings = canvas.bind("<Configure>")

            def _make_debounced(c, j, orig):
                def _debounced(event):
                    if j[0] is not None:
                        try:
                            c.after_cancel(j[0])
                        except Exception:
                            pass
                    def _do():
                        j[0] = None
                        bbox = c.bbox("all")
                        if bbox:
                            c.configure(scrollregion=bbox)
                    j[0] = c.after(80, _do)
                return _debounced

            canvas.unbind("<Configure>")
            canvas.bind("<Configure>", _make_debounced(canvas, _job, _orig_bindings))

    def show_window(self, icon=None, item=None):
        def _show():
            self.deiconify()
            self.update_idletasks()
            self.update()
            self.lift()
            self.focus_force()
        self.after(0, _show)

    def quit_app(self, icon=None, item=None):
        self.after(0, self.cleanup_and_exit)

    def cleanup_and_exit(self, exit=True):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.visible = False
            self.tray_icon.stop()
        set_system_proxy(False)
        self.save_current_routes()
        self.save_app_settings()
        if self.proxy_process:
            self.stop_proxy()
        if exit:
            self.quit()
            self.destroy()
            os._exit(0)

    def restart_app(self):
        self.cleanup_and_exit(exit=False)
        python = sys.executable
        os.execl(python, python, *sys.argv)

    def connect_from_tray(self, icon, item):
        self.after(0, self.toggle_connection)

    def disconnect_from_tray(self, icon, item):
        self.after(0, self.stop_proxy)

    def toggle_routing_from_tray(self, icon, item):
        self.after(0, self._toggle_routing_internal)

    def _toggle_routing_internal(self):
        current_state = self.split_tunnel_var.get()
        self.split_tunnel_var.set(not current_state)
        self.toggle_split_state()
        self.save_app_settings()
        self.restart_proxy_if_needed()

    def tr(self, key):
        return TRANSLATIONS.get(self.lang, TRANSLATIONS["ru"]).get(key, key)

    def load_app_settings(self):
        default_settings = {
            "split_tunneling": True,
            "language": "ru",
            "default_server": "",
            "window_geometry": None,
            "window_state": "normal",
            "dns_type": "system",
            "dns_server": "https://1.1.1.1/dns-query",
            "dns_through_proxy": True,
            "app_exceptions": [],
            "domain_exceptions": [],
            "minimize_on_close": True,
            "debug_mode": False,
            "kill_switch": False,
            "auto_reconnect": False
        }
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    default_settings.update(loaded)
            except Exception:
                pass
        return default_settings

    def save_app_settings(self):
        self.app_settings["split_tunneling"] = self.split_tunnel_var.get()
        self.app_settings["minimize_on_close"] = self.minimize_on_close
        try:
            geometry = self.geometry()
            self.app_settings["window_geometry"] = geometry
            self.app_settings["window_state"] = self.state()
        except Exception:
            pass
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.app_settings, f, indent=4)
            _restrict_file_acl(SETTINGS_FILE)
        except Exception:
            pass

    def toggle_minimize_on_close(self):
        self.minimize_on_close = self.minimize_on_close_var.get()
        self.save_app_settings()

    def toggle_debug_mode(self):
        global DEBUG_ENABLED
        self.app_settings["debug_mode"] = self.debug_mode_var.get()
        DEBUG_ENABLED = self.app_settings["debug_mode"]
        self.save_app_settings()
        debug_log(f"Режим отладки {'включён' if DEBUG_ENABLED else 'выключен'} пользователем")

    def toggle_kill_switch_setting(self):
        self.kill_switch_enabled = self.kill_switch_var.get()
        self.app_settings["kill_switch"] = self.kill_switch_enabled
        self.save_app_settings()
        debug_log(f"Kill Switch {'включён' if self.kill_switch_enabled else 'выключен'} пользователем")

    def toggle_auto_reconnect_setting(self):
        self.auto_reconnect_enabled = self.auto_reconnect_var.get()
        self.app_settings["auto_reconnect"] = self.auto_reconnect_enabled
        self.save_app_settings()
        debug_log(f"Авто-переключение серверов {'включено' if self.auto_reconnect_enabled else 'выключено'} пользователем")

    def center_window(self, window, width, height):
        x = int((self.winfo_screenwidth() / 2) - (width / 2))
        y = int((self.winfo_screenheight() / 2) - (height / 2))
        window.geometry(f"{width}x{height}+{x}+{y}")

    def delete_current_server(self):
        if self.selected_server_index != -1:
            if self.proxy_process:
                self.stop_proxy()
            name_to_del = self.servers[self.selected_server_index]["name"]
            if self.app_settings.get("default_server") == name_to_del:
                self.app_settings["default_server"] = ""
                self.save_app_settings()
            del self.servers[self.selected_server_index]
            self.save_servers_to_file()
            self.selected_server_index = -1
            self.name_var.set(self.tr("server_not_selected"))
            self.host_var.set("—")
            self.ping_label.configure(text="")
            self.connect_btn.configure(state="disabled")
            self.ping_btn.configure(state="disabled")
            self.delete_btn.configure(state="disabled")
            self.default_btn.configure(state="disabled")
            self.update_server_list()

    def view_logs(self):
        log_path = os.path.abspath(LOG_FILE)
        if os.path.exists(log_path):
            if os.name == 'nt':
                os.startfile(log_path)
            else:
                try:
                    subprocess.call(['xdg-open', log_path])
                except Exception:
                    pass
        else:
            messagebox.showinfo(self.tr("log_not_found"), self.tr("log_not_found"))

    def change_language(self, choice):
        self.app_settings["language"] = "ru" if choice == "Русский" else "en"
        self.save_app_settings()
        self.restart_app()

    def save_dns_and_restart(self):
        selected_type = self.dns_type_var.get()
        if selected_type == self.tr("dns_system"):
            self.app_settings["dns_type"] = "system"
        elif selected_type == self.tr("dns_doh"):
            self.app_settings["dns_type"] = "doh"
        elif selected_type == self.tr("dns_dot"):
            self.app_settings["dns_type"] = "dot"
        self.app_settings["dns_server"] = self.dns_addr_var.get().strip()
        self.app_settings["dns_through_proxy"] = self.dns_proxy_var.get()
        self.save_app_settings()
        if self.proxy_process is not None:
            self.restart_proxy_if_needed()
        else:
            messagebox.showinfo(self.tr("settings_title"), self.tr("dns_apply_restart"))
        self.show_panel("servers")

    def import_sites_from_file(self):
        filepath = filedialog.askopenfilename(
            title=self.tr("select_file"), filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                base_name = os.path.splitext(os.path.basename(filepath))[0]
                new_name = base_name + ".txt"
                counter = 1
                while new_name in self.routes_list:
                    new_name = f"{base_name}_{counter}.txt"
                    counter += 1

                self.save_current_routes()

                new_path = os.path.join(ROUTES_DIR, new_name)
                with open(new_path, 'w', encoding='utf-8') as f:
                    f.write(content.strip())

                self.refresh_routes_list()
                self.current_routes_file = new_name
                self.routes_combo.set(new_name)

                self.routing_textbox.configure(state="normal", fg_color=SIDEBAR_COLOR)
                self.routing_textbox.delete("1.0", "end")
                self.routing_textbox.insert("1.0", content.strip())
                self.toggle_split_state()
                self.restart_proxy_if_needed()
            except Exception:
                pass
        self.show_panel("servers")

    def check_ping_thread(self):
        if self.selected_server_index == -1:
            return
        self.ping_btn.configure(state="disabled")
        self._start_ping_animation()
        server = self.servers[self.selected_server_index]
        threading.Thread(target=self._perform_tcp_ping, args=(server['host'], server['port']), daemon=True).start()

    def _start_ping_animation(self):
        self._stop_ping_animation()
        dots_seq   = ["·", "··", "···", "··"]
        colors_seq = ["#A1A1AA", "#C4C4CC", "#E4E4EB", "#C4C4CC"]
        interval   = 320

        def _tick():
            idx = self._ping_anim_phase % len(dots_seq)
            try:
                self.ping_label.configure(
                    text=f"{self.tr('ping_checking')} {dots_seq[idx]}",
                    text_color=colors_seq[idx]
                )
            except Exception:
                return
            self._ping_anim_phase = idx + 1
            self._ping_anim_after_id = self.after(interval, _tick)
        _tick()

    def _stop_ping_animation(self):
        if self._ping_anim_after_id is not None:
            try:
                self.after_cancel(self._ping_anim_after_id)
            except Exception:
                pass
            self._ping_anim_after_id = None
        self._ping_anim_phase = 0

    def _fade_ping_result(self, text, target_color, steps=12, interval=20):
        BG = CARD_COLOR

        def _lerp(c1, c2, t):
            r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
            r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
            return f"#{int(r1+(r2-r1)*t):02X}{int(g1+(g2-g1)*t):02X}{int(b1+(b2-b1)*t):02X}"

        try:
            current_color = self.ping_label.cget("text_color")
            if not (isinstance(current_color, str) and current_color.startswith("#")):
                current_color = "#A1A1AA"
        except Exception:
            current_color = "#A1A1AA"
        current_text = self.ping_label.cget("text")

        def _fade_out(i):
            t = i / steps
            try:
                self.ping_label.configure(text=current_text, text_color=_lerp(current_color, BG, t))
            except Exception:
                return
            if i < steps:
                self.after(interval, lambda: _fade_out(i + 1))
            else:
                self.after(interval, lambda: _fade_in(0))

        def _fade_in(i):
            t = i / steps
            try:
                self.ping_label.configure(text=text, text_color=_lerp(BG, target_color, t))
            except Exception:
                return
            if i < steps:
                self.after(interval, lambda: _fade_in(i + 1))

        _fade_out(0)

    def _perform_tcp_ping(self, host, port, timeout=3):
        try:
            start_time = time.time()
            with socket.create_connection((host, int(port)), timeout=timeout):
                ms = round((time.time() - start_time) * 1000)
            self.after(0, lambda: self._update_ping_ui(ms))
        except:
            self.after(0, lambda: self._update_ping_ui(-1))

    def _update_ping_ui(self, ms):
        self._stop_ping_animation()
        self.ping_btn.configure(state="normal")
        if ms == -1:
            self._fade_ping_result(self.tr("status_error"), DANGER_COLOR)
        else:
            color = SUCCESS_COLOR if ms < 150 else ("#F59E0B" if ms < 300 else DANGER_COLOR)
            self._fade_ping_result(f"{ms} ms", color)

    def update_host_display(self):
        if self.selected_server_index == -1:
            return
        server = self.servers[self.selected_server_index]
        port = server.get('port', '')
        if self.hide_host_var.get():
            self.host_var.set("••••••••••••")
            self._hide_flag_label()
        else:
            self.host_var.set(f"{server['host']}:{port}")
            self._refresh_flag_for_current_server()

    def _hide_flag_label(self):
        if hasattr(self.flag_label, '_flag_img_ref'):
            delattr(self.flag_label, '_flag_img_ref')
        self.flag_label.configure(image=None, text="")
        if self.flag_label.winfo_ismapped():
            self.flag_label.pack_forget()

    def _show_flag_label(self):
        if not self.flag_label.winfo_ismapped():
            self.flag_label.pack(side="left", padx=(2, 0))

    def _refresh_flag_for_current_server(self):
        if self.selected_server_index == -1:
            return
        if self.hide_host_var.get():
            self._hide_flag_label()
            return
        host = self.servers[self.selected_server_index].get("host", "")
        if not host:
            return
        if host in self._country_cache:
            cc, ctk_img = self._country_cache[host]
            if ctk_img is not None:
                self._show_flag_label()
                self.flag_label.configure(image=ctk_img, text="")
                self.flag_label._flag_img_ref = ctk_img
            elif cc:
                self._show_flag_label()
                self.flag_label.configure(image=None, text=f"[{cc}]", text_color=TEXT_MUTED)
            else:
                self._hide_flag_label()
        else:
            self._flag_seq += 1
            _seq = self._flag_seq
            threading.Thread(
                target=self._fetch_server_country,
                args=(host, self.selected_server_index, _seq),
                daemon=True
            ).start()

    def _fetch_server_country(self, host: str, server_index: int, seq: int = 0):
        if host in self._country_cache:
            self.after(0, lambda e=self._country_cache[host]: self._update_flag_label(server_index, seq, e))
            return
        try:
            try:
                resolved_ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            except Exception:
                resolved_ip = host

            resp = requests.get(
                f"http://ip-api.com/json/{resolved_ip}?fields=countryCode",
                timeout=5
            )
            cc = resp.json().get("countryCode", "")

            ctk_img = None
            if cc:
                try:
                    flag_resp = requests.get(
                        f"https://flagcdn.com/28x21/{cc.lower()}.png",
                        timeout=5
                    )
                    pil_img = Image.open(BytesIO(flag_resp.content)).convert("RGBA")
                    ctk_img = ctk.CTkImage(
                        light_image=pil_img,
                        dark_image=pil_img,
                        size=(20, 14)
                    )
                except Exception as fe:
                    debug_log(f"Ошибка загрузки флага {cc}: {fe}")

            entry = (cc, ctk_img)
            self._country_cache[host] = entry
            self.after(0, lambda e=entry: self._update_flag_label(server_index, seq, e))
        except Exception as e:
            debug_log(f"Ошибка получения страны для {host}: {e}")

    def _update_flag_label(self, server_index: int, seq: int, entry):
        if self.selected_server_index != server_index:
            return
        if getattr(self, '_flag_seq', 0) != seq:
            return
        if self.hide_host_var.get():
            self._hide_flag_label()
            return
        cc, ctk_img = entry
        try:
            if ctk_img is not None:
                self._show_flag_label()
                self.flag_label.configure(image=ctk_img, text="")
                self.flag_label._flag_img_ref = ctk_img
            elif cc:
                self._show_flag_label()
                self.flag_label.configure(image=None, text=f"[{cc}]",
                                          text_color=TEXT_MUTED)
            else:
                self._hide_flag_label()
        except Exception:
            pass

    def toggle_split_state(self):
        if self.split_tunnel_var.get():
            self.routing_textbox.configure(state="normal", fg_color=SIDEBAR_COLOR)
            self.routes_combo.configure(state="readonly")
            self.new_routes_btn.configure(state="normal")
            self.delete_routes_btn.configure(state="normal")
            self.rename_routes_btn.configure(state="normal")
        else:
            self.routing_textbox.configure(state="disabled", fg_color=BG_COLOR)
            self.routes_combo.configure(state="disabled")
            self.new_routes_btn.configure(state="disabled")
            self.delete_routes_btn.configure(state="disabled")
            self.rename_routes_btn.configure(state="disabled")
        self.update_tray_menu()

    def on_split_toggle(self):
        self.save_current_routes()
        self.toggle_split_state()
        self.save_app_settings()
        self.restart_proxy_if_needed()

    def load_servers_from_file(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "rb") as f:
                    raw = f.read()
                try:
                    wrapper = json.loads(raw)
                    if isinstance(wrapper, dict) and wrapper.get("enc") == "dpapi":
                        ciphertext = base64.b64decode(wrapper["data"])
                        plaintext  = _dpapi_decrypt(ciphertext)
                        self.servers = json.loads(plaintext.decode("utf-8"))
                    else:
                        self.servers = wrapper if isinstance(wrapper, list) else []
                except Exception:
                    self.servers = []
                self.update_server_list()
            except Exception:
                pass

    def save_servers_to_file(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        plaintext  = json.dumps(self.servers, indent=4, ensure_ascii=False).encode("utf-8")
        ciphertext = _dpapi_encrypt(plaintext)
        wrapper    = {"enc": "dpapi", "data": base64.b64encode(ciphertext).decode("ascii")}
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(wrapper, f)
        _restrict_file_acl(DB_FILE)

    def load_routes(self):
        self.load_routes_from_file(self.current_routes_file)

    def save_routes(self):
        self.save_current_routes()

    def add_from_clipboard(self):
        try:
            raw = self.clipboard_get().strip()
            if not raw:
                return

            if raw.startswith(("vless://", "hysteria2://")):
                server = self.parse_single_link(raw)
                if server:
                    self.servers.append(server)
                    self.save_servers_to_file()
                    self.update_server_list()
                    self.show_panel("servers")
                else:
                    messagebox.showerror(self.tr("error"), "Не удалось распарсить ссылку из буфера.")
            elif raw.startswith(("http://", "https://")):
                threading.Thread(target=self.fetch_and_import_from_url, args=(raw,), daemon=True).start()
            else:
                messagebox.showerror(self.tr("error"), "Неизвестный формат в буфере обмена.")
        except Exception as e:
            debug_log(f"Ошибка при добавлении из буфера: {e}")

    def fetch_and_import_from_url(self, url):
        try:
            response = requests.get(url, timeout=15, allow_redirects=False)

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                if location.startswith(("vless://", "hysteria2://")):
                    server = self.parse_single_link(location)
                    if server:
                        self.servers.append(server)
                        self.after(0, self._finish_import_from_url)
                    else:
                        self.after(0, lambda: messagebox.showerror(self.tr("error"), "Не удалось распарсить ссылку из редиректа."))
                    return
                elif location.startswith(("http://", "https://")):
                    self.fetch_and_import_from_url(location)
                    return

            response.raise_for_status()
            content = response.text

            links = self._extract_links_from_text(content)
            if not links:
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    links = self._extract_links_from_text(decoded)
                except:
                    pass

            added = 0
            for link in links:
                server = self.parse_single_link(link)
                if server:
                    self.servers.append(server)
                    added += 1

            if added == 0:
                self.after(0, lambda: messagebox.showerror(self.tr("error"), "Не найдено ни одной подходящей ссылки."))
            else:
                self.after(0, self._finish_import_from_url)
        except Exception as e:
            debug_log(f"Ошибка загрузки URL: {e}")
            self.after(0, lambda: messagebox.showerror(self.tr("error"), f"Не удалось загрузить URL: {str(e)}"))

    def _extract_links_from_text(self, text):
        pattern = r'(vless://[^\s]+|hysteria2://[^\s]+)'
        matches = re.findall(pattern, text)
        return matches

    def _finish_import_from_url(self):
        self.save_servers_to_file()
        self.update_server_list()
        self.show_panel("servers")

    def parse_single_link(self, link, source=None):
        if not (link.startswith("vless://") or link.startswith("hysteria2://")):
            return None
        try:
            parsed = urllib.parse.urlparse(link)
            protocol = parsed.scheme
            params = dict(urllib.parse.parse_qsl(parsed.query))
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else parsed.hostname
            server = {
                "type": protocol,
                "name": name,
                "host": parsed.hostname,
                "port": parsed.port,
                "params": params
            }
            if protocol == "vless":
                server["uuid"] = parsed.username
            elif protocol == "hysteria2":
                server["password"] = parsed.username
            if source:
                server["source"] = source
            return server
        except Exception as e:
            debug_log(f"Ошибка парсинга ссылки {link}: {e}")
            return None

    def update_server_list(self):
        for frame in self.server_frames:
            frame.destroy()
        self.server_frames.clear()
        self.server_name_labels.clear()

        default_name = self.app_settings.get("default_server", "")

        for i, s in enumerate(self.servers):
            server_frame = ctk.CTkFrame(self.server_list_frame, fg_color="transparent", height=38)
            server_frame.pack(pady=4, fill="x")
            server_frame.pack_propagate(False)

            inner_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
            inner_frame.pack(fill="both", expand=True, padx=8, pady=4)

            name_label = ctk.CTkLabel(
                inner_frame,
                text=s["name"],
                font=self.font_main,
                text_color=TEXT_MAIN,
                anchor="w"
            )
            name_label.pack(side="left", fill="x", expand=True)

            self.server_frames.append(server_frame)
            self.server_name_labels.append(name_label)

            def make_select_callback(idx):
                return lambda event=None: self.select_server(idx)
            server_frame.bind("<Button-1>", make_select_callback(i))
            name_label.bind("<Button-1>", make_select_callback(i))
            inner_frame.bind("<Button-1>", make_select_callback(i))

        if self.selected_server_index != -1 and self.selected_server_index < len(self.server_frames):
            self.highlight_server(self.selected_server_index, True)
        else:
            for frame in self.server_frames:
                frame.configure(fg_color="transparent")

        self.refresh_all_server_colors()
        self.update_tray_menu()

    def highlight_server(self, index, highlight=True):
        if 0 <= index < len(self.server_frames):
            if highlight:
                self.server_frames[index].configure(fg_color=ACTIVE_ITEM_COLOR)
            else:
                self.server_frames[index].configure(fg_color="transparent")

    def select_server(self, index):
        if self.selected_server_index != -1 and self.selected_server_index < len(self.server_frames):
            self.highlight_server(self.selected_server_index, False)
        self.selected_server_index = index
        if index >= 0 and index < len(self.server_frames):
            self.highlight_server(index, True)
        s = self.servers[index]
        self.name_var.set(s["name"])
        self.ping_label.configure(text="")
        self.update_host_display()

        if self.proxy_process is not None and self.connected_server_index == index:
            self.server_info_card.configure(border_color=CONNECTED_BORDER_COLOR)
        else:
            self.server_info_card.configure(border_color=BORDER_COLOR)

        self._refresh_flag_for_current_server()

        if self.app_settings.get("default_server") == s["name"]:
            self.default_btn.configure(text_color=SUCCESS_COLOR, state="normal")
        else:
            self.default_btn.configure(text_color=DANGER_COLOR, state="normal")
        self.connect_btn.configure(state="normal")
        self.ping_btn.configure(state="normal")
        self.delete_btn.configure(state="normal")
        self._rename_btn.configure(state="normal")
        self._cancel_rename()
        self.update_tray_menu()

    def _start_rename(self):
        if self.selected_server_index == -1:
            return
        current_name = self.servers[self.selected_server_index]["name"]
        self._name_view_frame.pack_forget()
        self._name_entry.delete(0, "end")
        self._name_entry.insert(0, current_name)
        self._name_edit_frame.pack(side="left", padx=5)
        self._name_entry.focus_set()
        self._name_entry.select_range(0, "end")

    def _confirm_rename(self):
        if self.selected_server_index == -1:
            self._cancel_rename()
            return
        new_name = self._name_entry.get().strip()
        if not new_name:
            self._cancel_rename()
            return
        old_name = self.servers[self.selected_server_index]["name"]
        self.servers[self.selected_server_index]["name"] = new_name
        if self.app_settings.get("default_server") == old_name:
            self.app_settings["default_server"] = new_name
        self.name_var.set(new_name)
        self.save_servers_to_file()
        self.save_app_settings()
        self.update_server_list()
        self._cancel_rename()

    def _cancel_rename(self):
        try:
            self._name_edit_frame.pack_forget()
            self._name_view_frame.pack(side="left", padx=5)
        except Exception:
            pass

    def get_dns_config(self):
        dns_type = self.app_settings.get("dns_type", "system")
        if dns_type == "system":
            return {}

        server_address = self.app_settings.get("dns_server", "")
        if not server_address:
            return {}

        if dns_type == "doh":
            if not server_address.startswith("https://"):
                server_address = "https://" + server_address
            if not server_address.endswith("/dns-query"):
                if not server_address.endswith("/"):
                    server_address += "/"
                server_address += "dns-query"
        elif dns_type == "dot":
            if not server_address.startswith("tls://"):
                server_address = "tls://" + server_address

        dns_through_proxy = self.app_settings.get("dns_through_proxy", True)
        server_config = {
            "tag": "custom_dns",
            "address": server_address,
        }
        if dns_through_proxy:
            server_config["detour"] = "proxy"

        return {
            "servers": [server_config],
            "rules": [
                {
                    "outbound": "any",
                    "server": "custom_dns"
                }
            ]
        }

    def generate_singbox_config(self, server):
        p = server["params"]
        protocol_type = server.get("type", "vless")
        route_rules = []

        for app in self.app_exceptions:
            rule = {"outbound": "direct"}
            if app["type"] == "path":
                rule["process_path"] = app["value"]
            else:
                rule["process_name"] = app["value"]
            route_rules.append(rule)

        if self.domain_exceptions:
            suffixes = []
            for d in self.domain_exceptions:
                try:
                    clean = d.lstrip('.')
                    try:
                        puny = clean.encode('idna').decode('ascii')
                    except Exception:
                        puny = clean
                    suffixes.append('.' + puny)
                except Exception:
                    suffixes.append(d)
            if suffixes:
                route_rules.append({
                    "outbound": "direct",
                    "domain_suffix": suffixes
                })

        is_split = self.split_tunnel_var.get()
        final_outbound = "direct" if is_split else "proxy"
        if is_split:
            raw_routes = self.routing_textbox.get("1.0", "end-1c").strip()
            domains, ips = [], []
            items = [x.strip() for x in raw_routes.replace(',', '\n').split('\n') if x.strip()]
            for item in items:
                try:
                    if '/' in item:
                        ipaddress.ip_network(item, strict=False)
                        ips.append(item)
                    else:
                        ipaddress.ip_address(item)
                        ips.append(item + "/32")
                except:
                    domains.append(item)
            if domains or ips:
                rule = {"outbound": "proxy"}
                if domains:
                    rule["domain_suffix"] = domains
                if ips:
                    rule["ip_cidr"] = ips
                route_rules.append(rule)

        if protocol_type == "hysteria2":
            main_outbound = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": server["host"],
                "server_port": server["port"],
                "password": server.get("password", ""),
                "tls": {
                    "enabled": True,
                    "server_name": p.get("sni", ""),
                    "insecure": p.get("insecure", "0") == "1"
                }
            }
        else:
            main_outbound = {
                "type": "vless",
                "tag": "proxy",
                "server": server["host"],
                "server_port": server["port"],
                "uuid": server.get("uuid", ""),
                "packet_encoding": "xudp",
                "flow": p.get("flow", ""),
                "tls": {
                    "enabled": True,
                    "server_name": p.get("sni", ""),
                    "utls": {"enabled": True, "fingerprint": p.get("fp", "chrome")},
                    "reality": {
                        "enabled": True,
                        "public_key": p.get("pbk", ""),
                        "short_id": p.get("sid", "")
                    } if p.get("security") == "reality" else None
                }
            }
        config = {
            "log": {"level": "info", "output": LOG_FILE},
            "inbounds": [{
                "type": "mixed", "listen": "127.0.0.1",
                "listen_port": self._proxy_port,
                "sniff": True, "sniff_override_destination": True
            }],
            "outbounds": [
                main_outbound,
                {"type": "direct", "tag": "direct"}
            ],
            "route": {"rules": route_rules, "final": final_outbound, "auto_detect_interface": True}
        }
        dns_config = self.get_dns_config()
        if dns_config:
            config["dns"] = dns_config

        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        _restrict_file_acl(CONFIG_FILE)

    def toggle_connection(self):
        if self.selected_server_index == -1 and self.proxy_process is None:
            return
        if self.proxy_process is None:
            self.connect_btn.configure(state="disabled")
            self._show_connecting()
            threading.Thread(target=self._connect_worker, daemon=True).start()
        else:
            self.stop_proxy()

    def _cancel_status_fade(self):
        if self._status_fade_id is not None:
            try:
                self.after_cancel(self._status_fade_id)
            except Exception:
                pass
            self._status_fade_id = None
        self._status_fade_step = 0

    def _stop_animation(self):
        if self._anim_after_id is not None:
            try:
                self.after_cancel(self._anim_after_id)
            except Exception:
                pass
            self._anim_after_id = None
        self._anim_phase = 0

    def _fade_status_step(self, current_text, start_color, end_color, steps, step, interval,
                          new_text, target_color, background_color, after_fade_in_callback):
        t = step / steps
        r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
        r2, g2, b2 = int(end_color[1:3], 16), int(end_color[3:5], 16), int(end_color[5:7], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        color = f"#{r:02X}{g:02X}{b:02X}"
        self.status_label.configure(text=current_text, text_color=color)

        if step == steps:
            if end_color == background_color:
                self.status_label.configure(text=new_text, text_color=background_color)
                self._start_status_fade(new_text, background_color, target_color, steps, interval,
                                        after_fade_in_callback)
            else:
                if after_fade_in_callback:
                    after_fade_in_callback()
            return

        self._status_fade_id = self.after(interval, lambda: self._fade_status_step(
            current_text, start_color, end_color, steps, step + 1, interval,
            new_text, target_color, background_color, after_fade_in_callback
        ))

    def _start_status_fade(self, current_text, current_color, target_color, steps, interval,
                           after_fade_in_callback):
        self._status_fade_step = 0
        self._status_fade_id = self.after(interval, lambda: self._fade_status_step(
            current_text, current_color, target_color, steps, 0, interval,
            current_text, target_color, CARD_COLOR, after_fade_in_callback
        ))

    def smooth_status_transition(self, new_text, target_color, duration=300, after_fade_in_callback=None):
        self._stop_animation()
        self._cancel_status_fade()

        current_text = self.status_label.cget("text")
        current_color = self.status_label.cget("text_color")
        background_color = CARD_COLOR

        steps = 20
        interval = int(duration / (2 * steps))

        self._fade_status_step(current_text, current_color, background_color, steps, 0, interval,
                               new_text, target_color, background_color, after_fade_in_callback)

    def _show_connecting(self):
        def start_connecting_animation():
            self._start_connecting_animation()
        self.smooth_status_transition(self.tr("status_connecting"), TEXT_MUTED,
                                      after_fade_in_callback=start_connecting_animation)

    def _start_connecting_animation(self):
        self._stop_animation()
        dots_seq   = ["·", "··", "···", "··"]
        colors_seq = ["#A1A1AA", "#C4C4CC", "#E4E4EB", "#C4C4CC"]
        interval   = 380

        def _tick():
            idx = self._anim_phase % len(dots_seq)
            label_text = f"{self.tr('status_connecting')} {dots_seq[idx]}"
            color      = colors_seq[idx]
            try:
                self.status_label.configure(text=label_text, text_color=color)
            except Exception:
                return
            self._anim_phase += 1
            self._anim_after_id = self.after(interval, _tick)

        _tick()

    def _start_connected_animation(self):
        self._stop_animation()

        import math

        flash_steps = 6
        flash_interval = 50

        pulse_steps = 36
        pulse_interval = 55

        def _lerp_color(c1, c2, t):
            r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
            r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
            r = int(r1 + (r2 - r1) * t)
            g = int(g1 + (g2 - g1) * t)
            b = int(b1 + (b2 - b1) * t)
            return f"#{r:02X}{g:02X}{b:02X}"

        FLASH_START = "#FFFFFF"
        PULSE_BRIGHT = "#6EE7B7"
        PULSE_DIM    = "#059669"
        FINAL        = SUCCESS_COLOR

        label_text = self.tr("status_connected")

        def _flash_tick(step=0):
            if step >= flash_steps:
                _pulse_tick(0)
                return
            t = step / (flash_steps - 1)
            color = _lerp_color(FLASH_START, FINAL, t)
            try:
                self.status_label.configure(text=label_text, text_color=color)
            except Exception:
                return
            self._anim_phase += 1
            self._anim_after_id = self.after(flash_interval, lambda: _flash_tick(step + 1))

        def _pulse_tick(step=0):
            if step >= pulse_steps:
                try:
                    self.status_label.configure(text=label_text, text_color=FINAL)
                except Exception:
                    pass
                self._anim_after_id = None
                return
            t = (math.sin(2 * math.pi * step / 12) + 1) / 2
            color = _lerp_color(PULSE_DIM, PULSE_BRIGHT, t)
            try:
                self.status_label.configure(text=label_text, text_color=color)
            except Exception:
                return
            self._anim_phase += 1
            self._anim_after_id = self.after(pulse_interval, lambda: _pulse_tick(step + 1))

        _flash_tick(0)

    def _connect_worker(self):
        try:
            server = self.servers[self.selected_server_index]
            self.generate_singbox_config(server)
            time.sleep(0.2)
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            creation_flags = subprocess.CREATE_NO_WINDOW
            sb_path = resource_path("sing-box.exe")
            self.proxy_process = subprocess.Popen(
                [sb_path, "run", "-c", CONFIG_FILE],
                startupinfo=si,
                creationflags=creation_flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True
            )

            connected = False
            deadline = time.time() + 15
            while time.time() < deadline:
                if self.proxy_process.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", self._proxy_port), timeout=1):
                        connected = True
                        break
                except OSError:
                    time.sleep(0.5)

            if connected:
                set_system_proxy(True, port=self._proxy_port)
                _safe_delete_config()
                self.after(0, self._on_connected)
            else:
                try:
                    self.proxy_process.terminate()
                    self.proxy_process.wait(timeout=3)
                except Exception:
                    pass
                self.proxy_process = None
                _safe_delete_config()
                self.after(0, self._on_connect_failed)

        except Exception as e:
            self.proxy_process = None
            debug_log(f"Ошибка подключения: {e}")
            try:
                import traceback
                _get_error_logger().error(f"Ошибка запуска прокси: {e}\n{traceback.format_exc()}")
            except Exception:
                pass
            _safe_delete_config()
            self.after(0, self._on_connect_failed)

    def _on_connected(self):
        self.connected_server_index = self.selected_server_index
        self._auto_reconnect_attempts = 0
        self._no_network = False
        set_kill_switch(False)
        def start_connected_anim():
            self._start_connected_animation()
        self.smooth_status_transition(self.tr("status_connected"), SUCCESS_COLOR,
                                      after_fade_in_callback=start_connected_anim)
        self.connect_btn.configure(
            text=self.tr("btn_disconnect"), state="normal",
            fg_color=DANGER_COLOR, hover_color=DANGER_HOVER
        )
        if self.selected_server_index == self.connected_server_index:
            self.server_info_card.configure(border_color=CONNECTED_BORDER_COLOR)
        if hasattr(self, 'tray_icon'):
            self.tray_icon.icon = self.icon_on
        self.update_tray_menu()
        self.refresh_all_server_colors()
        self._monitor_stop_event.clear()
        threading.Thread(target=self._monitor_proxy, daemon=True).start()
        threading.Thread(target=self._monitor_network, daemon=True).start()

    def _monitor_proxy(self):
        while True:
            if self._monitor_stop_event.wait(timeout=1.0):
                break
            proc = self.proxy_process
            if proc is None:
                break
            if proc.poll() is not None:
                debug_log("Процесс sing-box неожиданно завершился, устанавливаем статус Ошибка")
                set_system_proxy(False)
                self.proxy_process = None
                self._monitor_stop_event.set()
                self.after(0, self._on_proxy_died)
                break

    def _on_proxy_died(self):
        self.connected_server_index = -1
        if self.auto_reconnect_enabled and len(self.servers) > 1:
            if self._try_next_server():
                return
        if self.kill_switch_enabled:
            set_kill_switch(True)
            self.smooth_status_transition(self.tr("kill_switch_activated"), DANGER_COLOR)
        else:
            self.smooth_status_transition(self.tr("status_error"), DANGER_COLOR)
        self.connect_btn.configure(
            text=self.tr("btn_connect"), state="normal",
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER
        )
        self.server_info_card.configure(border_color=BORDER_COLOR)
        if hasattr(self, 'tray_icon'):
            self.tray_icon.icon = self.icon_off
        self.update_tray_menu()
        self.refresh_all_server_colors()

    def _on_connect_failed(self):
        self.connected_server_index = -1
        if self.auto_reconnect_enabled and len(self.servers) > 1:
            if self._try_next_server():
                return
        self.smooth_status_transition(self.tr("status_error"), DANGER_COLOR)
        self.connect_btn.configure(
            text=self.tr("btn_connect"), state="normal",
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER
        )
        self.server_info_card.configure(border_color=BORDER_COLOR)
        self.update_tray_menu()
        self.refresh_all_server_colors()

    def stop_proxy(self):
        self._stop_animation()
        self._monitor_stop_event.set()
        set_system_proxy(False)
        set_kill_switch(False)
        if self.proxy_process:
            self.proxy_process.terminate()
            self.proxy_process.wait()
            self.proxy_process = None
        self.connected_server_index = -1
        self._auto_reconnect_attempts = 0
        self._no_network = False
        self.smooth_status_transition(self.tr("status_disconnected"), TEXT_MUTED)
        self.connect_btn.configure(text=self.tr("btn_connect"), fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER)
        self.server_info_card.configure(border_color=BORDER_COLOR)
        if hasattr(self, 'tray_icon'):
            self.tray_icon.icon = self.icon_off
        self.update_tray_menu()
        self.refresh_all_server_colors()

    def _try_next_server(self):
        max_attempts = len(self.servers)
        if self._auto_reconnect_attempts >= max_attempts:
            self._auto_reconnect_attempts = 0
            debug_log("Авто-переключение: все серверы перебраны, подключение не удалось")
            return False
        self._auto_reconnect_attempts += 1
        next_index = (self.selected_server_index + 1) % len(self.servers)
        debug_log(f"Авто-переключение: попытка {self._auto_reconnect_attempts}/{max_attempts}, сервер #{next_index}")
        self.smooth_status_transition(
            f"{self.tr('status_connecting')} [{self._auto_reconnect_attempts}/{max_attempts}]",
            TEXT_MUTED
        )
        self.select_server(next_index)
        self.after(800, self.toggle_connection)
        return True

    def _check_internet(self):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False

    def _monitor_network(self):
        while True:
            if self._monitor_stop_event.wait(timeout=5.0):
                break
            if self.proxy_process is None:
                break
            has_net = self._check_internet()
            if not has_net and not self._no_network:
                self._no_network = True
                debug_log("Сеть недоступна — обновляем статус")
                self.after(0, lambda: self.smooth_status_transition(
                    self.tr("status_no_network"), DANGER_COLOR
                ))
            elif has_net and self._no_network:
                self._no_network = False
                debug_log("Сеть восстановлена — обновляем статус")
                def _restore_status():
                    def start_anim():
                        self._start_connected_animation()
                    self.smooth_status_transition(
                        self.tr("status_connected"), SUCCESS_COLOR,
                        after_fade_in_callback=start_anim
                    )
                self.after(0, _restore_status)

    def get_app_path(self):
        if getattr(sys, 'frozen', False):
            return sys.executable
        return os.path.abspath(sys.argv[0])

    def check_autostart(self):
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "TaaClient")
                return value == self.get_app_path()
        except WindowsError:
            return False

    def toggle_autostart(self):
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                if self.autostart_var.get():
                    winreg.SetValueEx(key, "TaaClient", 0, winreg.REG_SZ, self.get_app_path())
                else:
                    try:
                        winreg.DeleteValue(key, "TaaClient")
                    except FileNotFoundError:
                        pass
        except Exception:
            pass список доменов и IP-адресов, которые направляются через прокси.
- Поддержка нескольких списков маршрутизации (создание, переименование, удаление).
- Настройки: автозапуск, выбор языка (русский/английский), DNS (системный, DoH, DoT) с опцией направления через прокси.
- Сворачивание в системный трей с меню для быстрого переключения серверов и управления.
- Все данные (серверы, настройки, списки маршрутов, логи) хранятся в папке рядом с исполняемым файлом (портативный режим).

Используемые технологии:
- customtkinter — современный GUI на основе tkinter.
- pystray — иконка в системном трее.
- dnspython / requests — тестирование DNS.
- subprocess — запуск и остановка sing-box (ядро прокси).
- winreg — управление системным прокси Windows.
- pyinstaller — для сборки в один .exe.

Версия: 1.1
Автор: Bububebe0
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import subprocess
import json
import os
import sys
import urllib.parse
import ctypes
import winreg
import ipaddress
import threading
import socket
import time
import pystray
from PIL import Image
import dns.resolver
import dns.name

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def data_path(relative_path=""):
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_DATA_DIR = data_path()
DATA_DIR = data_path("data")
DB_FILE = data_path("data/servers.json")
SETTINGS_FILE = data_path("data/settings.json")
CONFIG_FILE = data_path("data/config.json")
ROUTES_DIR = data_path("list")
LOG_FILE = data_path("proxy.log")

BG_COLOR = "#09090B"
SIDEBAR_COLOR = "#18181B"
CARD_COLOR = "#18181B"
BORDER_COLOR = "#27272A"
ACCENT_COLOR = "#4F46E5"
ACCENT_HOVER = "#4338CA"
SUCCESS_COLOR = "#10B981"
DANGER_COLOR = "#EF4444"
DANGER_HOVER = "#DC2626"
TEXT_MAIN = "#F8FAFC"
TEXT_MUTED = "#A1A1AA"
ACTIVE_ITEM_COLOR = "#27272A"

TRANSLATIONS = {
    "ru": {
        "title": "Taa Client | Vless Hysteria2 [1.1]",
        "app_name": "Сервера",
        "add_from_clipboard": "➕ Из буфера",
        "import_configs": "Импорт конфигов",
        "btn_exit": "Выйти из приложения",
        "settings": "Настройки",
        "connection_info": "Информация о соединении",
        "name": "Название:",
        "address": "Адрес:",
        "hide_ip": "Скрыть IP",
        "check_ping": "📡 Пинг",
        "set_default": "⭐ По умолчанию",
        "default_marker": " (дефолт)",
        "btn_delete": "Удалить",
        "routing": "Маршрутизация",
        "split_tunneling": "Сплит-туннелирование",
        "status_disconnected": "Отключено",
        "status_connected": "Подключено",
        "status_error": "❌ Ошибка",
        "btn_connect": "Подключиться",
        "btn_disconnect": "Отключиться",
        "ping_checking": "Проверка...",
        "server_not_selected": "Сервер не выбран",
        "settings_title": "Настройки",
        "autostart": "Автозапуск при старте Windows",
        "language_label": "Язык интерфейса:",
        "view_logs": "Посмотреть логи",
        "restart_app": "Перезагрузить",
        "import_title": "Импорт конфигураций",
        "import_file": "Импорт сайтов из файла",
        "import_clipboard": "VLESS/Hysteria2 из буфера",
        "select_file": "Выберите файл со списком сайтов",
        "log_not_found": "Файл логов пока не создан.",
        "tray_open": "Развернуть окно",
        "tray_exit": "Выйти",
        "new_routes_file": "Новый список",
        "delete_routes_file": "Удалить",
        "rename_routes_file": "Переименовать",
        "enter_name": "Введите имя",
        "confirm_delete": "Удалить список",
        "confirm_delete_text": "Вы уверены, что хотите удалить список '{0}'?",
        "error": "Ошибка",
        "cannot_delete_last": "Нельзя удалить единственный список маршрутизации.",
        "dns_settings": "Настройки DNS",
        "dns_type": "Тип DNS:",
        "dns_system": "Системный DNS",
        "dns_doh": "DNS over HTTPS (DoH)",
        "dns_dot": "DNS over TLS (DoT)",
        "dns_server_address": "Адрес сервера:",
        "dns_through_proxy": "Направлять DNS через прокси",
        "dns_test": "Проверить DNS",
        "dns_test_success": "DNS работает",
        "dns_test_fail": "DNS не отвечает",
        "dns_invalid_address": "Некорректный адрес DNS",
        "dns_apply_restart": "Изменения DNS вступят в силу после перезапуска прокси."
    },
    "en": {
        "title": "Minimal Proxy Client [1.2]",
        "app_name": "Servers",
        "add_from_clipboard": "➕ From Clipboard",
        "import_configs": "Import Configs",
        "btn_exit": "Quit Application",
        "settings": "Settings",
        "connection_info": "Connection Info",
        "name": "Name:",
        "address": "Address:",
        "hide_ip": "Hide IP",
        "check_ping": "📡 Ping",
        "set_default": "⭐ Set Default",
        "default_marker": " (default)",
        "btn_delete": "Delete",
        "routing": "Routing",
        "split_tunneling": "Split Tunneling",
        "status_disconnected": "Disconnected",
        "status_connected": "Connected",
        "status_error": "❌ Error",
        "btn_connect": "Connect",
        "btn_disconnect": "Disconnect",
        "ping_checking": "Checking...",
        "server_not_selected": "No server selected",
        "settings_title": "Settings",
        "autostart": "Launch on Windows startup",
        "language_label": "Interface Language:",
        "view_logs": "View Logs",
        "restart_app": "Restart Application",
        "import_title": "Import Configurations",
        "import_file": "Import sites from file",
        "import_clipboard": "VLESS/Hysteria2 from clipboard",
        "select_file": "Select file with site list",
        "log_not_found": "Log file not created yet.",
        "tray_open": "Open Window",
        "tray_exit": "Quit",
        "new_routes_file": "New list",
        "delete_routes_file": "Delete",
        "rename_routes_file": "Rename",
        "enter_name": "Enter name",
        "confirm_delete": "Delete list",
        "confirm_delete_text": "Are you sure you want to delete list '{0}'?",
        "error": "Error",
        "cannot_delete_last": "Cannot delete the only routing list.",
        "dns_settings": "DNS Settings",
        "dns_type": "DNS Type:",
        "dns_system": "System DNS",
        "dns_doh": "DNS over HTTPS (DoH)",
        "dns_dot": "DNS over TLS (DoT)",
        "dns_server_address": "Server Address:",
        "dns_through_proxy": "Route DNS through proxy",
        "dns_test": "Test DNS",
        "dns_test_success": "DNS works",
        "dns_test_fail": "DNS not responding",
        "dns_invalid_address": "Invalid DNS address",
        "dns_apply_restart": "DNS changes will take effect after proxy restart."
    }
}

class ProxyApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        os.makedirs(ROUTES_DIR, exist_ok=True)
        os.makedirs(DATA_DIR, exist_ok=True)

        self.app_settings = self.load_app_settings()
        self.lang = self.app_settings.get("language", "ru")

        self.title(self.tr("title"))

        try:
            self.iconbitmap(resource_path("ico.ico"))
        except Exception as e:
            print(f"Не удалось загрузить иконку окна: {e}")

        try:
            self.icon_on = Image.open(resource_path("ico.ico"))
            self.icon_off = Image.open(resource_path("off.ico"))
        except Exception:
            self.icon_on = Image.new('RGB', (64, 64), color=(79, 70, 229))
            self.icon_off = Image.new('RGB', (64, 64), color=(100, 100, 100))

        self.geometry("950x700")
        saved_geometry = self.app_settings.get("window_geometry")
        saved_state = self.app_settings.get("window_state", "normal")
        if saved_geometry:
            self.geometry(saved_geometry)
        else:
            self.center_window(self, 950, 700)
        if saved_state == "zoomed":
            self.state("zoomed")

        self.minsize(860, 620)
        self.configure(fg_color=BG_COLOR)

        self.proxy_process = None
        self.servers = []
        self.server_buttons = []
        self.selected_server_index = -1

        self.hide_host_var = ctk.BooleanVar(value=True)
        self.split_tunnel_var = ctk.BooleanVar(value=self.app_settings.get("split_tunneling", True))
        self.autostart_var = ctk.BooleanVar(value=self.check_autostart())

        self.font_title = ctk.CTkFont(family="Segoe UI", size=24, weight="bold")
        self.font_main = ctk.CTkFont(family="Segoe UI", size=14)
        self.font_bold = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")
        self.font_small = ctk.CTkFont(family="Segoe UI", size=12)

        self.current_routes_file = "routes.txt"
        self.routes_list = []

        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=SIDEBAR_COLOR)
        self.sidebar_frame.pack(side="left", fill="y")
        self.sidebar_frame.pack_propagate(False)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text=self.tr("app_name"), font=self.font_title, text_color=TEXT_MAIN)
        self.logo_label.pack(pady=(35, 25), padx=25, anchor="w")

        self.add_btn = ctk.CTkButton(
            self.sidebar_frame, text=self.tr("add_from_clipboard"), font=self.font_bold,
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, corner_radius=10, height=45,
            command=self.add_from_clipboard
        )
        self.add_btn.pack(pady=(0, 15), padx=20, fill="x")

        self.server_list_frame = ctk.CTkScrollableFrame(self.sidebar_frame, fg_color="transparent")
        self.server_list_frame.pack(pady=5, padx=10, fill="both", expand=True)

        self.btn_quit = ctk.CTkButton(
            self.sidebar_frame, text=self.tr("btn_exit"), font=self.font_main,
            fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=DANGER_COLOR, corner_radius=10, height=40, command=self.cleanup_and_exit
        )
        self.btn_quit.pack(side="bottom", pady=(5, 25), padx=20, fill="x")

        self.btn_settings = ctk.CTkButton(
            self.sidebar_frame, text=self.tr("settings"), font=self.font_main,
            fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, corner_radius=10, height=40, command=self.open_settings_dialog
        )
        self.btn_settings.pack(side="bottom", pady=(5, 5), padx=20, fill="x")

        self.btn_import = ctk.CTkButton(
            self.sidebar_frame, text=self.tr("import_configs"), font=self.font_main,
            fg_color="transparent", hover_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, corner_radius=10, height=40, command=self.open_import_dialog
        )
        self.btn_import.pack(side="bottom", pady=(15, 5), padx=20, fill="x")

        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(side="right", fill="both", expand=True, padx=35, pady=35)

        self.info_card = ctk.CTkFrame(self.main_frame, corner_radius=16, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.info_card.pack(fill="x", pady=(0, 25))

        self.name_var = ctk.StringVar(value=self.tr("server_not_selected"))
        self.host_var = ctk.StringVar(value="—")

        info_header = ctk.CTkFrame(self.info_card, fg_color="transparent")
        info_header.pack(fill="x", padx=25, pady=(20, 15))
        ctk.CTkLabel(info_header, text=self.tr("connection_info"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left")

        self.delete_btn = ctk.CTkButton(
            info_header, text=self.tr("btn_delete"), font=self.font_small,
            fg_color="transparent", text_color=DANGER_COLOR, hover_color=BORDER_COLOR,
            height=28, width=80, corner_radius=6, command=self.delete_current_server, state="disabled"
        )
        self.delete_btn.pack(side="right")

        details_frame = ctk.CTkFrame(self.info_card, fg_color="transparent")
        details_frame.pack(fill="x", padx=25, pady=(0, 20))

        name_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        name_row.pack(fill="x", pady=5)
        ctk.CTkLabel(name_row, text=self.tr("name"), font=self.font_main, text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
        ctk.CTkLabel(name_row, textvariable=self.name_var, font=self.font_bold, text_color=TEXT_MAIN).pack(side="left", fill="x", expand=True, padx=15)

        host_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        host_row.pack(fill="x", pady=5)
        ctk.CTkLabel(host_row, text=self.tr("address"), font=self.font_main, text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
        ctk.CTkLabel(host_row, textvariable=self.host_var, font=self.font_main, text_color=TEXT_MAIN).pack(side="left", padx=15)

        self.hide_switch = ctk.CTkSwitch(
            host_row, text=self.tr("hide_ip"), font=self.font_small, text_color=TEXT_MUTED,
            variable=self.hide_host_var, command=self.update_host_display,
            onvalue=True, offvalue=False, switch_width=38, switch_height=20
        )
        self.hide_switch.pack(side="right")

        ping_row = ctk.CTkFrame(details_frame, fg_color="transparent")
        ping_row.pack(fill="x", pady=(15, 5))
        self.ping_btn = ctk.CTkButton(
            ping_row, text=self.tr("check_ping"), font=self.font_main, height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            hover_color=SIDEBAR_COLOR, text_color=TEXT_MAIN, command=self.check_ping_thread, state="disabled"
        )
        self.ping_btn.pack(side="left")

        self.default_btn = ctk.CTkButton(
            ping_row, text=self.tr("set_default"), font=self.font_main, height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            hover_color=SIDEBAR_COLOR, text_color=DANGER_COLOR,
            command=self.set_current_as_default, state="disabled"
        )
        self.default_btn.pack(side="left", padx=10)

        self.ping_label = ctk.CTkLabel(ping_row, text="", font=self.font_bold)
        self.ping_label.pack(side="left", padx=10)

        self.status_connect_frame = ctk.CTkFrame(self.info_card, fg_color="transparent")
        self.status_connect_frame.pack(fill="x", padx=25, pady=(20, 20))

        self.status_label = ctk.CTkLabel(self.status_connect_frame, text=self.tr("status_disconnected"), font=self.font_title, text_color=TEXT_MUTED)
        self.status_label.pack(side="left")

        self.connect_btn = ctk.CTkButton(
            self.status_connect_frame, text=self.tr("btn_connect"), font=self.font_bold, fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER, height=50, width=220, corner_radius=10,
            command=self.toggle_connection, state="disabled"
        )
        self.connect_btn.pack(side="right")

        self.routing_card = ctk.CTkFrame(self.main_frame, corner_radius=16, fg_color=CARD_COLOR, border_width=1, border_color=BORDER_COLOR)
        self.routing_card.pack(fill="both", expand=True, pady=(0, 25))

        route_header = ctk.CTkFrame(self.routing_card, fg_color="transparent")
        route_header.pack(fill="x", padx=25, pady=(20, 10))
        ctk.CTkLabel(route_header, text=self.tr("routing"), font=self.font_bold, text_color=TEXT_MAIN).pack(side="left")

        self.split_switch = ctk.CTkSwitch(
            route_header, text=self.tr("split_tunneling"), font=self.font_small, text_color=TEXT_MUTED,
            variable=self.split_tunnel_var, command=self.on_split_toggle,
            onvalue=True, offvalue=False, switch_width=38, switch_height=20
        )
        self.split_switch.pack(side="right")

        routes_control_frame = ctk.CTkFrame(self.routing_card, fg_color="transparent")
        routes_control_frame.pack(fill="x", padx=25, pady=(5, 10))

        self.routes_combo = ctk.CTkComboBox(
            routes_control_frame,
            values=[],
            command=self.on_routes_file_selected,
            width=250,
            height=32,
            fg_color=SIDEBAR_COLOR,
            border_color=BORDER_COLOR,
            border_width=1,
            button_color=BORDER_COLOR,
            button_hover_color=ACTIVE_ITEM_COLOR,
            dropdown_fg_color=SIDEBAR_COLOR,
            dropdown_hover_color=ACTIVE_ITEM_COLOR,
            dropdown_text_color=TEXT_MAIN,
            corner_radius=8,
            font=self.font_main,
            dropdown_font=self.font_main,
            state="readonly"
        )
        self.routes_combo.pack(side="left", padx=(0, 10))

        self.new_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("new_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, hover_color=SIDEBAR_COLOR,
            width=70, height=30, corner_radius=6, command=self.create_new_routes_file
        )
        self.new_routes_btn.pack(side="left", padx=2)

        self.delete_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("delete_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=DANGER_COLOR, hover_color=SIDEBAR_COLOR,
            width=70, height=30, corner_radius=6, command=self.delete_routes_file
        )
        self.delete_routes_btn.pack(side="left", padx=2)

        self.rename_routes_btn = ctk.CTkButton(
            routes_control_frame, text=self.tr("rename_routes_file"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, hover_color=SIDEBAR_COLOR,
            width=90, height=30, corner_radius=6, command=self.rename_routes_file
        )
        self.rename_routes_btn.pack(side="left", padx=2)

        self.routing_textbox = ctk.CTkTextbox(
            self.routing_card, font=self.font_main, fg_color=SIDEBAR_COLOR, text_color=TEXT_MAIN,
            corner_radius=10, border_width=1, border_color=BORDER_COLOR
        )
        self.routing_textbox.pack(fill="both", expand=True, padx=25, pady=(0, 25))

        self.refresh_routes_list()
        self.load_servers_from_file()
        self.load_routes()
        self.toggle_split_state()
        self.select_default_server_on_start()

        self.create_tray_icon()
        self.protocol("WM_DELETE_WINDOW", self.hide_window)

    def refresh_routes_list(self):
        try:
            files = [f for f in os.listdir(ROUTES_DIR) if f.endswith('.txt')]
            if not files:
                default_file = "routes.txt"
                default_path = os.path.join(ROUTES_DIR, default_file)
                if not os.path.exists(default_path):
                    with open(default_path, 'w', encoding='utf-8') as f:
                        f.write("instagram.com\ntwitter.com\n2ip.ru")
                files = [default_file]
            self.routes_list = sorted(files)
            self.routes_combo.configure(values=self.routes_list)
            if self.current_routes_file not in self.routes_list:
                self.current_routes_file = self.routes_list[0]
            self.routes_combo.set(self.current_routes_file)
        except Exception as e:
            print(f"Ошибка обновления списка маршрутов: {e}")

    def on_routes_file_selected(self, choice):
        if choice != self.current_routes_file:
            self.save_current_routes()
            self.current_routes_file = choice
            self.load_routes_from_file(choice)
            self.restart_proxy_if_needed()

    def load_routes_from_file(self, filename):
        filepath = os.path.join(ROUTES_DIR, filename)
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                self.routing_textbox.delete("1.0", "end")
                self.routing_textbox.insert("1.0", content)
            else:
                self.routing_textbox.delete("1.0", "end")
        except Exception as e:
            print(f"Ошибка загрузки маршрутов из {filename}: {e}")

    def save_current_routes(self):
        self.save_routes_to_file(self.current_routes_file)

    def save_routes_to_file(self, filename):
        os.makedirs(ROUTES_DIR, exist_ok=True)
        filepath = os.path.join(ROUTES_DIR, filename)
        try:
            content = self.routing_textbox.get("1.0", "end-1c").strip()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"Ошибка сохранения маршрутов в {filename}: {e}")

    def create_new_routes_file(self):
        name = simpledialog.askstring(self.tr("new_routes_file"), self.tr("enter_name"),
                                      parent=self, initialvalue="new_list.txt")
        if not name:
            return
        if not name.endswith('.txt'):
            name += '.txt'
        if name in self.routes_list:
            messagebox.showerror(self.tr("error"), f"Файл {name} уже существует.")
            return
        filepath = os.path.join(ROUTES_DIR, name)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("")
            self.refresh_routes_list()
            self.save_current_routes()
            self.current_routes_file = name
            self.routes_combo.set(name)
            self.routing_textbox.delete("1.0", "end")
            self.restart_proxy_if_needed()
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось создать файл: {e}")

    def delete_routes_file(self):
        if len(self.routes_list) <= 1:
            messagebox.showerror(self.tr("error"), self.tr("cannot_delete_last"))
            return
        confirm = messagebox.askyesno(self.tr("confirm_delete"),
                                      self.tr("confirm_delete_text").format(self.current_routes_file))
        if not confirm:
            return
        filepath = os.path.join(ROUTES_DIR, self.current_routes_file)
        try:
            os.remove(filepath)
            self.refresh_routes_list()
            self.current_routes_file = self.routes_list[0]
            self.routes_combo.set(self.current_routes_file)
            self.load_routes_from_file(self.current_routes_file)
            self.restart_proxy_if_needed()
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось удалить файл: {e}")

    def rename_routes_file(self):
        old_name = self.current_routes_file
        new_name = simpledialog.askstring(self.tr("rename_routes_file"), self.tr("enter_name"),
                                          parent=self, initialvalue=old_name)
        if not new_name or new_name == old_name:
            return
        if not new_name.endswith('.txt'):
            new_name += '.txt'
        if new_name in self.routes_list:
            messagebox.showerror(self.tr("error"), f"Файл {new_name} уже существует.")
            return
        old_path = os.path.join(ROUTES_DIR, old_name)
        new_path = os.path.join(ROUTES_DIR, new_name)
        try:
            os.rename(old_path, new_path)
            self.refresh_routes_list()
            self.current_routes_file = new_name
            self.routes_combo.set(new_name)
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Не удалось переименовать файл: {e}")

    def restart_proxy_if_needed(self):
        if self.proxy_process is not None and self.selected_server_index != -1:
            self.stop_proxy()
            self.toggle_connection()

    def set_current_as_default(self):
        if self.selected_server_index != -1:
            server_name = self.servers[self.selected_server_index]["name"]
            current_default = self.app_settings.get("default_server", "")
            if current_default == server_name:
                self.app_settings["default_server"] = ""
                self.default_btn.configure(text_color=DANGER_COLOR)
            else:
                self.app_settings["default_server"] = server_name
                self.default_btn.configure(text_color=SUCCESS_COLOR)
            self.save_app_settings()
            self.update_server_list()

    def set_current_as_default_from_tray(self, icon, item):
        self.after(0, self.set_current_as_default)

    def select_default_server_on_start(self):
        default_name = self.app_settings.get("default_server")
        if default_name:
            for i, server in enumerate(self.servers):
                if server["name"] == default_name:
                    self.select_server(i)
                    break

    def build_tray_menu(self):
        server_items = []
        default_name = self.app_settings.get("default_server", "")
        for i, s in enumerate(self.servers):
            def make_callback(idx):
                return lambda icon, item: self.after(0, self.select_server, idx)
            def make_checked_condition(idx):
                return lambda item: self.selected_server_index == idx
            display_name = s["name"]
            if display_name == default_name:
                display_name += self.tr("default_marker")
            server_items.append(
                pystray.MenuItem(
                    display_name[:35] + ("..." if len(display_name) > 35 else ""),
                    make_callback(i),
                    checked=make_checked_condition(i),
                    radio=True
                )
            )
        if not server_items:
            server_items.append(pystray.MenuItem("Пусто", lambda icon, item: None, enabled=False))
        def is_not_connected(item):
            return self.proxy_process is None and self.selected_server_index != -1
        def is_connected(item):
            return self.proxy_process is not None
        def get_status_text(item):
            return "Статус: Подключено" if self.proxy_process is not None else "Статус: Отключено"
        return pystray.Menu(
            pystray.MenuItem(get_status_text, lambda icon, item: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Подключиться", self.connect_from_tray, enabled=is_not_connected),
            pystray.MenuItem("Отключиться", self.disconnect_from_tray, enabled=is_connected),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(" " + self.tr("app_name"), pystray.Menu(*server_items)),
            pystray.MenuItem(
                "⭐ " + self.tr("set_default"),
                self.set_current_as_default_from_tray,
                checked=lambda item: (self.selected_server_index != -1 and
                                     self.servers[self.selected_server_index]["name"] == self.app_settings.get("default_server", ""))
            ),
            pystray.MenuItem(
                " " + self.tr("split_tunneling"),
                self.toggle_routing_from_tray,
                checked=lambda item: self.split_tunnel_var.get()
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self.tr("tray_open"), self.show_window, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self.tr("tray_exit"), self.quit_app)
        )

    def update_tray_menu(self):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.menu = self.build_tray_menu()
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass
            self.after(200, self._delayed_tray_update)

    def _delayed_tray_update(self):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass

    def create_tray_icon(self):
        menu = self.build_tray_menu()
        self.tray_icon = pystray.Icon("MinimalProxyClient", self.icon_off, self.tr("title"), menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def hide_window(self):
        self.withdraw()

    def show_window(self, icon=None, item=None):
        self.after(0, self.deiconify)

    def quit_app(self, icon=None, item=None):
        self.after(0, self.cleanup_and_exit)

    def cleanup_and_exit(self):
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.visible = False
            self.tray_icon.stop()
        self.set_system_proxy(False)
        self.save_current_routes()
        self.save_app_settings()
        if self.proxy_process:
            self.stop_proxy()
        self.quit()
        self.destroy()
        os._exit(0)

    def connect_from_tray(self, icon, item):
        self.after(0, self.toggle_connection)

    def disconnect_from_tray(self, icon, item):
        self.after(0, self.stop_proxy)

    def toggle_routing_from_tray(self, icon, item):
        self.after(0, self._toggle_routing_internal)

    def _toggle_routing_internal(self):
        current_state = self.split_tunnel_var.get()
        self.split_tunnel_var.set(not current_state)
        self.toggle_split_state()
        self.save_app_settings()
        self.restart_proxy_if_needed()

    def tr(self, key):
        return TRANSLATIONS.get(self.lang, TRANSLATIONS["ru"]).get(key, key)

    def load_app_settings(self):
        default_settings = {
            "split_tunneling": True,
            "language": "ru",
            "default_server": "",
            "window_geometry": None,
            "window_state": "normal",
            "dns_type": "system",
            "dns_server": "https://1.1.1.1/dns-query",
            "dns_through_proxy": True
        }
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    default_settings.update(loaded)
            except Exception:
                pass
        return default_settings

    def save_app_settings(self):
        self.app_settings["split_tunneling"] = self.split_tunnel_var.get()
        try:
            geometry = self.geometry()
            self.app_settings["window_geometry"] = geometry
            self.app_settings["window_state"] = self.state()
        except Exception:
            pass
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.app_settings, f, indent=4)
        except Exception:
            pass

    def center_window(self, window, width, height):
        x = int((self.winfo_screenwidth() / 2) - (width / 2))
        y = int((self.winfo_screenheight() / 2) - (height / 2))
        window.geometry(f"{width}x{height}+{x}+{y}")

    def delete_current_server(self):
        if self.selected_server_index != -1:
            if self.proxy_process:
                self.stop_proxy()
            name_to_del = self.servers[self.selected_server_index]["name"]
            if self.app_settings.get("default_server") == name_to_del:
                self.app_settings["default_server"] = ""
                self.save_app_settings()
            del self.servers[self.selected_server_index]
            self.save_servers_to_file()
            self.selected_server_index = -1
            self.name_var.set(self.tr("server_not_selected"))
            self.host_var.set("—")
            self.ping_label.configure(text="")
            self.connect_btn.configure(state="disabled")
            self.ping_btn.configure(state="disabled")
            self.delete_btn.configure(state="disabled")
            self.default_btn.configure(state="disabled")
            self.update_server_list()

    def open_settings_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.attributes("-alpha", 0)
        dialog.title(self.tr("settings_title"))
        dialog.configure(fg_color=BG_COLOR)
        self.center_window(dialog, 500, 380)
        dialog.resizable(False, False)
        dialog.transient(self)

        container = ctk.CTkFrame(dialog, fg_color=CARD_COLOR, corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        container.pack(expand=True, fill="both", padx=25, pady=25)

        switch = ctk.CTkSwitch(
            container, text=self.tr("autostart"), font=self.font_main, text_color=TEXT_MAIN,
            variable=self.autostart_var, command=self.toggle_autostart, switch_width=38, switch_height=20
        )
        switch.pack(pady=(25, 15), padx=25, anchor="w")

        lang_frame = ctk.CTkFrame(container, fg_color="transparent")
        lang_frame.pack(fill="x", padx=25, pady=(0, 20))
        ctk.CTkLabel(lang_frame, text=self.tr("language_label"), font=self.font_main, text_color=TEXT_MAIN).pack(side="left")
        self.lang_var = ctk.StringVar(value="Русский" if self.lang == "ru" else "English")
        lang_menu = ctk.CTkOptionMenu(
            lang_frame, variable=self.lang_var, values=["Русский", "English"], command=self.change_language,
            fg_color=SIDEBAR_COLOR, button_color=BORDER_COLOR, button_hover_color=ACTIVE_ITEM_COLOR
        )
        lang_menu.pack(side="right")

        dns_frame = ctk.CTkFrame(container, fg_color="transparent", border_width=1, border_color=BORDER_COLOR, corner_radius=8)
        dns_frame.pack(fill="x", padx=25, pady=(0, 20))

        ctk.CTkLabel(dns_frame, text=self.tr("dns_settings"), font=self.font_bold, text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(10, 5))

        type_frame = ctk.CTkFrame(dns_frame, fg_color="transparent")
        type_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(type_frame, text=self.tr("dns_type"), font=self.font_main, text_color=TEXT_MUTED).pack(side="left")
        dns_type_var = ctk.StringVar(value=self.app_settings.get("dns_type", "system"))
        dns_type_menu = ctk.CTkOptionMenu(
            type_frame, variable=dns_type_var,
            values=[self.tr("dns_system"), self.tr("dns_doh"), self.tr("dns_dot")],
            fg_color=SIDEBAR_COLOR, button_color=BORDER_COLOR, button_hover_color=ACTIVE_ITEM_COLOR,
            width=150
        )
        dns_type_menu.pack(side="right")

        addr_frame = ctk.CTkFrame(dns_frame, fg_color="transparent")
        addr_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(addr_frame, text=self.tr("dns_server_address"), font=self.font_main, text_color=TEXT_MUTED).pack(side="left")
        dns_addr_var = ctk.StringVar(value=self.app_settings.get("dns_server", "https://1.1.1.1/dns-query"))
        dns_addr_entry = ctk.CTkEntry(addr_frame, textvariable=dns_addr_var, fg_color=SIDEBAR_COLOR, border_color=BORDER_COLOR)
        dns_addr_entry.pack(side="right", fill="x", expand=True, padx=(10, 0))

        dns_proxy_var = ctk.BooleanVar(value=self.app_settings.get("dns_through_proxy", True))
        dns_proxy_check = ctk.CTkCheckBox(
            dns_frame, text=self.tr("dns_through_proxy"), variable=dns_proxy_var,
            font=self.font_small, text_color=TEXT_MAIN
        )
        dns_proxy_check.pack(anchor="w", padx=15, pady=5)

        dns_test_btn = ctk.CTkButton(
            dns_frame, text=self.tr("dns_test"), font=self.font_small,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MAIN, hover_color=SIDEBAR_COLOR, height=30
        )
        dns_test_btn.pack(anchor="w", padx=15, pady=(0, 10))
        dns_test_label = ctk.CTkLabel(dns_frame, text="", font=self.font_small, text_color=TEXT_MUTED)
        dns_test_label.pack(anchor="w", padx=15, pady=(0, 10))

        def update_dns_fields(*args):
            selected = dns_type_var.get()
            if selected == self.tr("dns_system"):
                dns_addr_entry.configure(state="disabled")
                dns_proxy_check.configure(state="disabled")
                dns_test_btn.configure(state="disabled")
            else:
                dns_addr_entry.configure(state="normal")
                dns_proxy_check.configure(state="normal")
                dns_test_btn.configure(state="normal")
        dns_type_var.trace_add("write", update_dns_fields)
        update_dns_fields()

        def test_dns():
            dns_type = dns_type_var.get()
            if dns_type == self.tr("dns_system"):
                dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
                return
            server = dns_addr_var.get().strip()
            if not server:
                dns_test_label.configure(text=self.tr("dns_invalid_address"), text_color=DANGER_COLOR)
                return
            try:
                if dns_type == self.tr("dns_doh"):
                    import requests
                    response = requests.get(server, params={"name": "example.com", "type": "A"}, timeout=3)
                    if response.status_code == 200:
                        dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
                    else:
                        dns_test_label.configure(text=self.tr("dns_test_fail"), text_color=DANGER_COLOR)
                elif dns_type == self.tr("dns_dot"):
                    import socket, ssl
                    context = ssl.create_default_context()
                    host = server.replace("tls://", "")
                    with socket.create_connection((host, 853), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            dns_test_label.configure(text=self.tr("dns_test_success"), text_color=SUCCESS_COLOR)
            except Exception:
                dns_test_label.configure(text=self.tr("dns_test_fail"), text_color=DANGER_COLOR)
        dns_test_btn.configure(command=test_dns)

        btn_save = ctk.CTkButton(
            container, text=self.tr("restart_app"), font=self.font_bold,
            fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER, height=38, corner_radius=8,
            command=lambda: self.save_dns_and_restart(dns_type_var, dns_addr_var, dns_proxy_var, dialog)
        )
        btn_save.pack(fill="x", padx=25, pady=(0, 15))

        logs_btn = ctk.CTkButton(
            container, text=self.tr("view_logs"), font=self.font_bold, fg_color=SIDEBAR_COLOR, hover_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=38, corner_radius=8, command=self.view_logs
        )
        logs_btn.pack(fill="x", padx=25, pady=(0, 25))

        dialog.after(150, lambda: [dialog.attributes("-alpha", 1), dialog.grab_set()])

    def save_dns_and_restart(self, dns_type_var, dns_addr_var, dns_proxy_var, dialog):
        selected_type = dns_type_var.get()
        if selected_type == self.tr("dns_system"):
            self.app_settings["dns_type"] = "system"
        elif selected_type == self.tr("dns_doh"):
            self.app_settings["dns_type"] = "doh"
        elif selected_type == self.tr("dns_dot"):
            self.app_settings["dns_type"] = "dot"
        self.app_settings["dns_server"] = dns_addr_var.get().strip()
        self.app_settings["dns_through_proxy"] = dns_proxy_var.get()
        self.save_app_settings()
        dialog.destroy()
        if self.proxy_process is not None:
            self.restart_proxy_if_needed()
        else:
            messagebox.showinfo(self.tr("settings_title"), self.tr("dns_apply_restart"))

    def view_logs(self):
        log_path = os.path.abspath(LOG_FILE)
        if os.path.exists(log_path):
            if os.name == 'nt': os.startfile(log_path)
            else:
                try: subprocess.call(['xdg-open', log_path])
                except Exception: pass
        else:
            messagebox.showinfo(self.tr("log_not_found"), self.tr("log_not_found"))

    def change_language(self, choice):
        self.app_settings["language"] = "ru" if choice == "Русский" else "en"
        self.save_app_settings()
        self.restart_app()

    def restart_app(self):
        self.cleanup_and_exit()
        python = sys.executable
        os.execl(python, python, *sys.argv)

    def open_import_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.attributes("-alpha", 0)
        dialog.title(self.tr("import_title"))
        dialog.configure(fg_color=BG_COLOR)
        self.center_window(dialog, 400, 220)
        dialog.resizable(False, False)
        dialog.transient(self)
        container = ctk.CTkFrame(dialog, fg_color=CARD_COLOR, corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        container.pack(expand=True, fill="both", padx=20, pady=20)
        btn1 = ctk.CTkButton(
            container, text=self.tr("import_file"), font=self.font_bold, fg_color=SIDEBAR_COLOR, hover_color=BORDER_COLOR,
            text_color=TEXT_MAIN, height=42, corner_radius=8, command=lambda: [dialog.destroy(), self.import_sites_from_file()]
        )
        btn1.pack(pady=(25, 15), padx=25, fill="x")
        btn2 = ctk.CTkButton(
            container, text=self.tr("import_clipboard"), font=self.font_bold, fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER,
            height=42, corner_radius=8, command=lambda: [dialog.destroy(), self.add_from_clipboard()]
        )
        btn2.pack(padx=25, fill="x")
        dialog.after(150, lambda: [dialog.attributes("-alpha", 1), dialog.grab_set()])

    def get_app_path(self):
        if getattr(sys, 'frozen', False): return sys.executable
        return os.path.abspath(sys.argv[0])

    def check_autostart(self):
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "TaaClient")
                return value == self.get_app_path()
        except WindowsError: return False

    def toggle_autostart(self):
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                if self.autostart_var.get():
                    winreg.SetValueEx(key, "TaaClient", 0, winreg.REG_SZ, self.get_app_path())
                else:
                    try: winreg.DeleteValue(key, "TaaClient")
                    except FileNotFoundError: pass
        except Exception: pass

    def import_sites_from_file(self):
        filepath = filedialog.askopenfilename(
            title=self.tr("select_file"), filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f: content = f.read()
                self.routing_textbox.configure(state="normal", fg_color=SIDEBAR_COLOR)
                self.routing_textbox.delete("1.0", "end")
                self.routing_textbox.insert("1.0", content)
                self.toggle_split_state()
                self.save_current_routes()
                self.restart_proxy_if_needed()
            except Exception: pass

    def check_ping_thread(self):
        if self.selected_server_index == -1: return
        self.ping_btn.configure(state="disabled")
        self.ping_label.configure(text=self.tr("ping_checking"), text_color=TEXT_MUTED)
        server = self.servers[self.selected_server_index]
        threading.Thread(target=self._perform_tcp_ping, args=(server['host'], server['port']), daemon=True).start()

    def _perform_tcp_ping(self, host, port, timeout=3):
        try:
            start_time = time.time()
            with socket.create_connection((host, int(port)), timeout=timeout):
                ms = round((time.time() - start_time) * 1000)
            self.after(0, lambda: self._update_ping_ui(ms))
        except: self.after(0, lambda: self._update_ping_ui(-1))

    def _update_ping_ui(self, ms):
        self.ping_btn.configure(state="normal")
        if ms == -1: self.ping_label.configure(text=self.tr("status_error"), text_color=DANGER_COLOR)
        else:
            color = SUCCESS_COLOR if ms < 150 else ("#F59E0B" if ms < 300 else DANGER_COLOR)
            self.ping_label.configure(text=f"{ms} ms", text_color=color)

    def update_host_display(self):
        if self.selected_server_index == -1: return
        server = self.servers[self.selected_server_index]
        port = server.get('port', '')
        if self.hide_host_var.get(): self.host_var.set(f"••••••••••••:{port}")
        else: self.host_var.set(f"{server['host']}:{port}")

    def toggle_split_state(self):
        if self.split_tunnel_var.get():
            self.routing_textbox.configure(state="normal", fg_color=SIDEBAR_COLOR)
            self.routes_combo.configure(state="readonly")
            self.new_routes_btn.configure(state="normal")
            self.delete_routes_btn.configure(state="normal")
            self.rename_routes_btn.configure(state="normal")
        else:
            self.routing_textbox.configure(state="disabled", fg_color=BG_COLOR)
            self.routes_combo.configure(state="disabled")
            self.new_routes_btn.configure(state="disabled")
            self.delete_routes_btn.configure(state="disabled")
            self.rename_routes_btn.configure(state="disabled")
        self.update_tray_menu()

    def on_split_toggle(self):
        self.save_current_routes()
        self.toggle_split_state()
        self.save_app_settings()
        self.restart_proxy_if_needed()

    def set_system_proxy(self, enable=True):
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as key:
                if enable:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:1080")
                else: winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        except: pass

    def load_servers_from_file(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "r", encoding="utf-8") as f: self.servers = json.load(f)
                self.update_server_list()
            except: pass

    def save_servers_to_file(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(self.servers, f, indent=4, ensure_ascii=False)

    def load_routes(self):
        self.load_routes_from_file(self.current_routes_file)

    def save_routes(self):
        self.save_current_routes()

    def add_from_clipboard(self):
        try:
            url = self.clipboard_get().strip()
            if not (url.startswith("vless://") or url.startswith("hysteria2://")):
                return
            parsed = urllib.parse.urlparse(url)
            protocol = parsed.scheme
            params = dict(urllib.parse.parse_qsl(parsed.query))
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else parsed.hostname
            server_data = {
                "type": protocol,
                "name": name,
                "host": parsed.hostname,
                "port": parsed.port,
                "params": params
            }
            if protocol == "vless":
                server_data["uuid"] = parsed.username
            elif protocol == "hysteria2":
                server_data["password"] = parsed.username
            self.servers.append(server_data)
            self.save_servers_to_file()
            self.update_server_list()
        except: pass

    def update_server_list(self):
        for w in self.server_list_frame.winfo_children(): w.destroy()
        self.server_buttons.clear()
        default_name = self.app_settings.get("default_server", "")
        for i, s in enumerate(self.servers):
            display_name = s["name"]
            if s["name"] == default_name:
                display_name += self.tr("default_marker")
            btn = ctk.CTkButton(
                self.server_list_frame, text=display_name, font=self.font_main, fg_color="transparent",
                text_color=TEXT_MAIN, hover_color=ACTIVE_ITEM_COLOR, anchor="w", height=38, corner_radius=8,
                command=lambda idx=i: self.select_server(idx)
            )
            btn.pack(pady=4, fill="x")
            self.server_buttons.append(btn)
        if self.selected_server_index != -1 and self.selected_server_index < len(self.server_buttons):
            self.server_buttons[self.selected_server_index].configure(fg_color=ACTIVE_ITEM_COLOR)
        self.update_tray_menu()

    def select_server(self, index):
        if self.selected_server_index != -1 and self.selected_server_index < len(self.server_buttons):
            self.server_buttons[self.selected_server_index].configure(fg_color="transparent")
        self.selected_server_index = index
        self.server_buttons[index].configure(fg_color=ACTIVE_ITEM_COLOR)
        s = self.servers[index]
        self.name_var.set(s["name"])
        self.ping_label.configure(text="")
        self.update_host_display()
        if self.app_settings.get("default_server") == s["name"]:
            self.default_btn.configure(text_color=SUCCESS_COLOR, state="normal")
        else:
            self.default_btn.configure(text_color=DANGER_COLOR, state="normal")
        self.connect_btn.configure(state="normal")
        self.ping_btn.configure(state="normal")
        self.delete_btn.configure(state="normal")
        self.update_tray_menu()

    def get_dns_config(self):
        dns_type = self.app_settings.get("dns_type", "system")
        if dns_type == "system":
            return {}

        server_address = self.app_settings.get("dns_server", "")
        if not server_address:
            return {}

        if dns_type == "doh":
            if not server_address.startswith("https://"):
                server_address = "https://" + server_address
            if not server_address.endswith("/dns-query"):
                if not server_address.endswith("/"):
                    server_address += "/"
                server_address += "dns-query"
        elif dns_type == "dot":
            if not server_address.startswith("tls://"):
                server_address = "tls://" + server_address

        dns_through_proxy = self.app_settings.get("dns_through_proxy", True)
        server_config = {
            "tag": "custom_dns",
            "address": server_address,
        }
        if dns_through_proxy:
            server_config["detour"] = "proxy"

        return {
            "servers": [server_config],
            "rules": [
                {
                    "outbound": "any",
                    "server": "custom_dns"
                }
            ]
        }

    def generate_singbox_config(self, server):
        p = server["params"]
        protocol_type = server.get("type", "vless")
        route_rules = []
        is_split = self.split_tunnel_var.get()
        final_outbound = "direct" if is_split else "proxy"
        if is_split:
            raw_routes = self.routing_textbox.get("1.0", "end-1c").strip()
            domains, ips = [], []
            items = [x.strip() for x in raw_routes.replace(',', '\n').split('\n') if x.strip()]
            for item in items:
                try:
                    if '/' in item:
                        ipaddress.ip_network(item, strict=False)
                        ips.append(item)
                    else:
                        ipaddress.ip_address(item)
                        ips.append(item + "/32")
                except: domains.append(item)
            if domains or ips:
                rule = {"outbound": "proxy"}
                if domains: rule["domain_suffix"] = domains
                if ips: rule["ip_cidr"] = ips
                route_rules.append(rule)
        if protocol_type == "hysteria2":
            main_outbound = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": server["host"],
                "server_port": server["port"],
                "password": server.get("password", ""),
                "tls": {
                    "enabled": True,
                    "server_name": p.get("sni", ""),
                    "insecure": p.get("insecure", "0") == "1"
                }
            }
        else:
            main_outbound = {
                "type": "vless",
                "tag": "proxy",
                "server": server["host"],
                "server_port": server["port"],
                "uuid": server.get("uuid", ""),
                "packet_encoding": "xudp", "flow": p.get("flow", ""),
                "tls": {
                    "enabled": True, "server_name": p.get("sni", ""),
                    "utls": {"enabled": True, "fingerprint": p.get("fp", "chrome")},
                    "reality": {
                        "enabled": True, "public_key": p.get("pbk", ""), "short_id": p.get("sid", "")
                    } if p.get("security") == "reality" else None
                }
            }
        config = {
            "log": {"level": "info", "output": LOG_FILE},
            "inbounds": [{
                "type": "mixed", "listen": "127.0.0.1", "listen_port": 1080,
                "sniff": True, "sniff_override_destination": True
            }],
            "outbounds": [
                main_outbound,
                {"type": "direct", "tag": "direct"}
            ],
            "route": {"rules": route_rules, "final": final_outbound, "auto_detect_interface": True}
        }
        dns_config = self.get_dns_config()
        if dns_config:
            config["dns"] = dns_config

        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    def toggle_connection(self):
        if self.selected_server_index == -1 and self.proxy_process is None:
            return
        if self.proxy_process is None:
            if os.name == 'nt':
                try:
                    subprocess.run(
                        ["taskkill", "/f", "/im", "sing-box.exe"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                except Exception:
                    pass
            try:
                server = self.servers[self.selected_server_index]
                self.generate_singbox_config(server)
                time.sleep(0.3)
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                creation_flags = subprocess.CREATE_NO_WINDOW
                sb_path = resource_path("sing-box.exe")
                self.proxy_process = subprocess.Popen(
                    [sb_path, "run", "-c", CONFIG_FILE],
                    startupinfo=si,
                    creationflags=creation_flags,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    close_fds=True
                )
                self.set_system_proxy(True)
                self.status_label.configure(text=self.tr("status_connected"), text_color=SUCCESS_COLOR)
                self.connect_btn.configure(text=self.tr("btn_disconnect"), fg_color=DANGER_COLOR, hover_color=DANGER_HOVER)
                if hasattr(self, 'tray_icon'):
                    self.tray_icon.icon = self.icon_on
                self.update_tray_menu()
            except Exception as e:
                self.status_label.configure(text=self.tr("status_error"), text_color=DANGER_COLOR)
                with open("error.log", "a") as f:
                    f.write(f"Ошибка запуска: {e}\n")
        else:
            self.stop_proxy()

    def stop_proxy(self):
        self.set_system_proxy(False)
        if self.proxy_process:
            self.proxy_process.terminate()
            self.proxy_process.wait()
            self.proxy_process = None
        self.status_label.configure(text=self.tr("status_disconnected"), text_color=TEXT_MUTED)
        self.connect_btn.configure(text=self.tr("btn_connect"), fg_color=ACCENT_COLOR, hover_color=ACCENT_HOVER)
        if hasattr(self, 'tray_icon'):
            self.tray_icon.icon = self.icon_off
        self.update_tray_menu()

if __name__ == "__main__":
    app = ProxyApp()
    app.mainloop()
