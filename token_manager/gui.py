from __future__ import annotations

import sys
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

import tkinter as tk

from .config import load_app_config
from .constants import APP_NAME, APP_VERSION, DEFAULT_AUTH_TIMEOUT_SECONDS
from .gui_auth import GUIAuthMixin
from .gui_common import GUICommonMixin
from .gui_cpa import GUICPAMixin
from .gui_layout import GUILayoutMixin
from .gui_records import GUIRecordsMixin
from .gui_sub2api import GUISub2APIMixin
from .log_bus import LogBus
from .store import TokenStore


def _runtime_base_dir() -> Path:
    if getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def _apply_window_icon(root: tk.Tk) -> None:
    base_dir = _runtime_base_dir()
    ico_candidates = [
        base_dir / "build_assets" / "openai.ico",
        base_dir / "ico" / "openai.ico",
    ]
    png_candidates = [
        base_dir / "ico" / "openai.png",
    ]

    for ico_path in ico_candidates:
        if not ico_path.exists():
            continue
        try:
            root.iconbitmap(default=str(ico_path))
            return
        except Exception:
            pass

    for png_path in png_candidates:
        if not png_path.exists():
            continue
        try:
            image = tk.PhotoImage(file=str(png_path))
            root._window_icon_ref = image  # type: ignore[attr-defined]
            root.iconphoto(True, image)
            return
        except Exception:
            pass


def _apply_window_geometry(root: tk.Tk) -> None:
    screen_width = max(1280, int(root.winfo_screenwidth()))
    screen_height = max(800, int(root.winfo_screenheight()))
    width = min(max(1280, int(screen_width * 0.9)), screen_width - 48)
    height = min(max(820, int(screen_height * 0.88)), screen_height - 72)
    pos_x = max(0, (screen_width - width) // 2)
    pos_y = max(0, (screen_height - height) // 2)
    root.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
    root.minsize(1220, 780)


class TokenManagerGUI(
    GUILayoutMixin,
    GUICPAMixin,
    GUISub2APIMixin,
    GUIRecordsMixin,
    GUIAuthMixin,
    GUICommonMixin,
):
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        _apply_window_geometry(self.root)

        self.config = load_app_config()
        self.store = TokenStore(self.config)
        self.log_bus = LogBus()
        self._state_lock = threading.Lock()
        self.records: list[dict[str, Any]] = []
        self.cpa_records: list[dict[str, Any]] = []
        self.filtered_cpa_records: list[dict[str, Any]] = []
        self.invalidated_cpa_records: list[dict[str, Any]] = []
        self.cpa_index: dict[str, dict[str, Any]] = {}
        self.cpa_row_index: dict[str, dict[str, Any]] = {}
        self.cpa_invalidated_row_index: dict[str, dict[str, Any]] = {}
        self.sub2api_records: list[dict[str, Any]] = []
        self.filtered_sub2api_records: list[dict[str, Any]] = []
        self.invalidated_sub2api_records: list[dict[str, Any]] = []
        self.sub2api_index: dict[str, dict[str, Any]] = {}
        self.sub2api_row_index: dict[str, dict[str, Any]] = {}
        self.sub2api_invalidated_row_index: dict[str, dict[str, Any]] = {}
        self.sub2api_groups: list[dict[str, Any]] = []
        self.manual_oauth_start = None
        self.running_job = False
        self._running_job_lock = threading.Lock()
        self.auto_refresh_running = False
        self.auto_refresh_thread: threading.Thread | None = None
        self.preview_text_value = ""

        self.tokens_dir_var = tk.StringVar(value=str(self.config.get("tokens_dir") or ""))
        self.outputs_dir_var = tk.StringVar(value=str(self.config.get("outputs_dir") or ""))
        self.proxy_var = tk.StringVar(value=str(self.config.get("http_proxy") or ""))
        self.refresh_workers_var = tk.IntVar(value=int(self.config.get("refresh_workers") or 6))
        self.upload_workers_var = tk.IntVar(value=int(self.config.get("upload_workers") or 4))
        self.auth2fa_workers_var = tk.IntVar(value=int(self.config.get("auth_2fa_live_workers") or 3))
        self.auto_interval_var = tk.IntVar(value=int(self.config.get("auto_refresh_interval_seconds") or 60))
        self.auto_threshold_var = tk.IntVar(value=int(self.config.get("auto_refresh_threshold_seconds") or 300))
        self.auto_auth_timeout_var = tk.IntVar(value=int(self.config.get("auto_auth_timeout_seconds") or DEFAULT_AUTH_TIMEOUT_SECONDS))
        self.open_browser_var = tk.BooleanVar(value=bool(self.config.get("open_browser_on_auto_auth", True)))
        self.auth2fa_save_token_var = tk.BooleanVar(value=bool(self.config.get("auth_2fa_live_save_token", False)))
        self.search_var = tk.StringVar(value="")
        self.plan_filter_var = tk.StringVar(value="全部标签")
        self.status_filter_var = tk.StringVar(value="全部状态")
        self.stats_var = tk.StringVar(value="")
        self.cpa_search_var = tk.StringVar(value="")
        self.cpa_plan_filter_var = tk.StringVar(value="全部标签")
        self.cpa_status_filter_var = tk.StringVar(value="全部状态")
        self.sub2api_search_var = tk.StringVar(value="")
        self.sub2api_group_filter_var = tk.StringVar(value="全部分组")
        self.sub2api_status_filter_var = tk.StringVar(value="全部状态")
        self.sub2api_type_filter_var = tk.StringVar(value="全部类型")

        oauth = self.config.get("oauth") or {}
        self.oauth_auth_url_var = tk.StringVar(value=str(oauth.get("auth_url") or ""))
        self.oauth_token_url_var = tk.StringVar(value=str(oauth.get("token_url") or ""))
        self.oauth_client_id_var = tk.StringVar(value=str(oauth.get("client_id") or ""))
        self.oauth_redirect_uri_var = tk.StringVar(value=str(oauth.get("redirect_uri") or ""))
        self.oauth_scope_var = tk.StringVar(value=str(oauth.get("scope") or ""))

        integrations = self.config.get("integrations") or {}
        cpa = integrations.get("cpa") or {}
        sub2api = integrations.get("sub2api") or {}
        self.cpa_url_var = tk.StringVar(value=str(cpa.get("api_url") or ""))
        self.cpa_key_var = tk.StringVar(value=str(cpa.get("api_key") or ""))
        self.cpa_container_var = tk.StringVar(value=str(cpa.get("container_name") or "cli-proxy-api"))
        self.sub2api_url_var = tk.StringVar(value=str(sub2api.get("api_url") or ""))
        self.sub2api_key_var = tk.StringVar(value=str(sub2api.get("api_key") or ""))
        self.sub2api_group_ids_var = tk.StringVar(value=str(sub2api.get("group_ids") or "2"))
        self.sub2api_admin_email_var = tk.StringVar(value=str(sub2api.get("admin_email") or ""))
        self.sub2api_admin_password_var = tk.StringVar(value=str(sub2api.get("admin_password") or ""))

        self.upload_target_var = tk.StringVar(value="cpa")
        self.import_source_var = tk.StringVar(value="CPA")
        self.preview_format_var = tk.StringVar(value="CPA")
        self.auth2fa_stats_var = tk.StringVar(value="待授权 0")
        self.auth2fa_output_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="就绪")

        self._configure_styles()
        self.setup_ui()
        self.update_auth2fa_input_stats()
        self.reload_tokens()
        self.poll_logs()
        self.update_ui_timer()


def run_app() -> None:
    root = tk.Tk()
    _apply_window_icon(root)
    TokenManagerGUI(root)
    root.mainloop()
