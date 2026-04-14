from __future__ import annotations

import json
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .config import load_app_config, save_app_config
from .constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_AUTH_TIMEOUT_SECONDS,
    DEFAULT_LOG_POLL_MS,
    DEFAULT_UI_REFRESH_MS,
    MAX_REFRESH_WORKERS,
    MAX_UPLOAD_WORKERS,
)
from .converters import from_cpa_payload, from_sub2api_payload, to_cpa_payload, to_sub2api_payload
from .integrations import fetch_cpa_accounts, import_cpa_accounts_from_docker
from .log_bus import LogBus
from .oauth import browser_assisted_authorize, exchange_callback, generate_oauth_start
from .services import export_record_payloads, refresh_record, run_batch, sync_subscription, upload_record
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


class TokenManagerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1460x920")

        self.config = load_app_config()
        self.store = TokenStore(self.config)
        self.log_bus = LogBus()
        self.records: list[dict[str, Any]] = []
        self.cpa_records: list[dict[str, Any]] = []
        self.cpa_index: dict[str, dict[str, Any]] = {}
        self.cpa_row_index: dict[str, dict[str, Any]] = {}
        self.manual_oauth_start = None
        self.running_job = False
        self.auto_refresh_running = False
        self.auto_refresh_thread: threading.Thread | None = None
        self.preview_text_value = ""

        self.tokens_dir_var = tk.StringVar(value=str(self.config.get("tokens_dir") or ""))
        self.outputs_dir_var = tk.StringVar(value=str(self.config.get("outputs_dir") or ""))
        self.proxy_var = tk.StringVar(value=str(self.config.get("http_proxy") or ""))
        self.refresh_workers_var = tk.IntVar(value=int(self.config.get("refresh_workers") or 6))
        self.upload_workers_var = tk.IntVar(value=int(self.config.get("upload_workers") or 4))
        self.auto_interval_var = tk.IntVar(value=int(self.config.get("auto_refresh_interval_seconds") or 60))
        self.auto_threshold_var = tk.IntVar(value=int(self.config.get("auto_refresh_threshold_seconds") or 300))
        self.auto_auth_timeout_var = tk.IntVar(value=int(self.config.get("auto_auth_timeout_seconds") or DEFAULT_AUTH_TIMEOUT_SECONDS))
        self.open_browser_var = tk.BooleanVar(value=bool(self.config.get("open_browser_on_auto_auth", True)))
        self.search_var = tk.StringVar(value="")
        self.plan_filter_var = tk.StringVar(value="全部标签")
        self.status_filter_var = tk.StringVar(value="全部状态")
        self.stats_var = tk.StringVar(value="")

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

        self.upload_target_var = tk.StringVar(value="cpa")
        self.import_source_var = tk.StringVar(value="CPA")
        self.preview_format_var = tk.StringVar(value="CPA")
        self.status_var = tk.StringVar(value="就绪")

        self._configure_styles()
        self.setup_ui()
        self.reload_tokens()
        self.poll_logs()
        self.update_ui_timer()

    def _configure_styles(self) -> None:
        self.palette = {
            "bg": "#f3efe6",
            "card": "#fffdf8",
            "card_alt": "#f8f4ea",
            "border": "#d8cfbe",
            "text": "#22302b",
            "muted": "#6a756f",
            "primary": "#1f5a4d",
            "primary_hover": "#2a6b5c",
            "primary_soft": "#dce9e2",
            "accent": "#b7792b",
            "accent_soft": "#f3e3cb",
        }
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg=self.palette["bg"])
        style.configure(".", font=("Segoe UI", 10), background=self.palette["bg"], foreground=self.palette["text"])
        style.configure("TFrame", background=self.palette["bg"])
        style.configure("CardHost.TFrame", background=self.palette["bg"])
        style.configure("TLabel", background=self.palette["bg"], foreground=self.palette["text"])
        style.configure("TCheckbutton", background=self.palette["card"], foreground=self.palette["text"])
        style.map("TCheckbutton", background=[("active", self.palette["card"])])
        style.configure(
            "Card.TLabelframe",
            background=self.palette["card"],
            borderwidth=1,
            relief="solid",
            bordercolor=self.palette["border"],
            lightcolor=self.palette["border"],
            darkcolor=self.palette["border"],
        )
        style.configure(
            "Card.TLabelframe.Label",
            font=("Segoe UI Semibold", 10),
            foreground=self.palette["text"],
            background=self.palette["card"],
        )
        style.configure(
            "TButton",
            padding=(10, 7),
            background=self.palette["card_alt"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
            lightcolor=self.palette["border"],
            darkcolor=self.palette["border"],
        )
        style.map(
            "TButton",
            background=[("active", self.palette["accent_soft"]), ("pressed", self.palette["accent_soft"])],
            foreground=[("active", self.palette["text"])],
        )
        style.configure(
            "Primary.TButton",
            padding=(10, 7),
            font=("Segoe UI Semibold", 10),
            background=self.palette["primary"],
            foreground="#ffffff",
            bordercolor=self.palette["primary"],
            lightcolor=self.palette["primary"],
            darkcolor=self.palette["primary"],
        )
        style.map(
            "Primary.TButton",
            background=[("active", self.palette["primary_hover"]), ("pressed", self.palette["primary_hover"])],
            foreground=[("active", "#ffffff"), ("pressed", "#ffffff")],
        )
        style.configure("Accent.TLabel", font=("Segoe UI Semibold", 10), foreground=self.palette["muted"], background=self.palette["bg"])
        style.configure("Hero.TLabel", font=("Segoe UI Semibold", 20), foreground=self.palette["text"], background=self.palette["bg"])
        style.configure("SubHero.TLabel", font=("Segoe UI", 10), foreground=self.palette["muted"], background=self.palette["bg"])
        style.configure(
            "TEntry",
            fieldbackground=self.palette["card"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
            lightcolor=self.palette["border"],
            darkcolor=self.palette["border"],
            insertcolor=self.palette["text"],
        )
        style.configure(
            "TCombobox",
            fieldbackground=self.palette["card"],
            background=self.palette["card"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
            arrowsize=14,
        )
        style.map("TCombobox", fieldbackground=[("readonly", self.palette["card"])], selectbackground=[("readonly", self.palette["card"])])
        style.configure(
            "Treeview",
            rowheight=30,
            font=("Segoe UI", 10),
            background=self.palette["card"],
            fieldbackground=self.palette["card"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
        )
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI Semibold", 10),
            background=self.palette["card_alt"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
        )
        style.map(
            "Treeview",
            background=[("selected", self.palette["primary_soft"])],
            foreground=[("selected", self.palette["text"])],
        )
        style.map("Treeview.Heading", background=[("active", self.palette["accent_soft"])])
        style.configure("TNotebook", background=self.palette["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            padding=(14, 8),
            font=("Segoe UI Semibold", 10),
            background=self.palette["card_alt"],
            foreground=self.palette["muted"],
            bordercolor=self.palette["border"],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.palette["card"]), ("active", self.palette["accent_soft"])],
            foreground=[("selected", self.palette["text"]), ("active", self.palette["text"])],
        )

    def setup_ui(self) -> None:
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(shell)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text="OpenAI Token Manager", style="Hero.TLabel").pack(anchor=tk.W)
        ttk.Label(
            header,
            text="手动授权、自动授权、批量刷新、格式互转、可配置上传，统一放在一个面板里。",
            style="SubHero.TLabel",
        ).pack(anchor=tk.W, pady=(2, 0))

        outer = ttk.PanedWindow(shell, orient=tk.VERTICAL)
        outer.pack(fill=tk.BOTH, expand=True)

        top = ttk.PanedWindow(outer, orient=tk.HORIZONTAL)
        outer.add(top, weight=5)

        bottom = ttk.LabelFrame(outer, text="运行日志", padding=8, style="Card.TLabelframe")
        outer.add(bottom, weight=2)

        left = ttk.LabelFrame(top, text="账号列表", padding=10, style="Card.TLabelframe")
        right = ttk.Frame(top, style="CardHost.TFrame")
        top.add(left, weight=3)
        top.add(right, weight=2)

        toolbar = ttk.Frame(left)
        toolbar.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(toolbar, text="刷新列表", command=self.reload_tokens, width=10, style="Primary.TButton").pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="刷新选中", command=self.refresh_selected, width=10).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="刷新全部", command=self.refresh_all, width=10).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="同步标签", command=self.sync_selected_labels, width=10).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="删除", command=self.delete_selected, width=8).pack(side=tk.LEFT, padx=3)

        toolbar2 = ttk.Frame(left)
        toolbar2.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(toolbar2, text="上传目标").pack(side=tk.LEFT, padx=(2, 4))
        ttk.Combobox(
            toolbar2,
            textvariable=self.upload_target_var,
            values=["cpa", "sub2api"],
            width=10,
            state="readonly",
        ).pack(side=tk.LEFT)
        ttk.Button(toolbar2, text="上传选中", command=self.upload_selected, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar2, text="上传全部", command=self.upload_all, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar2, text="刷新 CPA", command=self.refresh_cpa_accounts, width=10).pack(side=tk.LEFT, padx=2)
        self.auto_refresh_button = ttk.Button(toolbar2, text="启动自动维护", command=self.toggle_auto_refresh, width=12)
        self.auto_refresh_button.pack(side=tk.LEFT, padx=8)

        filter_bar = ttk.Frame(left)
        filter_bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(filter_bar, text="搜索").pack(side=tk.LEFT, padx=(0, 4))
        search_entry = ttk.Entry(filter_bar, textvariable=self.search_var, width=24)
        search_entry.pack(side=tk.LEFT, padx=(0, 8))
        search_entry.bind("<KeyRelease>", lambda _e: self.reload_tokens(save_first=False))
        ttk.Label(filter_bar, text="标签").pack(side=tk.LEFT, padx=(0, 4))
        plan_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.plan_filter_var,
            values=["全部标签", "Team", "Plus", "Free", "Pro", "Enterprise", "Unknown"],
            width=12,
            state="readonly",
        )
        plan_combo.pack(side=tk.LEFT, padx=(0, 8))
        plan_combo.bind("<<ComboboxSelected>>", lambda _e: self.reload_tokens(save_first=False))
        ttk.Label(filter_bar, text="状态").pack(side=tk.LEFT, padx=(0, 4))
        status_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.status_filter_var,
            values=["全部状态", "有效", "已过期", "上传异常"],
            width=12,
            state="readonly",
        )
        status_combo.pack(side=tk.LEFT, padx=(0, 8))
        status_combo.bind("<<ComboboxSelected>>", lambda _e: self.reload_tokens(save_first=False))
        ttk.Button(filter_bar, text="应用筛选", command=lambda: self.reload_tokens(save_first=False), width=10).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(filter_bar, text="清空筛选", command=self.clear_filters, width=10).pack(side=tk.LEFT)

        quick_filter_row = ttk.Frame(left)
        quick_filter_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(quick_filter_row, text="快速分类").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(quick_filter_row, text="全部", command=lambda: self.apply_quick_filter("全部标签"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_filter_row, text="Team", command=lambda: self.apply_quick_filter("Team"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_filter_row, text="Plus", command=lambda: self.apply_quick_filter("Plus"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_filter_row, text="Free", command=lambda: self.apply_quick_filter("Free"), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_filter_row, text="上传异常", command=lambda: self.apply_quick_filter("全部标签", "上传异常"), width=10).pack(side=tk.LEFT, padx=8)

        stats_row = ttk.Frame(left)
        stats_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(stats_row, textvariable=self.stats_var, style="Accent.TLabel").pack(side=tk.LEFT)

        columns = ("email", "plan", "status", "remaining", "upload")
        list_frame = ttk.Frame(left)
        list_frame.pack(fill=tk.BOTH, expand=True)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.token_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        self.token_tree.heading("email", text="邮箱")
        self.token_tree.heading("plan", text="标签")
        self.token_tree.heading("status", text="状态")
        self.token_tree.heading("remaining", text="剩余时间")
        self.token_tree.heading("upload", text="上传状态")
        self.token_tree.column("email", width=300, stretch=False)
        self.token_tree.column("plan", width=90, stretch=False, anchor=tk.CENTER)
        self.token_tree.column("status", width=110, stretch=False, anchor=tk.CENTER)
        self.token_tree.column("remaining", width=130, stretch=False, anchor=tk.CENTER)
        self.token_tree.column("upload", width=180, stretch=False)
        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.token_tree.yview)
        scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.token_tree.xview)
        self.token_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        self.token_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        self.token_tree.bind("<<TreeviewSelect>>", self.on_selection_changed)
        self.token_tree.tag_configure("expired", foreground="#9f3a28")
        self.token_tree.tag_configure("warning", foreground=self.palette["accent"])

        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True)

        detail_tab = ttk.Frame(notebook, padding=8)
        auth_tab = ttk.Frame(notebook, padding=8)
        convert_tab = ttk.Frame(notebook, padding=8)
        cpa_tab = ttk.Frame(notebook, padding=8)
        settings_tab = ttk.Frame(notebook, padding=8)
        notebook.add(detail_tab, text="详情")
        notebook.add(auth_tab, text="授权")
        notebook.add(convert_tab, text="转换")
        notebook.add(cpa_tab, text="CPA")
        notebook.add(settings_tab, text="设置")

        self.detail_text = tk.Text(
            detail_tab,
            wrap=tk.WORD,
            height=18,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            padx=10,
            pady=10,
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.config(state=tk.DISABLED)

        detail_actions = ttk.Frame(detail_tab)
        detail_actions.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(detail_actions, text="复制 AT", command=self.copy_access_token, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(detail_actions, text="复制 RT", command=self.copy_refresh_token, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(detail_actions, text="预览 CPA", command=lambda: self.build_preview("CPA"), width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(detail_actions, text="预览 Sub2API", command=lambda: self.build_preview("Sub2API"), width=14).pack(side=tk.LEFT, padx=2)

        manual_frame = ttk.LabelFrame(auth_tab, text="手动授权", padding=8, style="Card.TLabelframe")
        manual_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(manual_frame, text="生成授权 URL", command=self.generate_manual_url, width=16).pack(anchor=tk.W, pady=(0, 6))
        self.url_text = scrolledtext.ScrolledText(
            manual_frame,
            height=4,
            wrap=tk.WORD,
            font=("Consolas", 8),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.url_text.pack(fill=tk.X)
        ttk.Label(manual_frame, text="回调 URL").pack(anchor=tk.W, pady=(8, 4))
        self.callback_entry = ttk.Entry(manual_frame, font=("Consolas", 9))
        self.callback_entry.pack(fill=tk.X)
        ttk.Button(manual_frame, text="提交并保存", command=self.submit_callback, width=14).pack(anchor=tk.W, pady=(8, 0))

        auto_frame = ttk.LabelFrame(auth_tab, text="自动授权", padding=8, style="Card.TLabelframe")
        auto_frame.pack(fill=tk.X)
        ttk.Checkbutton(auto_frame, text="自动打开浏览器", variable=self.open_browser_var).pack(anchor=tk.W)
        ttk.Label(auto_frame, text="回调等待秒数").pack(anchor=tk.W, pady=(6, 2))
        ttk.Spinbox(auto_frame, from_=30, to=1800, textvariable=self.auto_auth_timeout_var, width=8).pack(anchor=tk.W)
        ttk.Label(auto_frame, text="自动模式会监听本地回调并自动保存，不需要再粘贴回调 URL。").pack(anchor=tk.W, pady=(6, 6))
        ttk.Button(auto_frame, text="启动自动授权", command=self.start_auto_auth, width=16).pack(anchor=tk.W)

        convert_controls = ttk.Frame(convert_tab)
        convert_controls.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(convert_controls, text="预览格式").pack(side=tk.LEFT)
        ttk.Combobox(
            convert_controls,
            textvariable=self.preview_format_var,
            values=["CPA", "Sub2API"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(convert_controls, text="生成预览", command=self.build_preview_from_var, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(convert_controls, text="复制预览", command=self.copy_preview, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Label(convert_controls, text="导入来源").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Combobox(
            convert_controls,
            textvariable=self.import_source_var,
            values=["CPA", "Sub2API"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT)
        ttk.Button(convert_controls, text="导入剪贴板", command=self.import_from_clipboard, width=12).pack(side=tk.LEFT, padx=4)
        ttk.Button(convert_controls, text="导入文件", command=self.import_from_file, width=10).pack(side=tk.LEFT, padx=2)

        self.preview_text = scrolledtext.ScrolledText(
            convert_tab,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)

        cpa_toolbar = ttk.Frame(cpa_tab)
        cpa_toolbar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(cpa_toolbar, text="刷新远端列表", command=self.refresh_cpa_accounts, width=12, style="Primary.TButton").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cpa_toolbar, text="导入到 Tokens", command=self.import_cpa_to_tokens, width=12).pack(side=tk.LEFT, padx=(0, 8))
        self.cpa_stats_var = tk.StringVar(value="CPA 未加载")
        ttk.Label(cpa_toolbar, textvariable=self.cpa_stats_var, style="Accent.TLabel").pack(side=tk.LEFT)

        cpa_list_frame = ttk.Frame(cpa_tab)
        cpa_list_frame.pack(fill=tk.BOTH, expand=True)
        cpa_list_frame.columnconfigure(0, weight=1)
        cpa_list_frame.rowconfigure(0, weight=1)

        self.cpa_tree = ttk.Treeview(
            cpa_list_frame,
            columns=("email", "plan", "status", "last_refresh", "next_retry"),
            show="headings",
            selectmode="browse",
        )
        self.cpa_tree.heading("email", text="邮箱")
        self.cpa_tree.heading("plan", text="标签")
        self.cpa_tree.heading("status", text="状态")
        self.cpa_tree.heading("last_refresh", text="远端刷新")
        self.cpa_tree.heading("next_retry", text="下次重试")
        self.cpa_tree.column("email", width=260, stretch=False)
        self.cpa_tree.column("plan", width=80, stretch=False, anchor=tk.CENTER)
        self.cpa_tree.column("status", width=100, stretch=False, anchor=tk.CENTER)
        self.cpa_tree.column("last_refresh", width=150, stretch=False)
        self.cpa_tree.column("next_retry", width=180, stretch=False)
        cpa_scroll_y = ttk.Scrollbar(cpa_list_frame, orient=tk.VERTICAL, command=self.cpa_tree.yview)
        cpa_scroll_x = ttk.Scrollbar(cpa_list_frame, orient=tk.HORIZONTAL, command=self.cpa_tree.xview)
        self.cpa_tree.configure(yscrollcommand=cpa_scroll_y.set, xscrollcommand=cpa_scroll_x.set)
        self.cpa_tree.grid(row=0, column=0, sticky="nsew")
        cpa_scroll_y.grid(row=0, column=1, sticky="ns")
        cpa_scroll_x.grid(row=1, column=0, sticky="ew")
        self.cpa_tree.bind("<<TreeviewSelect>>", self.on_cpa_selection_changed)

        self.cpa_detail_text = tk.Text(
            cpa_tab,
            wrap=tk.WORD,
            height=10,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            padx=10,
            pady=10,
        )
        self.cpa_detail_text.pack(fill=tk.BOTH, expand=False, pady=(8, 0))
        self.cpa_detail_text.config(state=tk.DISABLED)

        settings_canvas = tk.Canvas(settings_tab, highlightthickness=0)
        settings_scroll = ttk.Scrollbar(settings_tab, orient=tk.VERTICAL, command=settings_canvas.yview)
        settings_inner = ttk.Frame(settings_canvas)
        settings_inner.bind(
            "<Configure>",
            lambda _e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all")),
        )
        settings_canvas.create_window((0, 0), window=settings_inner, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scroll.set)
        settings_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        settings_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        basic_frame = ttk.LabelFrame(settings_inner, text="基础设置", padding=8, style="Card.TLabelframe")
        basic_frame.pack(fill=tk.X, pady=(0, 8))
        self._add_labeled_entry(basic_frame, "Tokens 目录", self.tokens_dir_var, browse=True)
        self._add_labeled_entry(basic_frame, "输出目录", self.outputs_dir_var, browse_outputs=True)
        self._add_labeled_entry(basic_frame, "全局代理", self.proxy_var)
        self._add_labeled_spin(basic_frame, "刷新线程", self.refresh_workers_var, 1, MAX_REFRESH_WORKERS)
        self._add_labeled_spin(basic_frame, "上传线程", self.upload_workers_var, 1, MAX_UPLOAD_WORKERS)
        self._add_labeled_spin(basic_frame, "自动维护检查秒数", self.auto_interval_var, 30, 3600)
        self._add_labeled_spin(basic_frame, "自动维护提前刷新秒数", self.auto_threshold_var, 30, 3600)
        organize_row = ttk.Frame(basic_frame)
        organize_row.pack(fill=tk.X, pady=4)
        ttk.Label(organize_row, text="目录整理", width=18).pack(side=tk.LEFT)
        ttk.Label(organize_row, text="固定输出到 outputs/CPA 和 outputs/Sub2API", style="Accent.TLabel").pack(side=tk.LEFT)
        ttk.Button(organize_row, text="整理导出文件", command=self.organize_output_dirs, width=12).pack(side=tk.LEFT, padx=10)
        ttk.Button(organize_row, text="清理 Tokens", command=self.cleanup_tokens_dir, width=12).pack(side=tk.LEFT, padx=4)

        oauth_frame = ttk.LabelFrame(settings_inner, text="OAuth 配置", padding=8, style="Card.TLabelframe")
        oauth_frame.pack(fill=tk.X, pady=(0, 8))
        self._add_labeled_entry(oauth_frame, "Auth URL", self.oauth_auth_url_var)
        self._add_labeled_entry(oauth_frame, "Token URL", self.oauth_token_url_var)
        self._add_labeled_entry(oauth_frame, "Client ID", self.oauth_client_id_var)
        self._add_labeled_entry(oauth_frame, "Redirect URI", self.oauth_redirect_uri_var)
        self._add_labeled_entry(oauth_frame, "Scope", self.oauth_scope_var)

        cpa_frame = ttk.LabelFrame(settings_inner, text="CPA 配置", padding=8, style="Card.TLabelframe")
        cpa_frame.pack(fill=tk.X, pady=(0, 8))
        self._add_labeled_entry(cpa_frame, "CPA URL", self.cpa_url_var)
        self._add_labeled_entry(cpa_frame, "CPA Key", self.cpa_key_var)
        self._add_labeled_entry(cpa_frame, "CPA 容器名", self.cpa_container_var)

        sub2api_frame = ttk.LabelFrame(settings_inner, text="Sub2API 配置", padding=8, style="Card.TLabelframe")
        sub2api_frame.pack(fill=tk.X, pady=(0, 8))
        self._add_labeled_entry(sub2api_frame, "Sub2API URL", self.sub2api_url_var)
        self._add_labeled_entry(sub2api_frame, "Sub2API Key", self.sub2api_key_var)
        self._add_labeled_entry(sub2api_frame, "Group IDs", self.sub2api_group_ids_var)
        ttk.Button(settings_inner, text="保存设置", command=self.save_settings, width=12).pack(anchor=tk.W, pady=(4, 0))

        log_toolbar = ttk.Frame(bottom)
        log_toolbar.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(log_toolbar, textvariable=self.status_var).pack(side=tk.LEFT)
        ttk.Button(log_toolbar, text="清空日志", command=self.clear_logs, width=10).pack(side=tk.RIGHT)
        self.log_text = scrolledtext.ScrolledText(
            bottom,
            height=12,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.palette["card"],
            fg=self.palette["text"],
            relief="flat",
            insertbackground=self.palette["text"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _add_labeled_entry(self, parent, label: str, variable, browse: bool = False, browse_outputs: bool = False):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=4)
        ttk.Label(frame, text=label, width=18).pack(side=tk.LEFT)
        ttk.Entry(frame, textvariable=variable).pack(side=tk.LEFT, fill=tk.X, expand=True)
        if browse:
            ttk.Button(frame, text="浏览", command=self.choose_tokens_dir, width=8).pack(side=tk.LEFT, padx=4)
        if browse_outputs:
            ttk.Button(frame, text="浏览", command=self.choose_outputs_dir, width=8).pack(side=tk.LEFT, padx=4)

    def _add_labeled_spin(self, parent, label: str, variable, min_value: int, max_value: int):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=4)
        ttk.Label(frame, text=label, width=18).pack(side=tk.LEFT)
        ttk.Spinbox(frame, from_=min_value, to=max_value, textvariable=variable, width=10).pack(side=tk.LEFT)

    def log(self, message: str, level: str = "info") -> None:
        self.log_bus.write(level, message)

    def poll_logs(self) -> None:
        for event in self.log_bus.drain():
            ts = time.strftime("%H:%M:%S", time.localtime(event.created_at))
            self.log_text.insert(tk.END, f"[{ts}] {event.message}\n")
            self.log_text.see(tk.END)
        self.root.after(DEFAULT_LOG_POLL_MS, self.poll_logs)

    def clear_logs(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def current_settings(self) -> dict[str, Any]:
        config = dict(self.config)
        config["tokens_dir"] = self.tokens_dir_var.get().strip()
        config["outputs_dir"] = self.outputs_dir_var.get().strip()
        config["http_proxy"] = self.proxy_var.get().strip()
        config["refresh_workers"] = max(1, min(MAX_REFRESH_WORKERS, int(self.refresh_workers_var.get() or 1)))
        config["upload_workers"] = max(1, min(MAX_UPLOAD_WORKERS, int(self.upload_workers_var.get() or 1)))
        config["auto_refresh_interval_seconds"] = max(30, int(self.auto_interval_var.get() or 60))
        config["auto_refresh_threshold_seconds"] = max(30, int(self.auto_threshold_var.get() or 300))
        config["auto_auth_timeout_seconds"] = max(30, int(self.auto_auth_timeout_var.get() or DEFAULT_AUTH_TIMEOUT_SECONDS))
        config["open_browser_on_auto_auth"] = bool(self.open_browser_var.get())
        config["oauth"] = {
            "auth_url": self.oauth_auth_url_var.get().strip(),
            "token_url": self.oauth_token_url_var.get().strip(),
            "client_id": self.oauth_client_id_var.get().strip(),
            "redirect_uri": self.oauth_redirect_uri_var.get().strip(),
            "scope": self.oauth_scope_var.get().strip(),
        }
        config["integrations"] = {
            "cpa": {
                "api_url": self.cpa_url_var.get().strip(),
                "api_key": self.cpa_key_var.get().strip(),
                "container_name": self.cpa_container_var.get().strip() or "cli-proxy-api",
            },
            "sub2api": {
                "api_url": self.sub2api_url_var.get().strip(),
                "api_key": self.sub2api_key_var.get().strip(),
                "group_ids": self.sub2api_group_ids_var.get().strip(),
            },
        }
        return config

    def save_settings(self, reload_tokens: bool = True, notify: bool = True) -> None:
        self.config = self.current_settings()
        save_app_config(self.config)
        self.store = TokenStore(self.config)
        if notify:
            self.status_var.set("设置已保存")
            self.log("设置已保存")
        if reload_tokens:
            self.reload_tokens(save_first=False)

    def choose_tokens_dir(self) -> None:
        selected = filedialog.askdirectory(
            title="选择 Tokens 目录",
            initialdir=self.tokens_dir_var.get().strip() or ".",
            parent=self.root,
        )
        if selected:
            self.tokens_dir_var.set(selected)

    def choose_outputs_dir(self) -> None:
        selected = filedialog.askdirectory(
            title="选择输出目录",
            initialdir=self.outputs_dir_var.get().strip() or ".",
            parent=self.root,
        )
        if selected:
            self.outputs_dir_var.set(selected)

    def clear_filters(self) -> None:
        self.search_var.set("")
        self.plan_filter_var.set("全部标签")
        self.status_filter_var.set("全部状态")
        self.reload_tokens(save_first=False)

    def apply_quick_filter(self, plan: str, status: str = "全部状态") -> None:
        self.search_var.set("")
        self.plan_filter_var.set(plan)
        self.status_filter_var.set(status)
        self.reload_tokens(save_first=False)

    def reload_tokens(self, save_first: bool = True) -> None:
        if save_first:
            self.save_settings(reload_tokens=False, notify=False)
        selected_ids = set(self.token_tree.selection())
        for item in self.token_tree.get_children():
            self.token_tree.delete(item)
        all_records = self.store.load_all()
        self.records = self.filter_records(all_records)
        self.update_stats(all_records, self.records)
        for record in self.records:
            upload_summary = self.upload_summary(record)
            status = "已过期" if record["_is_expired"] else "有效"
            if record.get("uploads"):
                for target_state in record["uploads"].values():
                    if isinstance(target_state, dict) and not target_state.get("ok", True):
                        status = "上传异常" if status == "有效" else status
                        break
            iid = str(record.get("_filename") or record.get("email"))
            tags = ()
            if record["_is_expired"]:
                tags = ("expired",)
            elif record["_remaining_seconds"] < 600:
                tags = ("warning",)
            self.token_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", "Unknown"),
                    self.plan_label(record),
                    status,
                    record["_remaining_text"],
                    upload_summary,
                ),
                tags=tags,
            )
            if iid in selected_ids:
                self.token_tree.selection_add(iid)
        self.on_selection_changed()

    def filter_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.search_var.get().strip().lower()
        plan_filter = self.plan_filter_var.get().strip().lower()
        status_filter = self.status_filter_var.get().strip()
        filtered: list[dict[str, Any]] = []
        for record in records:
            email = str(record.get("email") or "").lower()
            plan_label = self.plan_label(record).lower()
            has_upload_error = any(
                isinstance(state, dict) and not state.get("ok", True)
                for state in (record.get("uploads") or {}).values()
            )
            status = "已过期" if record["_is_expired"] else "有效"
            if search and search not in email and search not in str(record.get("account_id") or "").lower():
                continue
            if plan_filter and plan_filter != "全部标签".lower() and plan_filter != plan_label:
                continue
            if status_filter == "有效" and record["_is_expired"]:
                continue
            if status_filter == "已过期" and not record["_is_expired"]:
                continue
            if status_filter == "上传异常" and not has_upload_error:
                continue
            filtered.append(record)
        return filtered

    def update_stats(self, all_records: list[dict[str, Any]], visible_records: list[dict[str, Any]]) -> None:
        totals = {
            "all": len(all_records),
            "visible": len(visible_records),
            "team": 0,
            "plus": 0,
            "free": 0,
            "other": 0,
        }
        for record in all_records:
            plan = str(record.get("_plan") or "unknown").strip().lower()
            if plan in {"team", "plus", "free"}:
                totals[plan] += 1
            else:
                totals["other"] += 1
        self.stats_var.set(
            f"全部 {totals['all']}  当前 {totals['visible']}  Team {totals['team']}  Plus {totals['plus']}  Free {totals['free']}  其他 {totals['other']}"
        )

    def populate_cpa_tree(self) -> None:
        for item in self.cpa_tree.get_children():
            self.cpa_tree.delete(item)
        self.cpa_row_index = {}
        counts = {"all": len(self.cpa_records), "active": 0, "error": 0}
        for idx, record in enumerate(self.cpa_records, start=1):
            status = str(record.get("status") or "").strip().lower()
            if status == "active":
                counts["active"] += 1
            elif status == "error":
                counts["error"] += 1
            iid = self._build_cpa_row_id(record, idx)
            self.cpa_row_index[iid] = record
            self.cpa_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", ""),
                    self.plan_label({"_plan": record.get("plan", "unknown")}),
                    record.get("status", ""),
                    record.get("last_refresh", ""),
                    record.get("next_retry_after", ""),
                ),
            )
        self.cpa_stats_var.set(f"CPA 账号 {counts['all']}  Active {counts['active']}  Error {counts['error']}")
        self.on_cpa_selection_changed()

    @staticmethod
    def _build_cpa_row_id(record: dict[str, Any], idx: int) -> str:
        email = str(record.get("email") or "").strip()
        name = str(record.get("name") or "").strip()
        provider = str(record.get("provider") or "").strip()
        return f"{email}|{provider}|{name or idx}"

    @staticmethod
    def _cpa_sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
        status = str(record.get("status") or "").strip().lower()
        status_rank = 3 if status == "active" else 2 if status == "refreshing" else 1 if status == "pending" else 0
        last_refresh = str(record.get("last_refresh") or "").strip()
        name = str(record.get("name") or "").strip()
        return (status_rank, last_refresh, name)

    def _build_cpa_email_index(self, records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in records:
            email = str(item.get("email") or "").strip().lower()
            if not email:
                continue
            grouped.setdefault(email, []).append(item)
        result: dict[str, dict[str, Any]] = {}
        for email, items in grouped.items():
            result[email] = sorted(items, key=self._cpa_sort_key, reverse=True)[0]
        return result

    def refresh_cpa_accounts(self) -> None:
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")

        def worker():
            records = fetch_cpa_accounts(settings, proxy_url=proxy)
            return {"records": records}

        def done(result):
            self.set_running(False, "CPA 刷新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                self.cpa_stats_var.set("CPA 加载失败")
                return
            self.cpa_records = result.get("records", [])
            self.cpa_index = self._build_cpa_email_index(self.cpa_records)
            self.populate_cpa_tree()
            self.log(f"CPA 列表已刷新，共 {len(self.cpa_records)} 条")

        self.run_background("正在连接 CPA", worker, done)

    def import_cpa_to_tokens(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)
        settings = dict(self.config)
        proxy = settings.get("http_proxy", "")

        def worker():
            return import_cpa_accounts_from_docker(settings, self.store, proxy_url=proxy)

        def done(result):
            self.set_running(False, "CPA 导入完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            summary = f"已导入 {result.get('imported', 0)}/{result.get('total', 0)}"
            if result.get("fail_count", 0):
                self.log(f"CPA 导入失败详情: {' | '.join(result.get('failures', [])[:10])}")
                summary += f"\n失败 {result.get('fail_count', 0)}"
            self.log(summary)
            self.reload_tokens(save_first=False)
            messagebox.showinfo("完成", summary)

        self.run_background("正在从 CPA 导入到 Tokens", worker, done)

    def on_cpa_selection_changed(self, _event=None) -> None:
        selection = self.cpa_tree.selection()
        if not selection:
            detail = "未选择 CPA 账号"
        else:
            key = selection[0]
            record = self.cpa_row_index.get(key, {})
            detail = f"""邮箱: {record.get('email', '')}
标签: {self.plan_label({'_plan': record.get('plan', 'unknown')})}
状态: {record.get('status', '')}
状态信息: {record.get('status_message', '') or '无'}
远端刷新时间: {record.get('last_refresh', '') or '无'}
下次重试: {record.get('next_retry_after', '') or '无'}
远端订阅到期: {record.get('subscription_active_until', '') or '无'}
Disabled: {record.get('disabled', False)}
Unavailable: {record.get('unavailable', False)}
Provider: {record.get('provider', '')}
文件名: {record.get('name', '')}
"""
        self.cpa_detail_text.config(state=tk.NORMAL)
        self.cpa_detail_text.delete("1.0", tk.END)
        self.cpa_detail_text.insert("1.0", detail)
        self.cpa_detail_text.config(state=tk.DISABLED)

    def organize_output_dirs(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)

        def worker():
            records = self.store.load_all()
            for record in records:
                export_record_payloads(self.store, record, self.config, log_fn=self.log)
            return {"count": len(records)}

        def done(result):
            self.set_running(False, "目录整理完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            self.log(f"已整理导出 {result['count']} 个账号文件")
            self.reload_tokens(save_first=False)
            messagebox.showinfo("完成", f"已整理导出 {result['count']} 个账号文件")

        self.run_background("正在整理 CPA 和 Sub2API 输出目录", worker, done)

    def cleanup_tokens_dir(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)

        def worker():
            return self.store.cleanup_tokens_directory()

        def done(result):
            self.set_running(False, "Tokens 清理完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            summary = (
                f"保留 {result.get('kept', 0)} 个账号文件\n"
                f"删除重复文件 {result.get('removed_files', 0)}\n"
                f"移动最佳文件 {result.get('moved_best_files', 0)}\n"
                f"移除旧目录 {result.get('removed_dirs', 0)}"
            )
            self.log(summary)
            self.reload_tokens(save_first=False)
            messagebox.showinfo("完成", summary)

        self.run_background("正在清理 Tokens 目录", worker, done)

    def upload_summary(self, record: dict[str, Any]) -> str:
        uploads = record.get("uploads") or {}
        parts: list[str] = []
        for key in ("cpa", "sub2api"):
            state = uploads.get(key) or {}
            if not state:
                continue
            parts.append(f"{key}:{'OK' if state.get('ok') else 'ERR'}")
        return " ".join(parts) or "-"

    def plan_label(self, record: dict[str, Any]) -> str:
        plan = str(record.get("_plan") or "unknown").strip().lower()
        mapping = {
            "team": "Team",
            "plus": "Plus",
            "free": "Free",
            "pro": "Pro",
            "enterprise": "Enterprise",
            "unknown": "Unknown",
        }
        return mapping.get(plan, plan.title() or "Unknown")

    def selected_records(self) -> list[dict[str, Any]]:
        selected = set(self.token_tree.selection())
        return [record for record in self.records if str(record.get("_filename") or record.get("email")) in selected]

    def primary_record(self) -> dict[str, Any] | None:
        records = self.selected_records()
        return records[0] if records else None

    def on_selection_changed(self, _event=None) -> None:
        record = self.primary_record()
        if not record:
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.insert("1.0", "未选择账号")
            self.detail_text.config(state=tk.DISABLED)
            return

        uploads = record.get("uploads") or {}
        upload_lines = []
        for key in ("cpa", "sub2api"):
            state = uploads.get(key) or {}
            if state:
                upload_lines.append(
                    f"{key}: {'成功' if state.get('ok') else '失败'} {state.get('updated_at', '')} {state.get('message', '')}".strip()
                )
        subscription = record.get("subscription") or {}
        cpa_remote = self.cpa_index.get(str(record.get("email") or "").strip().lower(), {})
        cpa_remote_text = "CPA 未加载或未找到对应账号"
        if cpa_remote:
            cpa_remote_text = (
                f"状态 {cpa_remote.get('status', '')}  "
                f"标签 {self.plan_label({'_plan': cpa_remote.get('plan', 'unknown')})}  "
                f"远端刷新 {cpa_remote.get('last_refresh', '') or '无'}"
            )
        detail = f"""邮箱: {record.get('email', 'Unknown')}
账号 ID: {record.get('account_id', 'Unknown')}
标签: {self.plan_label(record)}
标签来源: {subscription.get('source', '')}
订阅到期: {subscription.get('subscription_active_until', '') or '未知'}
状态: {'已过期' if record['_is_expired'] else '有效'}
剩余时间: {record['_remaining_text']}
最后刷新: {record.get('last_refresh', '')}
创建时间: {record.get('created_at', '')}
文件: {record.get('_filename', '')}

Access Token 前 60 位:
{str(record.get('access_token') or '')[:60]}...

Refresh Token 前 60 位:
{str(record.get('refresh_token') or '')[:60]}...

上传状态:
{chr(10).join(upload_lines) if upload_lines else '暂无'}

CPA 远端:
{cpa_remote_text}
"""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", detail)
        self.detail_text.config(state=tk.DISABLED)

    def set_running(self, running: bool, status: str = "") -> None:
        self.running_job = running
        self.status_var.set(status or ("任务进行中" if running else "就绪"))

    def run_background(self, status: str, worker, on_done):
        if self.running_job:
            messagebox.showinfo("提示", "已有任务在运行")
            return

        self.set_running(True, status)

        def runner():
            try:
                result = worker()
            except Exception as exc:
                traceback_text = traceback.format_exc(limit=5)
                self.log(f"任务异常: {exc}", "error")
                self.log(traceback_text, "error")
                result = {"error": str(exc)}
            self.root.after(0, lambda: on_done(result))

        threading.Thread(target=runner, daemon=True).start()

    def with_progress(self, job_name: str):
        def _progress(done: int, total_count: int, email: str):
            self.root.after(0, lambda: self.status_var.set(f"{job_name} {done}/{total_count} {email}"))
            self.log(f"{job_name} 进度 {done}/{total_count}: {email}")

        return _progress

    def refresh_selected(self) -> None:
        records = self.selected_records()
        if not records:
            messagebox.showerror("错误", "请先选择账号")
            return

        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")
        workers = min(len(records), int(settings.get("refresh_workers") or 1))

        def worker():
            return run_batch(
                records,
                workers=workers,
                job=lambda record: refresh_record(self.store, record, settings, proxy_url=proxy, log_fn=self.log),
                progress_cb=self.with_progress("刷新"),
            )

        def done(result):
            self.set_running(False, "刷新完成")
            self.reload_tokens()
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            messagebox.showinfo("完成", f"刷新完成\n成功: {result['success_count']}\n失败: {result['fail_count']}")

        self.run_background("正在刷新账号", worker, done)

    def refresh_all(self) -> None:
        if not self.records:
            messagebox.showinfo("提示", "没有账号")
            return
        self.token_tree.selection_set([str(record.get("_filename") or record.get("email")) for record in self.records])
        self.refresh_selected()

    def sync_selected_labels(self) -> None:
        records = self.selected_records()
        if not records:
            messagebox.showerror("错误", "请先选择账号")
            return
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")
        workers = min(len(records), int(settings.get("refresh_workers") or 1), 4)

        def worker():
            return run_batch(
                records,
                workers=workers,
                job=lambda record: sync_subscription(self.store, record, proxy_url=proxy, log_fn=self.log),
                progress_cb=self.with_progress("同步标签"),
            )

        def done(result):
            self.set_running(False, "标签同步完成")
            self.reload_tokens()
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            messagebox.showinfo("完成", f"同步完成\n成功: {result['success_count']}\n失败: {result['fail_count']}")

        self.run_background("正在同步标签", worker, done)

    def upload_selected(self) -> None:
        records = self.selected_records()
        if not records:
            messagebox.showerror("错误", "请先选择账号")
            return
        self.save_settings(reload_tokens=False, notify=False)
        target = self.upload_target_var.get().strip().lower()
        settings = dict(self.config)
        proxy = settings.get("http_proxy", "")
        workers = min(len(records), int(settings.get("upload_workers") or 1))

        def worker():
            return run_batch(
                records,
                workers=workers,
                job=lambda record: upload_record(self.store, record, settings, target=target, proxy_url=proxy, log_fn=self.log),
                progress_cb=self.with_progress(f"上传 {target}"),
            )

        def done(result):
            self.set_running(False, "上传完成")
            self.reload_tokens()
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            messagebox.showinfo("完成", f"上传 {target} 完成\n成功: {result['success_count']}\n失败: {result['fail_count']}")

        self.run_background(f"正在上传到 {target}", worker, done)

    def upload_all(self) -> None:
        if not self.records:
            messagebox.showinfo("提示", "没有账号")
            return
        self.token_tree.selection_set([str(record.get("_filename") or record.get("email")) for record in self.records])
        self.upload_selected()

    def delete_selected(self) -> None:
        records = self.selected_records()
        if not records:
            messagebox.showerror("错误", "请先选择账号")
            return
        if not messagebox.askyesno("确认", f"确定删除选中的 {len(records)} 个账号吗？"):
            return
        for record in records:
            self.store.delete(record.get("_filename", ""))
        self.log(f"已删除 {len(records)} 个账号")
        self.reload_tokens()

    def copy_to_clipboard(self, value: str, success_message: str) -> None:
        if not value:
            messagebox.showerror("错误", "内容为空")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set(success_message)

    def copy_access_token(self) -> None:
        record = self.primary_record()
        if not record:
            messagebox.showerror("错误", "请先选择账号")
            return
        self.copy_to_clipboard(str(record.get("access_token") or ""), "Access Token 已复制")

    def copy_refresh_token(self) -> None:
        record = self.primary_record()
        if not record:
            messagebox.showerror("错误", "请先选择账号")
            return
        self.copy_to_clipboard(str(record.get("refresh_token") or ""), "Refresh Token 已复制")

    def build_preview(self, format_name: str) -> None:
        record = self.primary_record()
        if not record:
            messagebox.showerror("错误", "请先选择账号")
            return
        self.save_settings(reload_tokens=False, notify=False)
        if format_name.upper() == "CPA":
            payload = to_cpa_payload(record)
            export_target = "cpa"
        else:
            payload = to_sub2api_payload(record, group_ids=self.sub2api_group_ids_var.get().strip())
            export_target = "sub2api"
        self.preview_text_value = json.dumps(payload, ensure_ascii=False, indent=2)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert("1.0", self.preview_text_value)
        export_path = self.store.export_payload(str(record.get("email") or ""), export_target, payload)
        self.log(f"已输出 {export_target} 文件: {export_path}")
        self.status_var.set(f"{format_name} 预览已生成")

    def build_preview_from_var(self) -> None:
        self.build_preview(self.preview_format_var.get().strip())

    def copy_preview(self) -> None:
        text = self.preview_text.get("1.0", tk.END).strip()
        self.copy_to_clipboard(text, "预览内容已复制")

    def import_payloads(self, payloads: list[dict[str, Any]], source: str) -> int:
        count = 0
        for payload in payloads:
            if source == "CPA":
                record = from_cpa_payload(payload)
            else:
                record = from_sub2api_payload(payload)
            if not record.get("access_token") and not record.get("refresh_token"):
                continue
            self.store.save_record(record)
            count += 1
        return count

    def import_from_clipboard(self) -> None:
        try:
            raw = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showerror("错误", "剪贴板为空")
            return
        self._import_text(raw, self.import_source_var.get().strip())

    def import_from_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="选择 JSON 文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
            parent=self.root,
        )
        if not file_path:
            return
        raw = Path(file_path).read_text(encoding="utf-8-sig")
        self._import_text(raw, self.import_source_var.get().strip())

    def _import_text(self, raw: str, source: str) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            messagebox.showerror("错误", f"JSON 解析失败: {exc}")
            return
        payloads = data if isinstance(data, list) else [data]
        payloads = [item for item in payloads if isinstance(item, dict)]
        count = self.import_payloads(payloads, source)
        self.log(f"已从 {source} 导入 {count} 条账号")
        self.reload_tokens()
        messagebox.showinfo("完成", f"已导入 {count} 条账号")

    def generate_manual_url(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)
        self.manual_oauth_start = generate_oauth_start(self.config)
        self.url_text.delete("1.0", tk.END)
        self.url_text.insert("1.0", self.manual_oauth_start.auth_url)
        self.copy_to_clipboard(self.manual_oauth_start.auth_url, "授权 URL 已复制")
        self.log("已生成手动授权 URL")

    def submit_callback(self) -> None:
        if not self.manual_oauth_start:
            messagebox.showerror("错误", "请先生成授权 URL")
            return
        callback_url = self.callback_entry.get().strip()
        if not callback_url:
            messagebox.showerror("错误", "请输入回调 URL")
            return
        self.save_settings(reload_tokens=False, notify=False)
        try:
            token_data = exchange_callback(
                callback_url,
                self.manual_oauth_start,
                self.config,
                proxy_url=self.config.get("http_proxy", ""),
            )
            path = self.store.save_token_response(token_data, metadata={"auth_mode": "manual"})
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
            self.log(f"手动授权失败: {exc}", "error")
            return
        self.log(f"手动授权成功: {path}")
        self.callback_entry.delete(0, tk.END)
        self.reload_tokens()
        messagebox.showinfo("完成", f"Token 已保存\n{path}")

    def start_auto_auth(self) -> None:
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")
        timeout = int(settings.get("auto_auth_timeout_seconds") or DEFAULT_AUTH_TIMEOUT_SECONDS)
        open_browser = bool(settings.get("open_browser_on_auto_auth", True))

        def worker():
            return browser_assisted_authorize(
                settings,
                proxy_url=proxy,
                timeout=timeout,
                open_browser=open_browser,
                log_fn=self.log,
            )

        def done(result):
            self.set_running(False, "自动授权结束")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            token_data = result["token_data"]
            path = self.store.save_token_response(token_data, metadata={"auth_mode": "auto_browser"})
            self.log(f"自动授权成功: {path}")
            self.reload_tokens()
            messagebox.showinfo("完成", f"自动授权成功\n{path}")

        self.run_background("正在等待自动授权回调", worker, done)

    def toggle_auto_refresh(self) -> None:
        if self.auto_refresh_running:
            self.auto_refresh_running = False
            self.auto_refresh_button.config(text="启动自动维护")
            self.status_var.set("自动维护已停止")
            self.log("自动维护已停止")
            return
        self.save_settings(reload_tokens=False, notify=False)
        self.auto_refresh_running = True
        self.auto_refresh_button.config(text="停止自动维护")
        self.log("自动维护已启动")
        self.auto_refresh_thread = threading.Thread(target=self.auto_refresh_worker, daemon=True)
        self.auto_refresh_thread.start()

    def auto_refresh_worker(self) -> None:
        while self.auto_refresh_running:
            try:
                settings = dict(self.config)
                if self.running_job:
                    time.sleep(2)
                    continue
                threshold = int(settings.get("auto_refresh_threshold_seconds") or 300)
                records = [record for record in self.store.load_all() if 0 < record["_remaining_seconds"] <= threshold and record.get("refresh_token")]
                if records:
                    self.log(f"自动维护命中 {len(records)} 个账号，开始刷新")
                    proxy = settings.get("http_proxy", "")
                    workers = min(len(records), int(settings.get("refresh_workers") or 1))
                    result = run_batch(
                        records,
                        workers=workers,
                        job=lambda record: refresh_record(self.store, record, settings, proxy_url=proxy, log_fn=self.log),
                        progress_cb=self.with_progress("自动维护"),
                    )
                    self.log(f"自动维护完成 成功={result['success_count']} 失败={result['fail_count']}")
                    self.root.after(0, lambda: self.reload_tokens(save_first=False))
            except Exception as exc:
                self.log(f"自动维护异常: {exc}", "error")
            sleep_seconds = int(settings.get("auto_refresh_interval_seconds") or 60)
            for _ in range(max(1, sleep_seconds)):
                if not self.auto_refresh_running:
                    break
                time.sleep(1)

    def update_ui_timer(self) -> None:
        if not self.running_job:
            self.reload_tokens(save_first=False)
        self.root.after(DEFAULT_UI_REFRESH_MS, self.update_ui_timer)


def run_app() -> None:
    root = tk.Tk()
    _apply_window_icon(root)
    TokenManagerGUI(root)
    root.mainloop()
