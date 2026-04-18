from __future__ import annotations

import threading
import time
import traceback
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import save_app_config
from .constants import (
    DEFAULT_AUTH_TIMEOUT_SECONDS,
    DEFAULT_LOG_POLL_MS,
    DEFAULT_UI_REFRESH_MS,
    MAX_REFRESH_WORKERS,
    MAX_UPLOAD_WORKERS,
)
from .store import TokenStore


class GUICommonMixin:
    def _configure_styles(self) -> None:
        self.palette = {
            "bg": "#edf3f5",
            "card": "#fbfdfe",
            "card_alt": "#f3f7f9",
            "border": "#d7e1e7",
            "text": "#203039",
            "muted": "#647681",
            "primary": "#0f766e",
            "primary_hover": "#115e59",
            "primary_soft": "#d9f0ec",
            "accent": "#c47a22",
            "accent_soft": "#f9ead7",
            "status_bg": "#e1f0ec",
        }
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        base_font = ("Microsoft YaHei UI", 10)
        bold_font = ("Microsoft YaHei UI", 10, "bold")
        hero_font = ("Microsoft YaHei UI", 21, "bold")

        self.root.configure(bg=self.palette["bg"])
        style.configure(".", font=base_font, background=self.palette["bg"], foreground=self.palette["text"])
        style.configure("TFrame", background=self.palette["bg"])
        style.configure("Shell.TFrame", background=self.palette["bg"])
        style.configure("Panel.TFrame", background=self.palette["card"])
        style.configure("Card.TFrame", background=self.palette["card"])
        style.configure("CardHost.TFrame", background=self.palette["bg"])
        style.configure("StatusBar.TFrame", background=self.palette["card_alt"])
        style.configure("TLabel", background=self.palette["bg"], foreground=self.palette["text"])
        style.configure("Card.TLabel", background=self.palette["card"], foreground=self.palette["text"])
        style.configure("CardSubtle.TLabel", background=self.palette["card"], foreground=self.palette["muted"])
        style.configure("SectionTitle.TLabel", background=self.palette["card"], foreground=self.palette["text"], font=("Microsoft YaHei UI", 12, "bold"))
        style.configure("SectionBody.TLabel", background=self.palette["card"], foreground=self.palette["muted"])
        style.configure("Stats.TLabel", background=self.palette["card"], foreground=self.palette["muted"], font=bold_font)
        style.configure("Chip.TLabel", background=self.palette["card_alt"], foreground=self.palette["muted"], font=("Microsoft YaHei UI", 9, "bold"), padding=(10, 5))
        style.configure("StatusChip.TLabel", background=self.palette["status_bg"], foreground=self.palette["primary"], font=("Microsoft YaHei UI", 9, "bold"), padding=(12, 6))
        style.configure("StatusBarLabel.TLabel", background=self.palette["card_alt"], foreground=self.palette["muted"], font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("StatusBarValue.TLabel", background=self.palette["card_alt"], foreground=self.palette["text"], font=bold_font)
        style.configure("TCheckbutton", background=self.palette["card"], foreground=self.palette["text"])
        style.map("TCheckbutton", background=[("active", self.palette["card"])], foreground=[("active", self.palette["text"])])
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
            font=bold_font,
            foreground=self.palette["text"],
            background=self.palette["card"],
        )
        style.configure(
            "Inner.TLabelframe",
            background=self.palette["card_alt"],
            borderwidth=1,
            relief="solid",
            bordercolor=self.palette["border"],
            lightcolor=self.palette["border"],
            darkcolor=self.palette["border"],
        )
        style.configure(
            "Inner.TLabelframe.Label",
            font=bold_font,
            foreground=self.palette["text"],
            background=self.palette["card_alt"],
        )
        style.configure(
            "TButton",
            padding=(11, 8),
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
            padding=(11, 8),
            font=bold_font,
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
        style.configure("Accent.TLabel", font=bold_font, foreground=self.palette["muted"], background=self.palette["bg"])
        style.configure("Hero.TLabel", font=hero_font, foreground=self.palette["text"], background=self.palette["card"])
        style.configure("SubHero.TLabel", font=base_font, foreground=self.palette["muted"], background=self.palette["card"])
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
            rowheight=32,
            font=base_font,
            background=self.palette["card"],
            fieldbackground=self.palette["card"],
            foreground=self.palette["text"],
            bordercolor=self.palette["border"],
        )
        style.configure(
            "Treeview.Heading",
            font=bold_font,
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
            padding=(16, 10),
            font=bold_font,
            background=self.palette["card_alt"],
            foreground=self.palette["muted"],
            bordercolor=self.palette["border"],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.palette["card"]), ("active", self.palette["accent_soft"])],
            foreground=[("selected", self.palette["text"]), ("active", self.palette["text"])],
        )

    def _add_labeled_entry(self, parent, label: str, variable, browse: bool = False, browse_outputs: bool = False, show: str | None = None):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill=tk.X, pady=4)
        ttk.Label(frame, text=label, width=18, style="Card.TLabel").pack(side=tk.LEFT)
        entry_kwargs: dict[str, Any] = {"textvariable": variable}
        if show is not None:
            entry_kwargs["show"] = show
        ttk.Entry(frame, **entry_kwargs).pack(side=tk.LEFT, fill=tk.X, expand=True)
        if browse:
            ttk.Button(frame, text="浏览", command=self.choose_tokens_dir, width=8).pack(side=tk.LEFT, padx=4)
        if browse_outputs:
            ttk.Button(frame, text="浏览", command=self.choose_outputs_dir, width=8).pack(side=tk.LEFT, padx=4)

    def _add_labeled_spin(self, parent, label: str, variable, min_value: int, max_value: int):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill=tk.X, pady=4)
        ttk.Label(frame, text=label, width=18, style="Card.TLabel").pack(side=tk.LEFT)
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
        def _int(var, default: int) -> int:
            try:
                return int(var.get() or default)
            except (ValueError, TypeError):
                return default

        config = dict(self.config)
        integrations = dict(config.get("integrations") or {})
        sub2api_existing = dict(integrations.get("sub2api") or {})
        config["tokens_dir"] = self.tokens_dir_var.get().strip()
        config["outputs_dir"] = self.outputs_dir_var.get().strip()
        config["http_proxy"] = self.proxy_var.get().strip()
        config["refresh_workers"] = max(1, min(MAX_REFRESH_WORKERS, _int(self.refresh_workers_var, 6)))
        config["upload_workers"] = max(1, min(MAX_UPLOAD_WORKERS, _int(self.upload_workers_var, 4)))
        config["auth_2fa_live_workers"] = max(1, min(MAX_REFRESH_WORKERS, _int(self.auth2fa_workers_var, 3)))
        config["auth_2fa_live_save_token"] = bool(self.auth2fa_save_token_var.get())
        config["auto_refresh_interval_seconds"] = max(30, _int(self.auto_interval_var, 60))
        config["auto_refresh_threshold_seconds"] = max(30, _int(self.auto_threshold_var, 300))
        config["auto_auth_timeout_seconds"] = max(30, _int(self.auto_auth_timeout_var, DEFAULT_AUTH_TIMEOUT_SECONDS))
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
                "admin_email": self.sub2api_admin_email_var.get().strip(),
                "admin_password": self.sub2api_admin_password_var.get().strip(),
                "access_token": str(sub2api_existing.get("access_token") or "").strip(),
                "refresh_token": str(sub2api_existing.get("refresh_token") or "").strip(),
                "token_expires_at": int(sub2api_existing.get("token_expires_at") or 0),
            },
        }
        return config

    def save_settings(self, reload_tokens: bool = True, notify: bool = True) -> None:
        config = self.current_settings()
        with self._state_lock:
            self.config = config
            self.store = TokenStore(config)
        save_app_config(config)
        if notify:
            self.status_var.set("设置已保存")
            self.log("设置已保存")
        if reload_tokens:
            self.reload_tokens(save_first=False)

    def persist_runtime_settings(self, settings: dict[str, Any]) -> None:
        with self._state_lock:
            self.config = settings
            self.store = TokenStore(settings)
        save_app_config(settings)

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

    def set_running(self, running: bool, status: str = "") -> None:
        with self._running_job_lock:
            self.running_job = running
        self.status_var.set(status or ("任务进行中" if running else "就绪"))

    def is_running(self) -> bool:
        with self._running_job_lock:
            return self.running_job

    def run_background(self, status: str, worker, on_done):
        with self._running_job_lock:
            if self.running_job:
                messagebox.showinfo("提示", "已有任务在运行")
                return
            self.running_job = True
        self.status_var.set(status)

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

    def update_ui_timer(self) -> None:
        if not self.is_running() and not self.token_tree.selection():
            self.reload_tokens(save_first=False)
        self.root.after(DEFAULT_UI_REFRESH_MS, self.update_ui_timer)
