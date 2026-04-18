from __future__ import annotations

import threading
import time
from pathlib import Path

from tkinter import filedialog, messagebox

from tools.auth_2fa_live import parse_account_lines, run_authorize_batch_lines
from .constants import DEFAULT_AUTH_TIMEOUT_SECONDS
from .oauth import browser_assisted_authorize, exchange_callback, generate_oauth_start
from .services import refresh_record, run_batch


class GUIAuthMixin:
    def import_auth2fa_accounts_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="选择 2FA 授权账号文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            parent=self.root,
        )
        if not selected:
            return
        try:
            text = Path(selected).read_text(encoding="utf-8-sig")
        except Exception as exc:
            messagebox.showerror("错误", str(exc))
            self.log(f"读取 2FA 账号文件失败: {exc}", "error")
            return
        self.auth2fa_input.delete("1.0", "end")
        self.auth2fa_input.insert("1.0", text)
        self.auth2fa_output_var.set(f"已导入 {selected}")
        self.update_auth2fa_input_stats()
        self.log(f"已导入 2FA 账号文件: {selected}")

    def clear_auth2fa_accounts_text(self) -> None:
        self.auth2fa_input.delete("1.0", "end")
        self.auth2fa_output_var.set("")
        self.update_auth2fa_input_stats()

    def update_auth2fa_input_stats(self) -> None:
        raw_text = self.auth2fa_input.get("1.0", "end")
        line_count = sum(1 for line in raw_text.splitlines() if str(line or "").strip() and not str(line or "").strip().startswith("#"))
        accounts, errors = parse_account_lines(raw_text)
        self.auth2fa_stats_var.set(f"待授权 {len(accounts)}  无效 {len(errors)}  原始 {line_count}")

    def start_auth2fa_batch(self) -> None:
        raw_text = self.auth2fa_input.get("1.0", "end")
        accounts, errors = parse_account_lines(raw_text)
        if not accounts:
            messagebox.showerror("错误", "请先导入账号，格式为 账号----密码----2FA密匙")
            self.update_auth2fa_input_stats()
            return

        self.save_settings(reload_tokens=False, notify=False)
        settings = self.current_settings()
        workers = max(1, int(settings.get("auth_2fa_live_workers") or 1))
        save_token = bool(settings.get("auth_2fa_live_save_token", False))
        output_dir = str((settings.get("outputs_dir") or "")).strip()
        save_dir = None if not output_dir else str(Path(output_dir).expanduser() / "auth_2fa_live")

        def gui_log(message: str) -> None:
            self.log(message)

        def progress(done: int, total_count: int, email: str) -> None:
            self.root.after(0, lambda: self.status_var.set(f"2FA授权 {done}/{total_count} {email}"))
            self.root.after(0, lambda: self.auth2fa_stats_var.set(f"执行中 {done}/{total_count}"))

        def worker():
            return run_authorize_batch_lines(
                raw_text,
                settings,
                workers=workers,
                save_dir=save_dir,
                save_token=save_token,
                include_secrets=False,
                quiet=True,
                log_fn=gui_log,
                progress_cb=progress,
            )

        def done(result):
            self.set_running(False, "2FA 批量授权结束")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            summary_path = str(result.get("summary_path") or "")
            self.auth2fa_output_var.set(summary_path)
            self.auth2fa_stats_var.set(
                f"完成 成功 {int(result.get('success_count') or 0)} 失败 {int(result.get('fail_count') or 0)}  无效 {int(result.get('input_error_count') or 0)}"
            )
            if save_token and int(result.get("success_count") or 0) > 0:
                self.reload_tokens(save_first=False)
            self.log(
                f"2FA 批量授权完成 成功={int(result.get('success_count') or 0)} 失败={int(result.get('fail_count') or 0)} 无效={int(result.get('input_error_count') or 0)}"
            )
            if summary_path:
                self.log(f"2FA 批量汇总: {summary_path}")
            messagebox.showinfo(
                "完成",
                f"成功 {int(result.get('success_count') or 0)} 个\n"
                f"失败 {int(result.get('fail_count') or 0)} 个\n"
                f"无效 {int(result.get('input_error_count') or 0)} 行\n"
                f"{summary_path}",
            )

        self.run_background("正在执行 2FA 批量授权", worker, done)

    def generate_manual_url(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)
        self.manual_oauth_start = generate_oauth_start(self.config)
        self.url_text.delete("1.0", "end")
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
        self.callback_entry.delete(0, "end")
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
            settings = None
            try:
                with self._state_lock:
                    settings = dict(self.config)
                    store_snapshot = self.store
                if self.is_running():
                    time.sleep(2)
                    continue
                threshold = int(settings.get("auto_refresh_threshold_seconds") or 300)
                records = [record for record in store_snapshot.load_all() if 0 < record["_remaining_seconds"] <= threshold and record.get("refresh_token")]
                if records:
                    self.log(f"自动维护命中 {len(records)} 个账号，开始刷新")
                    proxy = settings.get("http_proxy", "")
                    workers = min(len(records), int(settings.get("refresh_workers") or 1))
                    result = run_batch(
                        records,
                        workers=workers,
                        job=lambda record: refresh_record(store_snapshot, record, settings, proxy_url=proxy, log_fn=self.log),
                        progress_cb=self.with_progress("自动维护"),
                    )
                    self.log(f"自动维护完成 成功={result['success_count']} 失败={result['fail_count']}")
                    self.root.after(0, lambda: self.reload_tokens(save_first=False))
            except Exception as exc:
                self.log(f"自动维护异常: {exc}", "error")
            sleep_seconds = int((settings or {}).get("auto_refresh_interval_seconds") or 60)
            for _ in range(max(1, sleep_seconds)):
                if not self.auto_refresh_running:
                    break
                time.sleep(1)
