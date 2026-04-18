from __future__ import annotations

from typing import Any

import tkinter as tk
from tkinter import messagebox

from .integrations import fetch_cpa_accounts, import_cpa_accounts_from_docker
from .services import (
    delete_cpa_remote_records,
    refresh_cpa_remote_record,
    run_batch,
    set_cpa_remote_record_disabled,
)


class GUICPAMixin:
    def _cpa_message_summary(self, record: dict[str, Any], max_len: int = 90) -> str:
        raw = str(record.get("status_message") or "").strip().replace("\r", " ").replace("\n", " ")
        text = " ".join(raw.split())
        if not text:
            return "-"
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 1]}…"

    def _cpa_flags_text(self, record: dict[str, Any]) -> str:
        flags: list[str] = []
        if record.get("disabled"):
            flags.append("禁用")
        if record.get("unavailable"):
            flags.append("不可用")
        return " ".join(flags) or "-"

    def is_cpa_invalidated(self, record: dict[str, Any]) -> bool:
        message = str(record.get("status_message") or "").lower()
        return "token_invalidated" in message or "your authentication token has been invalidated" in message

    def clear_cpa_filters(self) -> None:
        self.cpa_search_var.set("")
        self.cpa_plan_filter_var.set("全部标签")
        self.cpa_status_filter_var.set("全部状态")
        self.populate_cpa_tree()

    def filter_cpa_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.cpa_search_var.get().strip().lower()
        plan_filter = self.cpa_plan_filter_var.get().strip().lower()
        status_filter = self.cpa_status_filter_var.get().strip().lower()
        filtered: list[dict[str, Any]] = []
        for record in records:
            email = str(record.get("email") or "").strip().lower()
            name = str(record.get("name") or "").strip().lower()
            status = str(record.get("status") or "").strip().lower()
            message = str(record.get("status_message") or "").strip().lower()
            plan_label = self.plan_label({"_plan": record.get("plan", "unknown")}).lower()
            if search and search not in email and search not in name and search not in message:
                continue
            if plan_filter and plan_filter != "全部标签".lower() and plan_filter != plan_label:
                continue
            if status_filter == "disabled" and not record.get("disabled"):
                continue
            if status_filter == "unavailable" and not record.get("unavailable"):
                continue
            if status_filter not in {"", "全部状态".lower(), "disabled", "unavailable"} and status_filter != status:
                continue
            filtered.append(record)
        return filtered

    def populate_cpa_tree(self) -> None:
        for item in self.cpa_tree.get_children():
            self.cpa_tree.delete(item)
        for item in self.cpa_invalidated_tree.get_children():
            self.cpa_invalidated_tree.delete(item)

        self.cpa_row_index = {}
        self.cpa_invalidated_row_index = {}
        self.filtered_cpa_records = self.filter_cpa_records(self.cpa_records)
        self.invalidated_cpa_records = [record for record in self.cpa_records if self.is_cpa_invalidated(record)]

        active_count = 0
        error_count = 0
        unavailable_count = 0
        disabled_count = 0

        for idx, record in enumerate(self.filtered_cpa_records, start=1):
            status = str(record.get("status") or "").strip().lower()
            if status == "active":
                active_count += 1
            elif status == "error":
                error_count += 1
            if record.get("unavailable"):
                unavailable_count += 1
            if record.get("disabled"):
                disabled_count += 1

            iid = self._build_cpa_row_id(record, idx)
            self.cpa_row_index[iid] = record
            tags: tuple[str, ...] = ()
            if self.is_cpa_invalidated(record):
                tags = ("invalidated",)
            elif status == "error":
                tags = ("error",)
            elif record.get("disabled") or record.get("unavailable"):
                tags = ("warning",)
            self.cpa_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", ""),
                    self.plan_label({"_plan": record.get("plan", "unknown")}),
                    record.get("status", ""),
                    self._cpa_flags_text(record),
                    record.get("last_refresh", ""),
                    record.get("next_retry_after", ""),
                    self._cpa_message_summary(record),
                ),
                tags=tags,
            )

        for idx, record in enumerate(self.invalidated_cpa_records, start=1):
            iid = f"inv_{self._build_cpa_row_id(record, idx)}"
            self.cpa_invalidated_row_index[iid] = record
            self.cpa_invalidated_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", ""),
                    self.plan_label({"_plan": record.get("plan", "unknown")}),
                    record.get("status", ""),
                    record.get("next_retry_after", ""),
                    self._cpa_message_summary(record, max_len=140),
                ),
                tags=("invalidated",),
            )

        self.cpa_stats_var.set(
            f"CPA 账号 {len(self.cpa_records)}  当前 {len(self.filtered_cpa_records)}  Error {sum(1 for item in self.cpa_records if str(item.get('status') or '').lower() == 'error')}  不可用 {sum(1 for item in self.cpa_records if item.get('unavailable'))}  封禁 {len(self.invalidated_cpa_records)}"
        )
        self.cpa_pool_stats_var.set(
            f"当前 {len(self.filtered_cpa_records)}  Active {active_count}  Error {error_count}  禁用 {disabled_count}  不可用 {unavailable_count}"
        )
        self.cpa_invalidated_stats_var.set(f"封禁记录 {len(self.invalidated_cpa_records)}")
        self.on_cpa_selection_changed()
        self.on_cpa_invalidated_selection_changed()

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

    def selected_cpa_pool_records(self) -> list[dict[str, Any]]:
        selected = set(self.cpa_tree.selection())
        return [record for iid, record in self.cpa_row_index.items() if iid in selected]

    def selected_cpa_invalidated_records(self) -> list[dict[str, Any]]:
        selected = set(self.cpa_invalidated_tree.selection())
        return [record for iid, record in self.cpa_invalidated_row_index.items() if iid in selected]

    def _set_cpa_detail(self, widget, record: dict[str, Any] | None, *, empty_text: str) -> None:
        if not record:
            detail = empty_text
        else:
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
路径: {record.get('path', '')}
"""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", detail)
        widget.config(state=tk.DISABLED)

    def on_cpa_selection_changed(self, _event=None) -> None:
        selection = self.cpa_tree.selection()
        record = self.cpa_row_index.get(selection[0], {}) if selection else None
        self._set_cpa_detail(self.cpa_detail_text, record, empty_text="未选择 CPA 账号")

    def on_cpa_invalidated_selection_changed(self, _event=None) -> None:
        selection = self.cpa_invalidated_tree.selection()
        record = self.cpa_invalidated_row_index.get(selection[0], {}) if selection else None
        self._set_cpa_detail(self.cpa_invalidated_detail_text, record, empty_text="未选择封禁记录")

    def refresh_selected_cpa_remote(self) -> None:
        records = self.selected_cpa_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 CPA 账号")
            return
        self._refresh_cpa_remote_records(records, label="选中")

    def refresh_filtered_cpa_remote(self) -> None:
        records = list(self.filtered_cpa_records)
        if not records:
            messagebox.showinfo("提示", "当前筛选下没有账号")
            return
        self._refresh_cpa_remote_records(records, label="当前筛选")

    def _refresh_cpa_remote_records(self, records: list[dict[str, Any]], *, label: str) -> None:
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")
        workers = min(len(records), max(1, int(settings.get("refresh_workers") or 1)), 8)

        def worker():
            return run_batch(
                records,
                workers=workers,
                job=lambda record: refresh_cpa_remote_record(record, settings, proxy_url=proxy, log_fn=self.log),
                progress_cb=self.with_progress("远端刷新"),
            )

        def done(result):
            self.set_running(False, "远端刷新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            messagebox.showinfo("完成", f"{label}远端刷新完成\n成功: {result['success_count']}\n失败: {result['fail_count']}")
            self.refresh_cpa_accounts()

        self.run_background("正在刷新远端 CPA 令牌", worker, done)

    def set_selected_cpa_disabled(self, disabled: bool) -> None:
        records = self.selected_cpa_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 CPA 账号")
            return
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")
        workers = min(len(records), 8)

        def worker():
            return run_batch(
                records,
                workers=workers,
                job=lambda record: set_cpa_remote_record_disabled(
                    record,
                    settings,
                    disabled=disabled,
                    proxy_url=proxy,
                    log_fn=self.log,
                ),
                progress_cb=self.with_progress("禁用状态更新"),
            )

        def done(result):
            self.set_running(False, "禁用状态更新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            messagebox.showinfo(
                "完成",
                f"{'禁用' if disabled else '启用'}完成\n成功: {result['success_count']}\n失败: {result['fail_count']}",
            )
            self.refresh_cpa_accounts()

        self.run_background(f"正在{'禁用' if disabled else '启用'}远端 CPA", worker, done)

    def delete_selected_cpa_records(self) -> None:
        records = self.selected_cpa_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 CPA 账号")
            return
        self._delete_cpa_records(records, title=f"确定删除选中的 {len(records)} 个远端 CPA 账号吗？")

    def delete_selected_invalidated_cpa_records(self) -> None:
        records = self.selected_cpa_invalidated_records()
        if not records:
            messagebox.showerror("错误", "请先选择封禁记录")
            return
        self._delete_cpa_records(records, title=f"确定删除选中的 {len(records)} 个封禁账号吗？")

    def delete_all_invalidated_cpa_records(self) -> None:
        records = list(self.invalidated_cpa_records)
        if not records:
            messagebox.showinfo("提示", "当前没有封禁记录")
            return
        self._delete_cpa_records(records, title=f"确定删除全部 {len(records)} 个封禁账号吗？")

    def _delete_cpa_records(self, records: list[dict[str, Any]], *, title: str) -> None:
        if not messagebox.askyesno("确认", title):
            return
        self.save_settings(reload_tokens=False, notify=False)
        settings = dict(self.config)
        proxy = settings.get("http_proxy", "")

        def worker():
            ok, message = delete_cpa_remote_records(records, settings, proxy_url=proxy, log_fn=self.log)
            return {"ok": ok, "message": message, "count": len(records)}

        def done(result):
            self.set_running(False, "远端删除完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            if not result.get("ok"):
                messagebox.showerror("错误", result.get("message", "删除失败"))
                return
            messagebox.showinfo("完成", f"已删除 {result.get('count', 0)} 个远端 CPA 账号")
            self.refresh_cpa_accounts()

        self.run_background("正在删除远端 CPA 账号", worker, done)
