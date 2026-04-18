from __future__ import annotations

from typing import Any

import tkinter as tk
from tkinter import messagebox

from .services import (
    delete_sub2api_remote_records,
    fetch_sub2api_remote_snapshot,
    is_sub2api_invalidated,
    refresh_sub2api_remote_records,
    set_sub2api_remote_records_status,
)


class GUISub2APIMixin:
    def _sub2api_error_summary(self, record: dict[str, Any], max_len: int = 96) -> str:
        raw = str(record.get("error_message") or "").strip().replace("\r", " ").replace("\n", " ")
        text = " ".join(raw.split())
        if not text:
            return "-"
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 1]}…"

    def _sub2api_groups_text(self, record: dict[str, Any], max_len: int = 32) -> str:
        groups = [str(item).strip() for item in (record.get("group_names") or []) if str(item).strip()]
        text = ", ".join(groups) or "-"
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 1]}…"

    def _sub2api_flags_text(self, record: dict[str, Any]) -> str:
        flags: list[str] = []
        if not record.get("schedulable", True):
            flags.append("停调度")
        if record.get("auto_pause_on_expired"):
            flags.append("到期暂停")
        if record.get("proxy_id"):
            flags.append("代理")
        return " ".join(flags) or "-"

    def clear_sub2api_filters(self) -> None:
        self.sub2api_search_var.set("")
        self.sub2api_group_filter_var.set("全部分组")
        self.sub2api_status_filter_var.set("全部状态")
        self.sub2api_type_filter_var.set("全部类型")
        self.populate_sub2api_tree()

    def filter_sub2api_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.sub2api_search_var.get().strip().lower()
        group_filter = self.sub2api_group_filter_var.get().strip().lower()
        status_filter = self.sub2api_status_filter_var.get().strip().lower()
        type_filter = self.sub2api_type_filter_var.get().strip().lower()
        filtered: list[dict[str, Any]] = []
        for record in records:
            email = str(record.get("email") or "").strip().lower()
            name = str(record.get("name") or "").strip().lower()
            groups = " ".join(str(item).strip().lower() for item in (record.get("group_names") or []))
            error_message = str(record.get("error_message") or "").strip().lower()
            record_type = str(record.get("type") or "").strip().lower()
            status = str(record.get("status") or "").strip().lower()
            if search and search not in email and search not in name and search not in groups and search not in error_message:
                continue
            if group_filter and group_filter != "全部分组".lower():
                group_names = [str(item).strip().lower() for item in (record.get("group_names") or [])]
                if group_filter not in group_names:
                    continue
            if type_filter and type_filter != "全部类型".lower() and type_filter != record_type:
                continue
            if status_filter == "invalidated" and not is_sub2api_invalidated(record):
                continue
            if status_filter == "unschedulable" and record.get("schedulable", True):
                continue
            if status_filter not in {"", "全部状态".lower(), "invalidated", "unschedulable"} and status_filter != status:
                continue
            filtered.append(record)
        return filtered

    def _update_sub2api_group_filter_values(self) -> None:
        values = ["全部分组"]
        values.extend(sorted({str(item.get("name") or "").strip() for item in self.sub2api_groups if str(item.get("name") or "").strip()}))
        if hasattr(self, "sub2api_group_combo"):
            self.sub2api_group_combo.configure(values=values)
        current = self.sub2api_group_filter_var.get().strip()
        if current and current not in values:
            self.sub2api_group_filter_var.set("全部分组")

    def populate_sub2api_tree(self) -> None:
        for item in self.sub2api_tree.get_children():
            self.sub2api_tree.delete(item)
        for item in self.sub2api_invalidated_tree.get_children():
            self.sub2api_invalidated_tree.delete(item)

        self.sub2api_row_index = {}
        self.sub2api_invalidated_row_index = {}
        self.filtered_sub2api_records = self.filter_sub2api_records(self.sub2api_records)
        self.invalidated_sub2api_records = [record for record in self.sub2api_records if is_sub2api_invalidated(record)]
        self._update_sub2api_group_filter_values()

        active_count = 0
        inactive_count = 0
        error_count = 0
        unschedulable_count = 0

        for idx, record in enumerate(self.filtered_sub2api_records, start=1):
            status = str(record.get("status") or "").strip().lower()
            if status == "active":
                active_count += 1
            elif status == "inactive":
                inactive_count += 1
            elif status == "error":
                error_count += 1
            if not record.get("schedulable", True):
                unschedulable_count += 1

            iid = self._build_sub2api_row_id(record, idx)
            self.sub2api_row_index[iid] = record
            tags: tuple[str, ...] = ()
            if is_sub2api_invalidated(record):
                tags = ("invalidated",)
            elif status == "error":
                tags = ("error",)
            elif not record.get("schedulable", True) or status == "inactive":
                tags = ("warning",)
            self.sub2api_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", ""),
                    self._sub2api_groups_text(record),
                    record.get("status", ""),
                    record.get("type", ""),
                    self._sub2api_flags_text(record),
                    record.get("expires_at_text", ""),
                    record.get("last_used_at", ""),
                    self._sub2api_error_summary(record),
                ),
                tags=tags,
            )

        for idx, record in enumerate(self.invalidated_sub2api_records, start=1):
            iid = f"inv_{self._build_sub2api_row_id(record, idx)}"
            self.sub2api_invalidated_row_index[iid] = record
            self.sub2api_invalidated_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.get("email", ""),
                    self._sub2api_groups_text(record, max_len=40),
                    record.get("status", ""),
                    record.get("expires_at_text", ""),
                    self._sub2api_error_summary(record, max_len=140),
                ),
                tags=("invalidated",),
            )

        self.sub2api_stats_var.set(
            f"Sub2API 账号 {len(self.sub2api_records)}  当前 {len(self.filtered_sub2api_records)}  Active {sum(1 for item in self.sub2api_records if str(item.get('status') or '').lower() == 'active')}  Error {sum(1 for item in self.sub2api_records if str(item.get('status') or '').lower() == 'error')}  失效 {len(self.invalidated_sub2api_records)}"
        )
        self.sub2api_pool_stats_var.set(
            f"当前 {len(self.filtered_sub2api_records)}  Active {active_count}  Inactive {inactive_count}  Error {error_count}  停调度 {unschedulable_count}"
        )
        self.sub2api_invalidated_stats_var.set(f"失效记录 {len(self.invalidated_sub2api_records)}")
        self.on_sub2api_selection_changed()
        self.on_sub2api_invalidated_selection_changed()

    @staticmethod
    def _build_sub2api_row_id(record: dict[str, Any], idx: int) -> str:
        return f"{int(record.get('id') or 0)}|{str(record.get('email') or record.get('name') or idx).strip()}"

    @staticmethod
    def _sub2api_sort_key(record: dict[str, Any]) -> tuple[int, int, str]:
        status = str(record.get("status") or "").strip().lower()
        status_rank = 3 if status == "active" else 2 if status == "inactive" else 1 if status == "error" else 0
        schedulable_rank = 1 if record.get("schedulable", True) else 0
        name = str(record.get("email") or record.get("name") or "").strip()
        return (status_rank, schedulable_rank, name)

    def _build_sub2api_email_index(self, records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in records:
            email = str(item.get("email") or "").strip().lower()
            if not email:
                continue
            grouped.setdefault(email, []).append(item)
        result: dict[str, dict[str, Any]] = {}
        for email, items in grouped.items():
            result[email] = sorted(items, key=self._sub2api_sort_key, reverse=True)[0]
        return result

    def refresh_sub2api_accounts(self) -> None:
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")

        def worker():
            return fetch_sub2api_remote_snapshot(settings, proxy_url=proxy, log_fn=self.log)

        def done(result):
            self.set_running(False, "Sub2API 刷新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                self.sub2api_stats_var.set("Sub2API 加载失败")
                return
            self.persist_runtime_settings(settings)
            self.sub2api_groups = result.get("groups", [])
            self.sub2api_records = result.get("records", [])
            self.sub2api_index = self._build_sub2api_email_index(self.sub2api_records)
            self.populate_sub2api_tree()
            self.log(f"Sub2API 列表已刷新，共 {len(self.sub2api_records)} 条")

        self.run_background("正在连接 Sub2API", worker, done)

    def selected_sub2api_pool_records(self) -> list[dict[str, Any]]:
        selected = set(self.sub2api_tree.selection())
        return [record for iid, record in self.sub2api_row_index.items() if iid in selected]

    def selected_sub2api_invalidated_records(self) -> list[dict[str, Any]]:
        selected = set(self.sub2api_invalidated_tree.selection())
        return [record for iid, record in self.sub2api_invalidated_row_index.items() if iid in selected]

    def _set_sub2api_detail(self, widget, record: dict[str, Any] | None, *, empty_text: str) -> None:
        if not record:
            detail = empty_text
        else:
            credentials = record.get("credentials") or {}
            detail = f"""邮箱: {record.get('email', '')}
名称: {record.get('name', '')}
账号 ID: {record.get('id', '')}
平台: {record.get('platform', '')}
类型: {record.get('type', '')}
状态: {record.get('status', '')}
分组: {', '.join(record.get('group_names') or []) or '无'}
Schedulable: {record.get('schedulable', True)}
到期时间: {record.get('expires_at_text', '') or record.get('expires_at', '') or '无'}
最后使用: {record.get('last_used_at', '') or '无'}
限流恢复: {record.get('rate_limit_reset_at', '') or '无'}
临时停调度: {record.get('temp_unschedulable_until', '') or '无'}
并发: {record.get('concurrency', 0)}
优先级: {record.get('priority', 0)}
Proxy ID: {record.get('proxy_id', '')}

错误信息:
{record.get('error_message', '') or '无'}

Credential Keys:
{', '.join(sorted(str(key) for key in credentials.keys())) or '无'}
"""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", detail)
        widget.config(state=tk.DISABLED)

    def on_sub2api_selection_changed(self, _event=None) -> None:
        selection = self.sub2api_tree.selection()
        record = self.sub2api_row_index.get(selection[0], {}) if selection else None
        self._set_sub2api_detail(self.sub2api_detail_text, record, empty_text="未选择 Sub2API 账号")

    def on_sub2api_invalidated_selection_changed(self, _event=None) -> None:
        selection = self.sub2api_invalidated_tree.selection()
        record = self.sub2api_invalidated_row_index.get(selection[0], {}) if selection else None
        self._set_sub2api_detail(self.sub2api_invalidated_detail_text, record, empty_text="未选择失效记录")

    def refresh_selected_sub2api_remote(self) -> None:
        records = self.selected_sub2api_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 Sub2API 账号")
            return
        self._refresh_sub2api_remote_records(records, label="选中")

    def refresh_filtered_sub2api_remote(self) -> None:
        records = list(self.filtered_sub2api_records)
        if not records:
            messagebox.showinfo("提示", "当前筛选下没有账号")
            return
        self._refresh_sub2api_remote_records(records, label="当前筛选")

    def _refresh_sub2api_remote_records(self, records: list[dict[str, Any]], *, label: str) -> None:
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")

        def worker():
            return refresh_sub2api_remote_records(records, settings, proxy_url=proxy, log_fn=self.log)

        def done(result):
            self.set_running(False, "Sub2API 远端刷新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            self.persist_runtime_settings(settings)
            messagebox.showinfo(
                "完成",
                f"{label}远端刷新完成\n成功: {result.get('success_count', 0)}\n失败: {result.get('fail_count', 0)}",
            )
            self.refresh_sub2api_accounts()

        self.run_background("正在刷新 Sub2API 远端账号", worker, done)

    def set_selected_sub2api_status(self, status: str) -> None:
        records = self.selected_sub2api_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 Sub2API 账号")
            return
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")

        def worker():
            return set_sub2api_remote_records_status(
                records,
                settings,
                status=status,
                proxy_url=proxy,
                log_fn=self.log,
            )

        def done(result):
            self.set_running(False, "Sub2API 状态更新完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            self.persist_runtime_settings(settings)
            messagebox.showinfo(
                "完成",
                f"状态更新完成\n成功: {result.get('success_count', 0)}\n失败: {result.get('fail_count', 0)}",
            )
            self.refresh_sub2api_accounts()

        self.run_background("正在更新 Sub2API 远端状态", worker, done)

    def delete_selected_sub2api_records(self) -> None:
        records = self.selected_sub2api_pool_records()
        if not records:
            messagebox.showerror("错误", "请先选择远端 Sub2API 账号")
            return
        self._delete_sub2api_records(records, title=f"确定删除选中的 {len(records)} 个远端 Sub2API 账号吗？")

    def delete_selected_invalidated_sub2api_records(self) -> None:
        records = self.selected_sub2api_invalidated_records()
        if not records:
            messagebox.showerror("错误", "请先选择失效记录")
            return
        self._delete_sub2api_records(records, title=f"确定删除选中的 {len(records)} 个失效账号吗？")

    def delete_all_invalidated_sub2api_records(self) -> None:
        records = list(self.invalidated_sub2api_records)
        if not records:
            messagebox.showinfo("提示", "当前没有失效记录")
            return
        self._delete_sub2api_records(records, title=f"确定删除全部 {len(records)} 个失效账号吗？")

    def _delete_sub2api_records(self, records: list[dict[str, Any]], *, title: str) -> None:
        if not messagebox.askyesno("确认", title):
            return
        settings = self.current_settings()
        proxy = settings.get("http_proxy", "")

        def worker():
            return delete_sub2api_remote_records(records, settings, proxy_url=proxy, log_fn=self.log)

        def done(result):
            self.set_running(False, "Sub2API 远端删除完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            self.persist_runtime_settings(settings)
            messagebox.showinfo(
                "完成",
                f"删除完成\n成功: {result.get('success_count', 0)}\n失败: {result.get('fail_count', 0)}",
            )
            self.refresh_sub2api_accounts()

        self.run_background("正在删除 Sub2API 远端账号", worker, done)
