from __future__ import annotations

import json
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox

from .converters import from_cpa_payload, from_sub2api_payload, to_cpa_payload, to_sub2api_payload
from .services import export_organized_payloads, refresh_record, run_batch, sync_subscription, upload_record


class GUIRecordsMixin:
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

    def filter_records(self, records: list[dict[str, object]]) -> list[dict[str, object]]:
        search = self.search_var.get().strip().lower()
        plan_filter = self.plan_filter_var.get().strip().lower()
        status_filter = self.status_filter_var.get().strip()
        filtered: list[dict[str, object]] = []
        for record in records:
            email = str(record.get("email") or "").lower()
            plan_label = self.plan_label(record).lower()
            has_upload_error = any(
                isinstance(state, dict) and not state.get("ok", True)
                for state in (record.get("uploads") or {}).values()
            )
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

    def update_stats(self, all_records: list[dict[str, object]], visible_records: list[dict[str, object]]) -> None:
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

    def organize_output_dirs(self) -> None:
        self.save_settings(reload_tokens=False, notify=False)

        def worker():
            records = self.store.load_all()
            return export_organized_payloads(self.store, records, self.config, log_fn=self.log)

        def done(result):
            self.set_running(False, "目录整理完成")
            if result.get("error"):
                messagebox.showerror("错误", result["error"])
                return
            self.log(
                f"已整理导出 CPA {result.get('cpa_count', 0)} 个账号文件，"
                f"Sub2API 聚合 {result.get('sub2api_count', 0)} 个账号"
            )
            if result.get("removed_sub2api_files", 0):
                self.log(f"已清理旧的 Sub2API 分散文件 {result.get('removed_sub2api_files', 0)} 个")
            self.reload_tokens(save_first=False)
            messagebox.showinfo(
                "完成",
                f"CPA 已导出 {result.get('cpa_count', 0)} 个账号文件\n"
                f"Sub2API 已生成聚合文件\n{result.get('sub2api_path', '')}\n"
                f"清理旧的分散文件 {result.get('removed_sub2api_files', 0)} 个",
            )

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

    def upload_summary(self, record: dict[str, object]) -> str:
        uploads = record.get("uploads") or {}
        parts: list[str] = []
        for key in ("cpa", "sub2api"):
            state = uploads.get(key) or {}
            if not state:
                continue
            parts.append(f"{key}:{'OK' if state.get('ok') else 'ERR'}")
        return " ".join(parts) or "-"

    def plan_label(self, record: dict[str, object]) -> str:
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

    def selected_records(self) -> list[dict[str, object]]:
        selected = set(self.token_tree.selection())
        return [record for record in self.records if str(record.get("_filename") or record.get("email")) in selected]

    def primary_record(self) -> dict[str, object] | None:
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
        sub2api_remote = self.sub2api_index.get(str(record.get("email") or "").strip().lower(), {})
        sub2api_remote_text = "Sub2API 未加载或未找到对应账号"
        if sub2api_remote:
            sub2api_remote_text = (
                f"状态 {sub2api_remote.get('status', '')}  "
                f"分组 {', '.join(sub2api_remote.get('group_names') or []) or '无'}  "
                f"到期 {sub2api_remote.get('expires_at_text', '') or '无'}"
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

Sub2API 远端:
{sub2api_remote_text}
"""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", detail)
        self.detail_text.config(state=tk.DISABLED)

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
        if hasattr(self, "right_notebook") and hasattr(self, "convert_tab"):
            self.right_notebook.select(self.convert_tab)
        export_path = self.store.export_payload(str(record.get("email") or ""), export_target, payload)
        self.log(f"已输出 {export_target} 文件: {export_path}")
        self.status_var.set(f"{format_name} 预览已生成")

    def build_preview_from_var(self) -> None:
        self.build_preview(self.preview_format_var.get().strip())

    def copy_preview(self) -> None:
        text = self.preview_text.get("1.0", tk.END).strip()
        self.copy_to_clipboard(text, "预览内容已复制")

    def import_payloads(self, payloads: list[dict[str, object]], source: str) -> int:
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
