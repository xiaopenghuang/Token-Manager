from __future__ import annotations

import json
import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from .utils import (
    decode_jwt,
    derive_account_id,
    derive_email,
    derive_subscription,
    format_time_remaining,
    jwt_expired_at,
    parse_rfc3339,
    remaining_seconds,
    safe_email_filename,
    safe_read_json,
)


class TokenStore:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.tokens_dir = Path(str(config.get("tokens_dir") or "")).expanduser()
        self.outputs_dir = Path(str(config.get("outputs_dir") or "")).expanduser()
        self.tokens_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir.mkdir(parents=True, exist_ok=True)

    def all_files(self) -> list[Path]:
        return sorted(self.tokens_dir.rglob("*.json"))

    def normalize(self, data: dict[str, Any], filename: Path | None = None) -> dict[str, Any]:
        record = deepcopy(data)
        record["access_token"] = str(record.get("access_token") or "").strip()
        record["refresh_token"] = str(record.get("refresh_token") or "").strip()
        record["id_token"] = str(record.get("id_token") or "").strip()
        record["session_token"] = str(record.get("session_token") or "").strip()
        record["email"] = derive_email(
            record.get("access_token", ""),
            record.get("id_token", ""),
            str(record.get("email") or ""),
        )
        record["account_id"] = derive_account_id(
            record.get("access_token", ""),
            record.get("id_token", ""),
            str(record.get("account_id") or ""),
        )
        if not record.get("expired"):
            record["expired"] = jwt_expired_at(record.get("access_token", ""), record.get("id_token", ""))
        record["type"] = str(record.get("type") or "codex")
        record["subscription"] = derive_subscription(
            record.get("access_token", ""),
            record.get("id_token", ""),
            record.get("subscription"),
        )
        record["custom_tags"] = [str(item).strip() for item in record.get("custom_tags", []) if str(item).strip()]
        uploads = record.get("uploads")
        record["uploads"] = uploads if isinstance(uploads, dict) else {}
        if not record.get("created_at"):
            record["created_at"] = str(record.get("last_refresh") or "")
        seconds = remaining_seconds(str(record.get("expired") or ""))
        record["_remaining_seconds"] = seconds
        record["_remaining_text"] = format_time_remaining(seconds)
        record["_is_expired"] = seconds <= 0
        record["_filename"] = str(filename or "")
        record["_plan"] = str(((record.get("subscription") or {}).get("plan") or "unknown")).strip()
        return record

    def load(self, path: Path) -> dict[str, Any] | None:
        raw = safe_read_json(path)
        if raw is None:
            return None
        if not any(raw.get(key) for key in ("id_token", "access_token", "refresh_token")):
            return None
        return self.normalize(raw, filename=path)

    def load_all(self) -> list[dict[str, Any]]:
        records_by_email: dict[str, dict[str, Any]] = {}
        for path in self.all_files():
            record = self.load(path)
            if record:
                email_key = str(record.get("email") or "").strip().lower()
                if not email_key:
                    email_key = str(path).lower()
                existing = records_by_email.get(email_key)
                if existing is None or self._record_sort_key(record) > self._record_sort_key(existing):
                    records_by_email[email_key] = record
        records = list(records_by_email.values())
        records.sort(key=lambda item: (item["_remaining_seconds"], item.get("email", "")))
        return records

    @staticmethod
    def _record_sort_key(record: dict[str, Any]) -> tuple[float, float, int]:
        last_refresh_dt = parse_rfc3339(str(record.get("last_refresh") or ""))
        created_dt = parse_rfc3339(str(record.get("created_at") or ""))
        last_refresh_ts = last_refresh_dt.timestamp() if last_refresh_dt else 0.0
        created_ts = created_dt.timestamp() if created_dt else 0.0
        access_len = len(str(record.get("access_token") or ""))
        return (last_refresh_ts, created_ts, access_len)

    def save_record(self, record: dict[str, Any], filename: str | Path | None = None) -> Path:
        normalized = self.normalize(record, filename=None)
        source = Path(filename) if filename else None
        target = self._resolve_path(normalized, source=source)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {key: value for key, value in normalized.items() if not str(key).startswith("_")}
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if source and source.resolve() != target.resolve() and source.exists():
            try:
                source.unlink()
            except Exception:
                pass
        return target

    def _resolve_path(self, record: dict[str, Any], source: Path | None = None) -> Path:
        email = str(record.get("email") or "").strip()
        filename = f"{safe_email_filename(email)}.json"
        legacy_filename = f"{str(email or '').replace('@', '_').replace('.', '_')}.json"
        legacy_exact = self.tokens_dir / f"{email}.json"
        legacy_underscored = self.tokens_dir / legacy_filename
        exact = self.tokens_dir / filename
        if source and source.exists():
            if source.parent == self.tokens_dir:
                return source
            return exact
        existing_by_email = self._find_existing_path_by_email(email)
        if existing_by_email is not None:
            return existing_by_email
        if legacy_exact.exists():
            return legacy_exact
        if legacy_underscored.exists():
            return legacy_underscored
        return exact

    def _find_existing_path_by_email(self, email: str) -> Path | None:
        target_email = str(email or "").strip().lower()
        if not target_email:
            return None
        best_path: Path | None = None
        best_key: tuple[float, float, int] | None = None
        for path in self.all_files():
            record = self.load(path)
            if not record:
                continue
            if str(record.get("email") or "").strip().lower() != target_email:
                continue
            sort_key = self._record_sort_key(record)
            if best_key is None or sort_key > best_key:
                best_key = sort_key
                best_path = path
        return best_path

    def save_token_response(
        self,
        token_data: dict[str, Any],
        *,
        existing_filename: str | Path | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        record = {
            "id_token": str(token_data.get("id_token") or ""),
            "access_token": str(token_data.get("access_token") or ""),
            "refresh_token": str(token_data.get("refresh_token") or ""),
            "email": str(token_data.get("email") or ""),
            "account_id": str(token_data.get("account_id") or ""),
            "last_refresh": str(token_data.get("last_refresh") or ""),
            "expired": str(token_data.get("expired") or ""),
            "type": str(token_data.get("type") or "codex"),
        }
        if existing_filename:
            old = safe_read_json(Path(existing_filename)) or {}
            old.update(record)
            record = old
        if metadata:
            merged_meta = dict(record.get("metadata") or {})
            merged_meta.update(metadata)
            record["metadata"] = merged_meta
        return self.save_record(record, filename=existing_filename)

    def delete(self, filename: str | Path) -> None:
        path = Path(filename)
        if path.exists():
            path.unlink()

    def organize_existing_records(self) -> int:
        count = 0
        for record in self.load_all():
            source = record.get("_filename")
            self.save_record(record, filename=source)
            count += 1
        return count

    def cleanup_tokens_directory(self) -> dict[str, int]:
        raw_records: list[tuple[Path, dict[str, Any]]] = []
        for path in self.all_files():
            record = self.load(path)
            if record:
                raw_records.append((path, record))

        grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
        for path, record in raw_records:
            email_key = str(record.get("email") or "").strip().lower() or str(path).lower()
            grouped.setdefault(email_key, []).append((path, record))

        kept = 0
        removed = 0
        moved = 0
        for _, items in grouped.items():
            items.sort(key=lambda pair: self._record_sort_key(pair[1]), reverse=True)
            best_path, best_record = items[0]
            target = self.save_record(best_record, filename=None)
            kept += 1
            if best_path.resolve() != target.resolve() and best_path.exists():
                try:
                    best_path.unlink()
                    moved += 1
                except Exception:
                    pass
            for old_path, _ in items[1:]:
                if old_path.resolve() == target.resolve():
                    continue
                if old_path.exists():
                    old_path.unlink()
                    removed += 1

        removed_dirs = 0
        for child in sorted(self.tokens_dir.iterdir(), reverse=True):
            if child.is_dir():
                try:
                    shutil.rmtree(child)
                    removed_dirs += 1
                except Exception:
                    pass

        return {
            "kept": kept,
            "removed_files": removed,
            "moved_best_files": moved,
            "removed_dirs": removed_dirs,
        }

    def export_payload(self, email: str, target: str, payload: dict[str, Any]) -> Path:
        label = str(target or "unknown").strip()
        if label.lower() == "cpa":
            label = "CPA"
        elif label.lower() == "sub2api":
            label = "Sub2API"
        export_dir = self._ensure_output_dir(label)
        export_path = export_dir / f"{safe_email_filename(email)}.json"
        export_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return export_path

    def _ensure_output_dir(self, label: str) -> Path:
        desired = self.outputs_dir / label
        for child in self.outputs_dir.iterdir():
            if child.is_dir() and child.name.lower() == label.lower():
                if child.name == label:
                    return child
                temp_dir = self.outputs_dir / f"__tmp_{uuid.uuid4().hex[:8]}"
                child.rename(temp_dir)
                temp_dir.rename(desired)
                return desired
        if desired.exists():
            return desired
        desired.mkdir(parents=True, exist_ok=True)
        return desired
