from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


INVALID_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]+')


def now_ts() -> int:
    return int(time.time())


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts()))


def parse_rfc3339(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    for candidate in (raw, raw.replace("Z", "+00:00")):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def format_rfc3339_from_ts(timestamp: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(timestamp)))


def remaining_seconds(expired_at: str) -> int:
    dt = parse_rfc3339(expired_at)
    if dt is None:
        return -1
    return int((dt - datetime.now(timezone.utc)).total_seconds())


def format_time_remaining(seconds: int) -> str:
    if seconds == -1:
        return "未知"
    if seconds <= 0:
        return "已过期"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f"{days}天 {hours}小时"
    if hours > 0:
        return f"{hours}小时 {minutes}分钟"
    return f"{minutes}分钟"


def decode_jwt(token: str) -> dict[str, Any]:
    raw = str(token or "").strip()
    if raw.count(".") < 2:
        return {}
    payload = raw.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        data = json.loads(decoded.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def jwt_expired_at(access_token: str, id_token: str = "") -> str:
    access_payload = decode_jwt(access_token)
    id_payload = decode_jwt(id_token)
    exp = access_payload.get("exp") or id_payload.get("exp")
    try:
        return format_rfc3339_from_ts(int(exp))
    except Exception:
        return ""


def get_auth_claims(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("https://api.openai.com/auth")
    return nested if isinstance(nested, dict) else {}


def get_profile_claims(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("https://api.openai.com/profile")
    return nested if isinstance(nested, dict) else {}


def normalize_plan(plan: str) -> str:
    raw = str(plan or "").strip().lower()
    if not raw:
        return "unknown"
    if "enterprise" in raw:
        return "enterprise"
    if "team" in raw:
        return "team"
    if "plus" in raw:
        return "plus"
    if "pro" in raw:
        return "pro"
    if "free" in raw:
        return "free"
    return raw


def plan_directory_name(plan: str) -> str:
    normalized = normalize_plan(plan)
    mapping = {
        "team": "team",
        "plus": "plus",
        "free": "free",
        "pro": "pro",
        "enterprise": "enterprise",
        "unknown": "unknown",
    }
    return mapping.get(normalized, normalized or "unknown")


def derive_subscription(access_token: str, id_token: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    existing = dict(existing or {})
    access_payload = decode_jwt(access_token)
    id_payload = decode_jwt(id_token)
    access_auth = get_auth_claims(access_payload)
    id_auth = get_auth_claims(id_payload)
    plan = (
        access_auth.get("chatgpt_plan_type")
        or id_auth.get("chatgpt_plan_type")
        or existing.get("plan")
        or ""
    )
    active_until = (
        access_auth.get("chatgpt_subscription_active_until")
        or id_auth.get("chatgpt_subscription_active_until")
        or existing.get("subscription_active_until")
        or ""
    )
    workspace_plan = existing.get("workspace_plan_type", "")
    return {
        "plan": normalize_plan(str(plan)),
        "workspace_plan_type": str(workspace_plan or ""),
        "subscription_active_until": str(active_until or ""),
        "checked_at": str(existing.get("checked_at") or now_rfc3339()),
        "source": str(existing.get("source") or ("jwt" if plan else "unknown")),
    }


def derive_email(access_token: str, id_token: str, existing_email: str = "") -> str:
    id_payload = decode_jwt(id_token)
    access_payload = decode_jwt(access_token)
    return str(
        existing_email
        or id_payload.get("email")
        or get_profile_claims(access_payload).get("email")
        or "unknown"
    ).strip()


def derive_account_id(access_token: str, id_token: str, existing_account_id: str = "") -> str:
    access_auth = get_auth_claims(decode_jwt(access_token))
    id_auth = get_auth_claims(decode_jwt(id_token))
    return str(
        existing_account_id
        or access_auth.get("chatgpt_account_id")
        or id_auth.get("chatgpt_account_id")
        or ""
    ).strip()


def safe_email_filename(email: str) -> str:
    raw = str(email or "").strip() or "unknown"
    cleaned = INVALID_FILENAME_CHARS.sub("_", raw)
    return cleaned or "unknown"


def safe_read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def parse_callback_url(callback_url: str) -> tuple[str, str]:
    candidate = str(callback_url or "").strip()
    if not candidate:
        raise ValueError("回调 URL 不能为空")

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        if key not in query or not query[key]:
            query[key] = values

    error = (query.get("error") or [""])[0]
    if error:
        desc = (query.get("error_description") or [""])[0]
        raise RuntimeError(f"OAuth 错误: {error} {desc}".strip())

    code = (query.get("code") or [""])[0].strip()
    state = (query.get("state") or [""])[0].strip()
    if not code or not state:
        raise ValueError("回调 URL 格式不正确")
    return code, state


def build_requests_proxies(proxy_url: str) -> dict[str, str] | None:
    value = str(proxy_url or "").strip()
    if not value:
        return None
    return {"http": value, "https": value}


def atomic_write_json(path: Path, data: Any, *, ensure_ascii: bool = False, indent: int = 2) -> None:
    """Write JSON to *path* atomically: write to a temp file in the same directory, then os.replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp", prefix=".~")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=ensure_ascii, indent=indent)
        os.replace(tmp_path, str(target))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def safe_int(value: Any, default: int = 0) -> int:
    """Convert *value* to int, returning *default* on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
