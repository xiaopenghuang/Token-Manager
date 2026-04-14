from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .constants import DEFAULT_OAUTH_CLIENT_ID
from .utils import decode_jwt, get_auth_claims


def _b64url_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _derive_display_name(email: str) -> str:
    local = (email or "").split("@", 1)[0]
    parts = [part for part in local.replace(".", " ").replace("_", " ").replace("-", " ").split() if part]
    if not parts:
        return "OpenAI User"
    return " ".join(item[:1].upper() + item[1:] for item in parts[:3])


def _build_compat_id_token(access_token: str, email: str) -> str:
    payload = decode_jwt(access_token)
    if not payload:
        return ""
    auth_info = get_auth_claims(payload)
    profile = payload.get("https://api.openai.com/profile") or {}
    email_from_token = str(profile.get("email") or payload.get("email") or email or "").strip()
    account_id = str(auth_info.get("chatgpt_account_id") or auth_info.get("account_id") or "").strip()
    user_id = str(auth_info.get("chatgpt_user_id") or auth_info.get("user_id") or payload.get("sub") or "").strip()
    plan_type = str(auth_info.get("chatgpt_plan_type") or "free").strip() or "free"
    organization_id = str(
        auth_info.get("organization_id")
        or f"org-{hashlib.sha1((account_id or email_from_token or user_id).encode('utf-8')).hexdigest()[:24]}"
    )
    project_id = str(
        auth_info.get("project_id")
        or f"proj_{hashlib.sha1((organization_id + ':' + (account_id or user_id)).encode('utf-8')).hexdigest()[:24]}"
    )
    compat_auth = {
        "chatgpt_account_id": account_id,
        "chatgpt_plan_type": plan_type,
        "chatgpt_subscription_active_start": auth_info.get("chatgpt_subscription_active_start"),
        "chatgpt_subscription_active_until": auth_info.get("chatgpt_subscription_active_until"),
        "chatgpt_subscription_last_checked": auth_info.get("chatgpt_subscription_last_checked"),
        "chatgpt_user_id": user_id,
        "completed_platform_onboarding": bool(auth_info.get("completed_platform_onboarding", False)),
        "groups": auth_info.get("groups", []),
        "is_org_owner": bool(auth_info.get("is_org_owner", True)),
        "localhost": bool(auth_info.get("localhost", True)),
        "organization_id": organization_id,
        "organizations": auth_info.get("organizations") or [
            {"id": organization_id, "is_default": True, "role": "owner", "title": "Personal"}
        ],
        "project_id": project_id,
        "user_id": str(auth_info.get("user_id") or user_id or "").strip(),
    }
    compat_payload = {
        "amr": ["pwd", "otp", "mfa"],
        "at_hash": hashlib.sha256(access_token.encode("utf-8")).hexdigest()[:22],
        "aud": [DEFAULT_OAUTH_CLIENT_ID],
        "auth_provider": "password",
        "auth_time": int(payload.get("pwd_auth_time") or payload.get("auth_time") or payload.get("iat") or 0),
        "email": email_from_token,
        "email_verified": bool(profile.get("email_verified", payload.get("email_verified", True))),
        "exp": int(payload.get("exp") or 0),
        "https://api.openai.com/auth": compat_auth,
        "iat": int(payload.get("iat") or 0),
        "iss": payload.get("iss") or "https://auth.openai.com",
        "jti": f"compat-{hashlib.sha1(access_token.encode('utf-8')).hexdigest()[:32]}",
        "name": _derive_display_name(email_from_token),
        "sid": str(payload.get("session_id") or ""),
        "sub": payload.get("sub") or user_id,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "compat"}
    signature = _b64url_bytes(b"compat_signature_for_cpa_parsing_only")
    return f"{_b64url_json(header)}.{_b64url_json(compat_payload)}.{signature}"


def _now_plus_8() -> datetime:
    return datetime.now(tz=timezone(timedelta(hours=8)))


def _decode_exp_timestamp(access_token: str) -> int:
    payload = decode_jwt(access_token)
    exp = payload.get("exp")
    return int(exp) if isinstance(exp, int) else 0


def to_cpa_payload(record: dict[str, Any]) -> dict[str, Any]:
    access_token = str(record.get("access_token") or "").strip()
    refresh_token = str(record.get("refresh_token") or "").strip()
    id_token = str(record.get("id_token") or "").strip()
    email = str(record.get("email") or "").strip()
    if access_token and not id_token:
        id_token = _build_compat_id_token(access_token, email)
    exp_timestamp = _decode_exp_timestamp(access_token)
    expired = ""
    if exp_timestamp > 0:
        expired = datetime.fromtimestamp(exp_timestamp, tz=timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    auth_info = get_auth_claims(decode_jwt(access_token))
    now = _now_plus_8().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    return {
        "type": "codex",
        "email": email,
        "expired": expired,
        "id_token": id_token,
        "account_id": str(
            record.get("account_id")
            or auth_info.get("chatgpt_account_id")
            or ""
        ).strip(),
        "access_token": access_token,
        "last_refresh": now,
        "refresh_token": refresh_token,
    }


def _parse_group_ids(raw: Any) -> list[int]:
    if isinstance(raw, str):
        items = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        items = list(raw)
    elif raw is None:
        items = []
    else:
        items = [raw]
    values: list[int] = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            values.append(int(text))
        except ValueError:
            continue
    return values or [2]


def to_sub2api_payload(record: dict[str, Any], group_ids: Any = None) -> dict[str, Any]:
    cpa_payload = to_cpa_payload(record)
    access_token = str(cpa_payload.get("access_token") or "")
    refresh_token = str(cpa_payload.get("refresh_token") or "")
    id_token = str(cpa_payload.get("id_token") or "")
    email = str(cpa_payload.get("email") or "")
    access_auth = get_auth_claims(decode_jwt(access_token))
    id_auth = get_auth_claims(decode_jwt(id_token))
    organization_id = str(
        id_auth.get("organization_id")
        or access_auth.get("organization_id")
        or ""
    ).strip()
    expires_at = _decode_exp_timestamp(access_token) or int(time.time()) + 863999
    client_id = str(record.get("client_id") or DEFAULT_OAUTH_CLIENT_ID).strip() or DEFAULT_OAUTH_CLIENT_ID
    return {
        "name": email,
        "notes": "",
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 863999,
            "expires_at": expires_at,
            "chatgpt_account_id": str(
                access_auth.get("chatgpt_account_id") or cpa_payload.get("account_id") or ""
            ).strip(),
            "chatgpt_user_id": str(access_auth.get("chatgpt_user_id") or "").strip(),
            "organization_id": organization_id,
            "client_id": client_id,
            "id_token": id_token,
        },
        "extra": {"email": email},
        "group_ids": _parse_group_ids(group_ids),
        "concurrency": 10,
        "priority": 1,
        "auto_pause_on_expired": True,
    }


def from_cpa_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": str(payload.get("email") or "").strip(),
        "access_token": str(payload.get("access_token") or "").strip(),
        "refresh_token": str(payload.get("refresh_token") or "").strip(),
        "id_token": str(payload.get("id_token") or "").strip(),
        "account_id": str(payload.get("account_id") or "").strip(),
        "expired": str(payload.get("expired") or "").strip(),
        "last_refresh": str(payload.get("last_refresh") or "").strip(),
        "type": str(payload.get("type") or "codex"),
    }


def from_sub2api_payload(payload: dict[str, Any]) -> dict[str, Any]:
    credentials = payload.get("credentials") or {}
    extra = payload.get("extra") or {}
    return {
        "email": str(extra.get("email") or payload.get("name") or "").strip(),
        "access_token": str(credentials.get("access_token") or "").strip(),
        "refresh_token": str(credentials.get("refresh_token") or "").strip(),
        "id_token": str(credentials.get("id_token") or "").strip(),
        "account_id": str(credentials.get("chatgpt_account_id") or "").strip(),
        "type": "codex",
        "metadata": {
            "imported_from": "sub2api",
            "sub2api_group_ids": payload.get("group_ids") or [],
            "sub2api_concurrency": payload.get("concurrency"),
            "sub2api_priority": payload.get("priority"),
        },
    }
