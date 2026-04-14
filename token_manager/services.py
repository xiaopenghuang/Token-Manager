from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from typing import Any, Callable

import requests

from .converters import to_cpa_payload, to_sub2api_payload
from .integrations import upload_state_patch, upload_to_cpa, upload_to_sub2api
from .store import TokenStore
from .utils import (
    build_requests_proxies,
    decode_jwt,
    derive_subscription,
    format_rfc3339_from_ts,
    now_rfc3339,
    now_ts,
)


def refresh_oauth_token(refresh_token: str, settings: dict[str, Any], proxy_url: str = "") -> dict[str, Any]:
    oauth = dict(settings.get("oauth") or {})
    response = requests.post(
        str(oauth.get("token_url") or ""),
        data={
            "grant_type": "refresh_token",
            "client_id": str(oauth.get("client_id") or ""),
            "refresh_token": str(refresh_token or ""),
            "redirect_uri": str(oauth.get("redirect_uri") or ""),
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        timeout=30,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code} - {response.text[:300]}")
    data = response.json()
    access_token = str(data.get("access_token") or "").strip()
    if not access_token:
        raise RuntimeError("刷新结果缺少 access_token")
    id_token = str(data.get("id_token") or "").strip()
    claims = decode_jwt(id_token)
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    expires_in = int(data.get("expires_in") or 3600)
    now = now_ts()
    return {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": str(data.get("refresh_token") or refresh_token or ""),
        "account_id": str(auth_claims.get("chatgpt_account_id") or ""),
        "last_refresh": format_rfc3339_from_ts(now),
        "email": str(claims.get("email") or ""),
        "type": "codex",
        "expired": format_rfc3339_from_ts(now + max(0, expires_in)),
    }


def probe_subscription_with_api(record: dict[str, Any], proxy_url: str = "") -> dict[str, Any]:
    access_token = str(record.get("access_token") or "").strip()
    if not access_token:
        raise RuntimeError("账号缺少 access_token")
    response = requests.get(
        "https://chatgpt.com/backend-api/me",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "codex_cli_rs/0.116.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464",
        },
        timeout=20,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code} - {response.text[:300]}")
    body = response.json()
    plan_type = str(body.get("plan_type") or "").strip()
    workspace_plan_type = ""
    orgs = ((body.get("orgs") or {}).get("data") if isinstance(body.get("orgs"), dict) else []) or []
    if isinstance(orgs, list):
        for org in orgs:
            settings = (org or {}).get("settings") or {}
            if isinstance(settings, dict) and settings.get("workspace_plan_type"):
                workspace_plan_type = str(settings.get("workspace_plan_type") or "").strip()
                break
    subscription = derive_subscription(
        record.get("access_token", ""),
        record.get("id_token", ""),
        {
            "plan": plan_type or workspace_plan_type,
            "workspace_plan_type": workspace_plan_type,
            "subscription_active_until": str(
                body.get("chatgpt_subscription_active_until")
                or body.get("subscription_active_until")
                or ""
            ).strip(),
            "checked_at": now_rfc3339(),
            "source": "backend-api/me",
        },
    )
    subscription["workspace_plan_type"] = workspace_plan_type
    subscription["source"] = "backend-api/me"
    return subscription


def merge_patch(record: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(record)
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_patch(merged[key], value)
        else:
            merged[key] = value
    return merged


def refresh_record(
    store: TokenStore,
    record: dict[str, Any],
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
    sync_plan: bool = True,
) -> tuple[bool, str]:
    email = record.get("email", "Unknown")
    refresh_token = str(record.get("refresh_token") or "").strip()
    if not refresh_token:
        return False, "Refresh Token 不存在"
    if callable(log_fn):
        log_fn(f"开始刷新 {email}")
    token_data = refresh_oauth_token(refresh_token, settings, proxy_url=proxy_url)
    existing = deepcopy(record)
    existing.update(token_data)
    existing.setdefault("subscription", {})
    if sync_plan:
        try:
            existing["subscription"] = probe_subscription_with_api(existing, proxy_url=proxy_url)
        except Exception:
            existing["subscription"] = derive_subscription(
                existing.get("access_token", ""),
                existing.get("id_token", ""),
                existing.get("subscription"),
            )
    path = record.get("_filename") or None
    store.save_record(existing, filename=path)
    if callable(log_fn):
        log_fn(f"刷新完成 {email}")
    return True, "刷新成功"


def sync_subscription(
    store: TokenStore,
    record: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    email = record.get("email", "Unknown")
    if callable(log_fn):
        log_fn(f"开始同步标签 {email}")
    try:
        subscription = probe_subscription_with_api(record, proxy_url=proxy_url)
    except Exception as exc:
        subscription = derive_subscription(
            record.get("access_token", ""),
            record.get("id_token", ""),
            record.get("subscription"),
        )
        subscription["source"] = "jwt"
        merged = deepcopy(record)
        merged["subscription"] = subscription
        store.save_record(merged, filename=record.get("_filename"))
        if callable(log_fn):
            log_fn(f"标签同步降级为 JWT 解析 {email}: {exc}")
        return False, f"接口同步失败，已降级本地解析: {exc}"
    merged = deepcopy(record)
    merged["subscription"] = subscription
    store.save_record(merged, filename=record.get("_filename"))
    if callable(log_fn):
        log_fn(f"标签同步完成 {email}")
    return True, "标签同步成功"


def _upload_target(target: str):
    normalized = str(target or "").strip().lower()
    if normalized == "cpa":
        return upload_to_cpa
    if normalized == "sub2api":
        return upload_to_sub2api
    raise ValueError(f"未知上传目标: {target}")


def upload_record(
    store: TokenStore,
    record: dict[str, Any],
    settings: dict[str, Any],
    *,
    target: str,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    email = record.get("email", "Unknown")
    if callable(log_fn):
        log_fn(f"开始上传 {email} -> {target}")
    normalized_target = str(target or "").strip().lower()
    if normalized_target == "cpa":
        export_path = store.export_payload(email, normalized_target, to_cpa_payload(record))
    elif normalized_target == "sub2api":
        export_path = store.export_payload(email, normalized_target, to_sub2api_payload(record, group_ids=((settings.get("integrations") or {}).get("sub2api") or {}).get("group_ids")))
    else:
        export_path = None
    if callable(log_fn) and export_path is not None:
        log_fn(f"已输出 {normalized_target} 文件: {export_path}")
    uploader = _upload_target(target)
    ok, message = uploader(record, settings, proxy_url=proxy_url)
    merged = merge_patch(record, upload_state_patch(target, ok, message))
    store.save_record(merged, filename=record.get("_filename"))
    if callable(log_fn):
        log_fn(f"上传结束 {email} -> {target}: {message}")
    return ok, message


def export_record_payloads(
    store: TokenStore,
    record: dict[str, Any],
    settings: dict[str, Any],
    *,
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, str]:
    email = str(record.get("email") or "").strip()
    cpa_path = store.export_payload(email, "CPA", to_cpa_payload(record))
    sub2api_group_ids = ((settings.get("integrations") or {}).get("sub2api") or {}).get("group_ids")
    sub2api_path = store.export_payload(email, "Sub2API", to_sub2api_payload(record, group_ids=sub2api_group_ids))
    if callable(log_fn):
        log_fn(f"已整理导出 {email}")
    return {"CPA": str(cpa_path), "Sub2API": str(sub2api_path)}


def run_batch(
    records: list[dict[str, Any]],
    *,
    workers: int,
    job,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    total = len(records)
    completed = 0
    results: list[tuple[dict[str, Any], bool, str]] = []
    if total == 0:
        return {"success_count": 0, "fail_count": 0, "results": results}
    workers = max(1, min(int(workers or 1), total))
    if workers == 1:
        for record in records:
            try:
                ok, message = job(record)
            except Exception as exc:
                ok, message = False, str(exc)
            completed += 1
            results.append((record, ok, message))
            if callable(progress_cb):
                progress_cb(completed, total, record.get("email", "Unknown"))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(job, record): record for record in records}
            for future in as_completed(future_map):
                record = future_map[future]
                try:
                    ok, message = future.result()
                except Exception as exc:
                    ok, message = False, str(exc)
                completed += 1
                results.append((record, ok, message))
                if callable(progress_cb):
                    progress_cb(completed, total, record.get("email", "Unknown"))
    fails = [item for item in results if not item[1]]
    return {
        "success_count": len(results) - len(fails),
        "fail_count": len(fails),
        "results": results,
    }
