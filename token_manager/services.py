from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import timedelta, timezone
from typing import Any, Callable

import requests

from .converters import to_cpa_payload, to_sub2api_payload
from .integrations import (
    bulk_update_sub2api_accounts,
    delete_cpa_auth_files,
    delete_sub2api_account,
    fetch_sub2api_accounts,
    fetch_sub2api_groups,
    load_cpa_auth_file_from_docker,
    refresh_sub2api_accounts,
    resolve_cpa_auth_file_path,
    save_cpa_auth_file_to_docker,
    set_cpa_auth_file_disabled,
    upload_state_patch,
    upload_to_cpa,
    upload_to_sub2api,
)
from .store import TokenStore
from .utils import (
    build_requests_proxies,
    decode_jwt,
    derive_subscription,
    format_rfc3339_from_ts,
    now_rfc3339,
    now_ts,
    parse_rfc3339,
    remaining_seconds,
    safe_int,
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


def refresh_cpa_remote_record(
    record: dict[str, Any],
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    email = record.get("email") or record.get("name") or "Unknown"
    file_path = resolve_cpa_auth_file_path(record)
    if callable(log_fn):
        log_fn(f"开始刷新远端 CPA {email}")
    payload = load_cpa_auth_file_from_docker(settings, file_path)
    refresh_token = str(payload.get("refresh_token") or "").strip()
    if not refresh_token:
        return False, "Refresh Token 不存在"
    token_data = refresh_oauth_token(refresh_token, settings, proxy_url=proxy_url)
    merged = deepcopy(payload)
    merged.update(token_data)
    if not merged.get("email"):
        merged["email"] = str(record.get("email") or "")
    save_cpa_auth_file_to_docker(settings, file_path, merged)
    if callable(log_fn):
        log_fn(f"远端 CPA 刷新完成 {email}")
    return True, "远端刷新成功"


def set_cpa_remote_record_disabled(
    record: dict[str, Any],
    settings: dict[str, Any],
    *,
    disabled: bool,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    name = str(record.get("name") or record.get("id") or "").strip()
    label = record.get("email") or name or "Unknown"
    if callable(log_fn):
        log_fn(f"{'禁用' if disabled else '启用'}远端 CPA {label}")
    ok, message = set_cpa_auth_file_disabled(settings, name, disabled, proxy_url=proxy_url)
    if callable(log_fn):
        log_fn(f"{'禁用' if disabled else '启用'}远端 CPA 结束 {label}: {message}")
    return ok, message


def delete_cpa_remote_records(
    records: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    names = sorted(
        {
            str(record.get("name") or record.get("id") or "").strip()
            for record in records
            if str(record.get("name") or record.get("id") or "").strip()
        }
    )
    if not names:
        return False, "没有可删除的 CPA 文件"
    if callable(log_fn):
        log_fn(f"开始删除远端 CPA {len(names)} 个文件")
    ok, message = delete_cpa_auth_files(settings, names, proxy_url=proxy_url)
    if callable(log_fn):
        log_fn(f"删除远端 CPA 结束: {message}")
    return ok, message


def is_sub2api_invalidated(record: dict[str, Any]) -> bool:
    message = str(record.get("error_message") or "").lower()
    return "token invalidated" in message or "your authentication token has been invalidated" in message


def fetch_sub2api_remote_snapshot(
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    groups = fetch_sub2api_groups(settings, proxy_url=proxy_url)
    records = fetch_sub2api_accounts(settings, proxy_url=proxy_url, filters={"platform": "openai"})
    group_name_by_id = {safe_int(item.get("id")): str(item.get("name") or "").strip() for item in groups}
    for record in records:
        if record.get("group_names"):
            continue
        record["group_names"] = [
            group_name_by_id.get(safe_int(group_id), f"#{safe_int(group_id)}")
            for group_id in (record.get("group_ids") or [])
            if safe_int(group_id) > 0
        ]
    if callable(log_fn):
        log_fn(f"Sub2API 远端账号 {len(records)} 条，分组 {len(groups)} 条")
    return {"groups": groups, "records": records}


def refresh_sub2api_remote_records(
    records: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    account_ids = sorted({safe_int(record.get("id")) for record in records if safe_int(record.get("id")) > 0})
    if not account_ids:
        return {"success_count": 0, "fail_count": 0, "total": 0, "results": []}
    if callable(log_fn):
        log_fn(f"开始批量刷新 Sub2API 远端账号 {len(account_ids)} 个")
    data = refresh_sub2api_accounts(settings, account_ids, proxy_url=proxy_url)
    if callable(log_fn):
        log_fn(
            f"Sub2API 远端刷新结束 成功 {int(data.get('success') or 0)} 失败 {int(data.get('failed') or 0)}"
        )
    return {
        **data,
        "success_count": int(data.get("success") or 0),
        "fail_count": int(data.get("failed") or 0),
        "total": int(data.get("total") or len(account_ids)),
    }


def set_sub2api_remote_records_status(
    records: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    status: str,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    account_ids = sorted({safe_int(record.get("id")) for record in records if safe_int(record.get("id")) > 0})
    if not account_ids:
        return {"success_count": 0, "fail_count": 0, "total": 0, "results": []}
    if callable(log_fn):
        log_fn(f"开始批量更新 Sub2API 状态 {status} 共 {len(account_ids)} 个")
    data = bulk_update_sub2api_accounts(settings, account_ids, {"status": str(status or "").strip()}, proxy_url=proxy_url)
    if callable(log_fn):
        log_fn(
            f"Sub2API 状态更新结束 成功 {int(data.get('success') or 0)} 失败 {int(data.get('failed') or 0)}"
        )
    return {
        **data,
        "success_count": int(data.get("success") or 0),
        "fail_count": int(data.get("failed") or 0),
        "total": len(account_ids),
    }


def delete_sub2api_remote_records(
    records: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    unique_records: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for record in records:
        account_id = safe_int(record.get("id"))
        if account_id <= 0 or account_id in seen_ids:
            continue
        seen_ids.add(account_id)
        unique_records.append(record)
    if callable(log_fn):
        log_fn(f"开始删除 Sub2API 远端账号 {len(unique_records)} 个")
    result = run_batch(
        unique_records,
        workers=min(len(unique_records), 8) if unique_records else 1,
        job=lambda record: delete_sub2api_account(settings, safe_int(record.get("id")), proxy_url=proxy_url),
    )
    if callable(log_fn):
        log_fn(f"Sub2API 删除结束 成功 {result.get('success_count', 0)} 失败 {result.get('fail_count', 0)}")
    return result


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


def _sub2api_export_expires_at(record: dict[str, Any]) -> str:
    expired = str(record.get("expired") or "").strip()
    expired_dt = parse_rfc3339(expired)
    if expired_dt is None:
        return expired
    return expired_dt.astimezone(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def _sub2api_export_token_version(record: dict[str, Any]) -> int:
    last_refresh = str(record.get("last_refresh") or "").strip()
    refreshed_dt = parse_rfc3339(last_refresh)
    if refreshed_dt is not None:
        return int(refreshed_dt.timestamp() * 1000)
    return now_ts() * 1000


def _sub2api_export_account(record: dict[str, Any], *, group_ids: Any = None) -> dict[str, Any]:
    base = to_sub2api_payload(record, group_ids=group_ids)
    credentials = dict(base.get("credentials") or {})
    email = str(((base.get("extra") or {}).get("email") or base.get("name") or record.get("email") or "")).strip()
    expires_in = int(record.get("_remaining_seconds") or remaining_seconds(str(record.get("expired") or "")) or 0)
    return {
        "name": str(base.get("name") or email),
        "platform": str(base.get("platform") or "openai"),
        "type": str(base.get("type") or "oauth"),
        "credentials": {
            "_token_version": _sub2api_export_token_version(record),
            "access_token": str(credentials.get("access_token") or ""),
            "chatgpt_account_id": str(credentials.get("chatgpt_account_id") or ""),
            "chatgpt_user_id": str(credentials.get("chatgpt_user_id") or ""),
            "email": email,
            "expires_at": _sub2api_export_expires_at(record),
            "expires_in": max(0, expires_in),
            "id_token": str(credentials.get("id_token") or ""),
            "organization_id": str(credentials.get("organization_id") or ""),
            "refresh_token": str(credentials.get("refresh_token") or ""),
        },
        "extra": {"email": email},
        "concurrency": int(base.get("concurrency") or 10),
        "priority": int(base.get("priority") or 1),
        "rate_multiplier": 1,
        "auto_pause_on_expired": bool(base.get("auto_pause_on_expired", True)),
    }


def export_organized_payloads(
    store: TokenStore,
    records: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    cpa_paths: list[str] = []
    group_ids = ((settings.get("integrations") or {}).get("sub2api") or {}).get("group_ids")
    sub2api_accounts: list[dict[str, Any]] = []
    removed_sub2api_files = store.cleanup_target_json_files("Sub2API", keep_prefixes=("sub2api_accounts_",))
    for record in records:
        email = str(record.get("email") or "").strip()
        cpa_paths.append(str(store.export_payload(email, "CPA", to_cpa_payload(record))))
        sub2api_accounts.append(_sub2api_export_account(record, group_ids=group_ids))
        if callable(log_fn):
            log_fn(f"已整理导出 {email}")
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    bundle_filename = f"sub2api_accounts_{timestamp}.json"
    bundle_payload = {
        "exported_at": now_rfc3339(),
        "proxies": [],
        "accounts": sub2api_accounts,
    }
    sub2api_path = store.export_named_payload("Sub2API", bundle_filename, bundle_payload)
    if callable(log_fn):
        log_fn(f"已生成 Sub2API 聚合文件: {sub2api_path}")
        if removed_sub2api_files:
            log_fn(f"已清理旧的 Sub2API 分散文件 {removed_sub2api_files} 个")
    return {
        "cpa_count": len(cpa_paths),
        "sub2api_count": len(sub2api_accounts),
        "sub2api_path": str(sub2api_path),
        "removed_sub2api_files": removed_sub2api_files,
    }


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
