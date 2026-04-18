from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from .converters import to_cpa_payload, to_sub2api_payload
from .utils import build_requests_proxies, now_rfc3339, now_ts, safe_int


def _response_error(response: requests.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("msg") or data.get("error") or "").strip()
    except Exception:
        pass
    return response.text[:300].strip() or f"HTTP {response.status_code}"


def _subprocess_silent_kwargs() -> dict[str, Any]:
    if sys.platform != "win32":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "startupinfo": startupinfo,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
    }


def _cpa_api_url(settings: dict[str, Any]) -> str:
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    api_url = str(cpa.get("api_url") or "").strip()
    if not api_url:
        raise RuntimeError("CPA API URL 未配置")
    return api_url.rstrip("/")


def _cpa_api_key(settings: dict[str, Any]) -> str:
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    return str(cpa.get("api_key") or "").strip()


def _cpa_container_name(settings: dict[str, Any]) -> str:
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    return str(cpa.get("container_name") or "cli-proxy-api").strip() or "cli-proxy-api"


def _cpa_management_headers(settings: dict[str, Any]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_cpa_api_key(settings)}",
        "Accept": "application/json, text/plain, */*",
    }


def _sub2api_settings(settings: dict[str, Any]) -> dict[str, Any]:
    integrations = settings.get("integrations")
    if not isinstance(integrations, dict):
        return {}
    sub2api = integrations.get("sub2api")
    if not isinstance(sub2api, dict):
        return {}
    return sub2api


_sub2api_auth_lock = threading.Lock()


def _sub2api_api_url(settings: dict[str, Any]) -> str:
    api_url = str(_sub2api_settings(settings).get("api_url") or "").strip()
    if not api_url:
        raise RuntimeError("Sub2API API URL 未配置")
    return api_url.rstrip("/")


def _sub2api_api_key(settings: dict[str, Any]) -> str:
    return str(_sub2api_settings(settings).get("api_key") or "").strip()


def _sub2api_admin_email(settings: dict[str, Any]) -> str:
    return str(_sub2api_settings(settings).get("admin_email") or "").strip()


def _sub2api_admin_password(settings: dict[str, Any]) -> str:
    return str(_sub2api_settings(settings).get("admin_password") or "").strip()


def _sub2api_access_token(settings: dict[str, Any]) -> str:
    return str(_sub2api_settings(settings).get("access_token") or "").strip()


def _sub2api_refresh_token(settings: dict[str, Any]) -> str:
    return str(_sub2api_settings(settings).get("refresh_token") or "").strip()


def _sub2api_token_expires_at(settings: dict[str, Any]) -> int:
    try:
        return int(_sub2api_settings(settings).get("token_expires_at") or 0)
    except Exception:
        return 0


def _sub2api_base_headers(settings: dict[str, Any], *, token: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/plain, */*",
    }
    auth_token = str(token or "").strip()
    api_key = _sub2api_api_key(settings)
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["x-api-key"] = api_key
    return headers


def _sub2api_public_headers() -> dict[str, str]:
    return {
        "Accept": "application/json, text/plain, */*",
    }


def _sub2api_is_session_expired(settings: dict[str, Any]) -> bool:
    expires_at = _sub2api_token_expires_at(settings)
    return bool(expires_at and expires_at <= now_ts() + 30)


def _set_sub2api_session(settings: dict[str, Any], data: dict[str, Any]) -> None:
    integrations = settings.get("integrations")
    if not isinstance(integrations, dict):
        return
    sub2api = integrations.get("sub2api")
    if not isinstance(sub2api, dict):
        return
    access_token = str(data.get("access_token") or "").strip()
    refresh_token = str(data.get("refresh_token") or sub2api.get("refresh_token") or "").strip()
    expires_in = int(data.get("expires_in") or 0)
    sub2api["access_token"] = access_token
    sub2api["refresh_token"] = refresh_token
    sub2api["token_expires_at"] = now_ts() + max(60, expires_in - 30) if access_token and expires_in > 0 else 0


def _sub2api_response_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _sub2api_response_data(response: requests.Response) -> Any:
    body = _sub2api_response_json(response)
    if isinstance(body, dict) and "code" in body:
        if int(body.get("code") or 0) != 0:
            raise RuntimeError(str(body.get("message") or body.get("error") or "Sub2API 请求失败").strip())
        return body.get("data")
    return body


def _sub2api_datetime_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        raw = int(value)
    except Exception:
        return str(value or "").strip()
    if raw <= 0:
        return ""
    if raw > 10_000_000_000:
        raw = raw // 1000
    dt = datetime.fromtimestamp(raw, tz=timezone(timedelta(hours=8)))
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def login_sub2api_admin(settings: dict[str, Any], *, proxy_url: str = "") -> dict[str, Any]:
    email = _sub2api_admin_email(settings)
    password = _sub2api_admin_password(settings)
    if not email or not password:
        raise RuntimeError("Sub2API 管理邮箱或密码未配置")
    response = requests.post(
        f"{_sub2api_api_url(settings)}/api/v1/auth/login",
        headers={
            "Content-Type": "application/json",
            **_sub2api_public_headers(),
        },
        json={"email": email, "password": password},
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code != 200:
        raise RuntimeError(_response_error(response))
    data = _sub2api_response_data(response)
    if not isinstance(data, dict):
        raise RuntimeError("Sub2API 登录结果异常")
    _set_sub2api_session(settings, data)
    return data


def refresh_sub2api_admin_session(settings: dict[str, Any], *, proxy_url: str = "") -> dict[str, Any]:
    refresh_token = _sub2api_refresh_token(settings)
    if not refresh_token:
        raise RuntimeError("Sub2API Refresh Token 未配置")
    response = requests.post(
        f"{_sub2api_api_url(settings)}/api/v1/auth/refresh",
        headers={
            "Content-Type": "application/json",
            **_sub2api_public_headers(),
        },
        json={"refresh_token": refresh_token},
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code != 200:
        raise RuntimeError(_response_error(response))
    data = _sub2api_response_data(response)
    if not isinstance(data, dict):
        raise RuntimeError("Sub2API 刷新登录态结果异常")
    _set_sub2api_session(settings, data)
    return data


def _ensure_sub2api_auth(settings: dict[str, Any], *, proxy_url: str = "") -> str:
    with _sub2api_auth_lock:
        access_token = _sub2api_access_token(settings)
        if access_token and not _sub2api_is_session_expired(settings):
            return access_token
        if access_token and _sub2api_refresh_token(settings):
            try:
                refresh_sub2api_admin_session(settings, proxy_url=proxy_url)
                return _sub2api_access_token(settings)
            except Exception:
                pass
        if _sub2api_admin_email(settings) and _sub2api_admin_password(settings):
            login_sub2api_admin(settings, proxy_url=proxy_url)
            return _sub2api_access_token(settings)
        return ""


def _sub2api_request(
    settings: dict[str, Any],
    method: str,
    path: str,
    *,
    proxy_url: str = "",
    require_auth: bool = True,
    **kwargs,
) -> requests.Response:
    api_url = _sub2api_api_url(settings)
    token = _ensure_sub2api_auth(settings, proxy_url=proxy_url) if require_auth else ""
    extra_headers = dict(kwargs.pop("headers", {}) or {})
    retry_headers = dict(kwargs.pop("retry_headers", {}) or {})
    headers = {
        **_sub2api_base_headers(settings, token=token),
        **extra_headers,
    }
    response = requests.request(
        method.upper(),
        f"{api_url}{path}",
        headers=headers,
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
        **kwargs,
    )
    if response.status_code != 401 or not require_auth:
        return response

    refreshed = False
    if _sub2api_refresh_token(settings):
        try:
            refresh_sub2api_admin_session(settings, proxy_url=proxy_url)
            refreshed = True
        except Exception:
            refreshed = False
    if not refreshed and _sub2api_admin_email(settings) and _sub2api_admin_password(settings):
        login_sub2api_admin(settings, proxy_url=proxy_url)
        refreshed = True
    if not refreshed:
        return response

    retry_headers = {
        **_sub2api_base_headers(settings, token=_sub2api_access_token(settings)),
        **extra_headers,
        **retry_headers,
    }
    return requests.request(
        method.upper(),
        f"{api_url}{path}",
        headers=retry_headers,
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
        **kwargs,
    )


def fetch_sub2api_groups(settings: dict[str, Any], *, proxy_url: str = "") -> list[dict[str, Any]]:
    response = _sub2api_request(settings, "GET", "/api/v1/admin/groups/all", proxy_url=proxy_url)
    if response.status_code != 200:
        raise RuntimeError(_response_error(response))
    data = _sub2api_response_data(response)
    items = data if isinstance(data, list) else []
    groups: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        groups.append(
            {
                "id": safe_int(item.get("id")),
                "name": str(item.get("name") or "").strip(),
                "platform": str(item.get("platform") or "").strip(),
                "status": str(item.get("status") or "").strip(),
            }
        )
    groups.sort(key=lambda item: (item.get("platform") or "", item.get("name") or ""))
    return groups


def fetch_sub2api_accounts(
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    filters: dict[str, Any] | None = None,
    page_size: int = 100,
) -> list[dict[str, Any]]:
    query_filters = {key: value for key, value in dict(filters or {}).items() if str(value or "").strip()}
    page = 1
    pages = 1
    records: list[dict[str, Any]] = []
    group_name_by_id: dict[int, str] = {}
    while page <= pages:
        response = _sub2api_request(
            settings,
            "GET",
            "/api/v1/admin/accounts",
            proxy_url=proxy_url,
            params={
                "page": page,
                "page_size": page_size,
                **query_filters,
            },
        )
        if response.status_code != 200:
            raise RuntimeError(_response_error(response))
        data = _sub2api_response_data(response)
        items = data.get("items") if isinstance(data, dict) else []
        pages = max(1, int(data.get("pages") or 1)) if isinstance(data, dict) else 1
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            credentials = item.get("credentials") or {}
            if not isinstance(credentials, dict):
                credentials = {}
            extra = item.get("extra") or {}
            if not isinstance(extra, dict):
                extra = {}
            groups = item.get("groups") or []
            if not isinstance(groups, list):
                groups = []
            group_ids = item.get("group_ids") or []
            if not isinstance(group_ids, list):
                group_ids = []
            group_names: list[str] = []
            for group in groups:
                if not isinstance(group, dict):
                    continue
                try:
                    group_id = safe_int(group.get("id"))
                except Exception:
                    group_id = 0
                group_name = str(group.get("name") or "").strip()
                if group_id > 0 and group_name:
                    group_name_by_id[group_id] = group_name
                if group_name:
                    group_names.append(group_name)
            if not group_names:
                group_names = [group_name_by_id.get(safe_int(group_id), f"#{safe_int(group_id)}") for group_id in group_ids if safe_int(group_id) > 0]
            email = str(credentials.get("email") or extra.get("email") or item.get("name") or "").strip()
            records.append(
                {
                    "id": safe_int(item.get("id")),
                    "name": str(item.get("name") or "").strip(),
                    "email": email,
                    "platform": str(item.get("platform") or "").strip(),
                    "type": str(item.get("type") or "").strip(),
                    "status": str(item.get("status") or "").strip(),
                    "error_message": str(item.get("error_message") or "").strip(),
                    "group_ids": [safe_int(group_id) for group_id in group_ids if safe_int(group_id) > 0],
                    "group_names": group_names,
                    "concurrency": safe_int(item.get("concurrency")),
                    "priority": safe_int(item.get("priority")),
                    "schedulable": bool(item.get("schedulable", True)),
                    "proxy_id": item.get("proxy_id"),
                    "last_used_at": str(item.get("last_used_at") or "").strip(),
                    "expires_at": item.get("expires_at"),
                    "expires_at_text": _sub2api_datetime_text(item.get("expires_at")),
                    "rate_limited_at": str(item.get("rate_limited_at") or "").strip(),
                    "rate_limit_reset_at": str(item.get("rate_limit_reset_at") or "").strip(),
                    "temp_unschedulable_until": str(item.get("temp_unschedulable_until") or "").strip(),
                    "auto_pause_on_expired": bool(item.get("auto_pause_on_expired", False)),
                    "credentials": credentials,
                    "extra": extra,
                    "groups": groups,
                    "proxy": item.get("proxy") or {},
                }
            )
        page += 1
    records.sort(key=lambda item: (str(item.get("email") or ""), str(item.get("name") or "")))
    return records


def refresh_sub2api_accounts(
    settings: dict[str, Any],
    account_ids: list[int],
    *,
    proxy_url: str = "",
) -> dict[str, Any]:
    response = _sub2api_request(
        settings,
        "POST",
        "/api/v1/admin/accounts/batch-refresh",
        proxy_url=proxy_url,
        headers={"Content-Type": "application/json"},
        json={"account_ids": [safe_int(account_id) for account_id in account_ids if safe_int(account_id) > 0]},
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(_response_error(response))
    data = _sub2api_response_data(response)
    return data if isinstance(data, dict) else {}


def bulk_update_sub2api_accounts(
    settings: dict[str, Any],
    account_ids: list[int],
    updates: dict[str, Any],
    *,
    proxy_url: str = "",
) -> dict[str, Any]:
    payload = {"account_ids": [safe_int(account_id) for account_id in account_ids if safe_int(account_id) > 0], **dict(updates or {})}
    response = _sub2api_request(
        settings,
        "POST",
        "/api/v1/admin/accounts/bulk-update",
        proxy_url=proxy_url,
        headers={"Content-Type": "application/json"},
        json=payload,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(_response_error(response))
    data = _sub2api_response_data(response)
    return data if isinstance(data, dict) else {}


def delete_sub2api_account(
    settings: dict[str, Any],
    account_id: int,
    *,
    proxy_url: str = "",
) -> tuple[bool, str]:
    response = _sub2api_request(
        settings,
        "DELETE",
        f"/api/v1/admin/accounts/{safe_int(account_id)}",
        proxy_url=proxy_url,
    )
    if response.status_code in (200, 201):
        try:
            data = _sub2api_response_data(response)
            if isinstance(data, dict):
                return True, str(data.get("message") or "删除成功")
        except Exception:
            pass
        return True, "删除成功"
    return False, _response_error(response)


def resolve_cpa_auth_file_path(record: dict[str, Any]) -> str:
    file_path = str(record.get("path") or "").strip()
    if file_path:
        return file_path
    file_name = str(record.get("name") or record.get("id") or "").strip()
    if not file_name:
        raise RuntimeError("CPA 记录缺少 path/name")
    return f"/root/.cli-proxy-api/{file_name}"


def _docker_exec(container_name: str, command: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container_name, "sh", "-lc", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        **_subprocess_silent_kwargs(),
    )


def load_cpa_auth_file_from_docker(settings: dict[str, Any], file_path: str) -> dict[str, Any]:
    container_name = _cpa_container_name(settings)
    command = f"cat {shlex.quote(str(file_path).strip())}"
    proc = _docker_exec(container_name, command, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "docker exec 读取失败")
    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:
        raise RuntimeError(f"CPA 文件 JSON 解析失败: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("CPA 文件内容不是对象")
    return payload


def save_cpa_auth_file_to_docker(settings: dict[str, Any], file_path: str, payload: dict[str, Any]) -> None:
    container_name = _cpa_container_name(settings)
    target_path = str(file_path).strip()
    if not target_path:
        raise RuntimeError("CPA 目标路径为空")
    parent_dir = str(Path(target_path).parent).replace("\\", "/")
    mkdir_proc = _docker_exec(container_name, f"mkdir -p {shlex.quote(parent_dir)}", timeout=15)
    if mkdir_proc.returncode != 0:
        raise RuntimeError(mkdir_proc.stderr.strip() or mkdir_proc.stdout.strip() or "创建 CPA 目录失败")

    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            temp_path = handle.name
        proc = subprocess.run(
            ["docker", "cp", temp_path, f"{container_name}:{target_path}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            **_subprocess_silent_kwargs(),
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "docker cp 写入失败")
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink()
            except Exception:
                pass


def set_cpa_auth_file_disabled(
    settings: dict[str, Any],
    name: str,
    disabled: bool,
    *,
    proxy_url: str = "",
) -> tuple[bool, str]:
    target_name = str(name or "").strip()
    if not target_name:
        return False, "CPA 文件名为空"
    response = requests.patch(
        f"{_cpa_api_url(settings)}/v0/management/auth-files/status",
        headers={
            **_cpa_management_headers(settings),
            "Content-Type": "application/json",
        },
        json={"name": target_name, "disabled": bool(disabled)},
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code == 200:
        return True, "已更新禁用状态"
    return False, _response_error(response)


def delete_cpa_auth_files(
    settings: dict[str, Any],
    names: list[str],
    *,
    delete_all: bool = False,
    proxy_url: str = "",
) -> tuple[bool, str]:
    response = requests.delete(
        f"{_cpa_api_url(settings)}/v0/management/auth-files",
        headers={
            **_cpa_management_headers(settings),
            "Content-Type": "application/json",
        },
        params={"all": "true"} if delete_all else None,
        json=None if delete_all else {"names": [name for name in names if str(name).strip()]},
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code in (200, 201):
        return True, "删除成功"
    return False, _response_error(response)


def fetch_cpa_accounts(settings: dict[str, Any], proxy_url: str = "") -> list[dict[str, Any]]:
    response = requests.get(
        f"{_cpa_api_url(settings)}/v0/management/auth-files",
        headers=_cpa_management_headers(settings),
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code != 200:
        raise RuntimeError(_response_error(response))

    data = response.json()
    items = data.get("files", []) if isinstance(data, dict) else []
    records: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        id_token = item.get("id_token") or {}
        if not isinstance(id_token, dict):
            id_token = {}
        plan = str(id_token.get("plan_type") or "").strip().lower() or "unknown"
        records.append(
            {
                "email": str(item.get("email") or "").strip(),
                "name": str(item.get("name") or "").strip(),
                "path": str(item.get("path") or "").strip(),
                "provider": str(item.get("provider") or item.get("type") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "status_message": str(item.get("status_message") or "").strip(),
                "last_refresh": str(item.get("last_refresh") or "").strip(),
                "next_retry_after": str(item.get("next_retry_after") or "").strip(),
                "disabled": bool(item.get("disabled")),
                "unavailable": bool(item.get("unavailable")),
                "plan": plan,
                "subscription_active_until": str(id_token.get("chatgpt_subscription_active_until") or "").strip(),
            }
        )
    records.sort(key=lambda item: (item.get("email", ""), item.get("status", "")))
    return records


def import_cpa_accounts_from_docker(settings: dict[str, Any], store, proxy_url: str = "") -> dict[str, Any]:
    container_name = _cpa_container_name(settings)
    summaries = fetch_cpa_accounts(settings, proxy_url=proxy_url)
    codex_rows = [item for item in summaries if str(item.get("provider") or "").strip().lower() == "codex"]

    def _status_rank(row: dict[str, Any]) -> tuple[int, str, str]:
        status = str(row.get("status") or "").strip().lower()
        rank = 3 if status == "active" else 2 if status == "refreshing" else 1 if status == "pending" else 0
        return (rank, str(row.get("last_refresh") or "").strip(), str(row.get("name") or "").strip())

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in codex_rows:
        email = str(row.get("email") or "").strip().lower()
        if not email:
            continue
        grouped.setdefault(email, []).append(row)

    selected_rows: list[dict[str, Any]] = []
    for _, items in grouped.items():
        selected_rows.append(sorted(items, key=_status_rank, reverse=True)[0])

    imported = 0
    failures: list[str] = []
    for row in selected_rows:
        file_name = str(row.get("name") or "").strip()
        file_path = str(row.get("path") or "").strip() or f"/root/.cli-proxy-api/{file_name}"
        if not file_name:
            failures.append("发现一条缺少文件名的 CPA 记录")
            continue
        command = f"cat {shlex.quote(file_path)}"
        proc = subprocess.run(
            ["docker", "exec", container_name, "sh", "-lc", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            **_subprocess_silent_kwargs(),
        )
        if proc.returncode != 0:
            failures.append(f"{file_name}: {proc.stderr.strip() or proc.stdout.strip() or 'docker exec 失败'}")
            continue
        try:
            payload = json.loads(proc.stdout)
        except Exception as exc:
            failures.append(f"{file_name}: JSON 解析失败 {exc}")
            continue
        if not isinstance(payload, dict):
            failures.append(f"{file_name}: 文件内容不是对象")
            continue
        if not any(payload.get(key) for key in ("access_token", "refresh_token", "id_token")):
            failures.append(f"{file_name}: 缺少 token 字段")
            continue
        store.save_record(payload)
        imported += 1

    return {
        "total": len(selected_rows),
        "imported": imported,
        "fail_count": len(failures),
        "failures": failures,
    }


def upload_to_cpa(record: dict[str, Any], settings: dict[str, Any], proxy_url: str = "") -> tuple[bool, str]:
    try:
        api_url = _cpa_api_url(settings)
        api_key = _cpa_api_key(settings)
    except RuntimeError as exc:
        return False, str(exc)
    payload = to_cpa_payload(record)
    response = requests.post(
        f"{api_url}/v0/management/auth-files",
        headers={"Authorization": f"Bearer {api_key}"},
        files={
            "file": (
                f"{payload['email']}.json",
                json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
                "application/json",
            )
        },
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code in (200, 201):
        return True, "上传成功"
    return False, _response_error(response)


def upload_to_sub2api(record: dict[str, Any], settings: dict[str, Any], proxy_url: str = "") -> tuple[bool, str]:
    try:
        group_ids = _sub2api_settings(settings).get("group_ids")
        payload = to_sub2api_payload(record, group_ids=group_ids)
        response = _sub2api_request(
            settings,
            "POST",
            "/api/v1/admin/accounts",
            proxy_url=proxy_url,
            headers={
                "Content-Type": "application/json",
                "Referer": f"{_sub2api_api_url(settings)}/admin/accounts",
            },
            json=payload,
        )
    except RuntimeError as exc:
        return False, str(exc)
    if response.status_code in (200, 201):
        try:
            _sub2api_response_data(response)
        except Exception as exc:
            return False, str(exc)
        return True, "上传成功"
    return False, _response_error(response)


def upload_state_patch(target: str, ok: bool, message: str) -> dict[str, Any]:
    return {
        "uploads": {
            target: {
                "ok": bool(ok),
                "message": str(message or "").strip(),
                "updated_at": now_rfc3339(),
            }
        }
    }
