from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

import requests

from .converters import to_cpa_payload, to_sub2api_payload
from .utils import build_requests_proxies, now_rfc3339


def _response_error(response: requests.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("msg") or data.get("error") or "").strip()
    except Exception:
        pass
    return response.text[:300].strip() or f"HTTP {response.status_code}"


def fetch_cpa_accounts(settings: dict[str, Any], proxy_url: str = "") -> list[dict[str, Any]]:
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    api_url = str(cpa.get("api_url") or "").strip()
    api_key = str(cpa.get("api_key") or "").strip()
    if not api_url:
        raise RuntimeError("CPA API URL 未配置")

    response = requests.get(
        f"{api_url.rstrip('/')}/v0/management/auth-files",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json, text/plain, */*",
        },
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
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    container_name = str(cpa.get("container_name") or "cli-proxy-api").strip() or "cli-proxy-api"
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
    cpa = ((settings.get("integrations") or {}).get("cpa") or {})
    api_url = str(cpa.get("api_url") or "").strip()
    api_key = str(cpa.get("api_key") or "").strip()
    if not api_url:
        return False, "CPA API URL 未配置"
    payload = to_cpa_payload(record)
    response = requests.post(
        f"{api_url.rstrip('/')}/v0/management/auth-files",
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
    sub2api = ((settings.get("integrations") or {}).get("sub2api") or {})
    api_url = str(sub2api.get("api_url") or "").strip()
    api_key = str(sub2api.get("api_key") or "").strip()
    group_ids = sub2api.get("group_ids")
    if not api_url:
        return False, "Sub2API API URL 未配置"
    if not api_key:
        return False, "Sub2API API Key 未配置"
    payload = to_sub2api_payload(record, group_ids=group_ids)
    response = requests.post(
        f"{api_url.rstrip('/')}/api/v1/admin/accounts",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Referer": f"{api_url.rstrip('/')}/admin/accounts",
            "x-api-key": api_key,
        },
        json=payload,
        timeout=30,
        verify=False,
        proxies=build_requests_proxies(proxy_url),
    )
    if response.status_code in (200, 201):
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
