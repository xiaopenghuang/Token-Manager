from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import count
from pathlib import Path
from typing import Any, Callable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from token_manager.config import load_app_config
from token_manager.constants import APP_DIR
from token_manager.oauth import OAuthCallbackServer, exchange_callback, generate_oauth_start
from token_manager.store import TokenStore
from token_manager.utils import now_rfc3339, parse_callback_url
from tools.auth_2fa_live import (
    AUTH_BASE_URL,
    AUTH_CONTINUE_URL,
    MFA_ISSUE_CHALLENGE_URL,
    MFA_VERIFY_URL,
    ORGANIZATION_SELECT_URL,
    PASSWORD_VERIFY_URL,
    SENTINEL_URL,
    WORKSPACE_SELECT_URL,
    AuthAccount,
    _compact_egress_payload,
    _detect_egress_drift,
    _ensure_dir,
    _fetch_live_totp_code,
    _resolve_proxy_egress,
    _sanitize_account_payload,
    _sanitize_log_entry,
    _select_effective_egress,
    _select_workspace,
    _snippet,
    _start_to_dict,
    _timestamp_slug,
    _token_summary,
    _write_json,
    parse_account_lines,
)
from tools.flow_probe_core import CDPClient, TargetInfo, load_targets


DEFAULT_DEBUG_PORT_BASE = 9333
PAGE_STATE_JS = r"""
(() => {
  const walkRoots = (root, out) => {
    if (!root) {
      return;
    }
    out.push(root);
    const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
    for (const node of all) {
      if (node && node.shadowRoot) {
        walkRoots(node.shadowRoot, out);
      }
    }
  };

  const collect = (selector) => {
    const roots = [];
    walkRoots(document, roots);
    const seen = new Set();
    const items = [];
    for (const root of roots) {
      const found = root.querySelectorAll ? root.querySelectorAll(selector) : [];
      for (const element of found) {
        if (!seen.has(element)) {
          seen.add(element);
          items.push(element);
        }
      }
    }
    return items;
  };

  const visible = (element) => {
    if (!element || !element.getBoundingClientRect) {
      return false;
    }
    const style = window.getComputedStyle(element);
    if (!style || style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity || '1') === 0) {
      return false;
    }
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  const labelText = (element) => {
    const bits = [];
    const label = element.closest ? element.closest('label') : null;
    if (label && label.innerText) {
      bits.push(label.innerText);
    }
    const labelId = element.getAttribute && element.getAttribute('aria-labelledby');
    if (labelId) {
      for (const part of labelId.split(/\s+/)) {
        const match = document.getElementById(part);
        if (match && match.innerText) {
          bits.push(match.innerText);
        }
      }
    }
    return bits.join(' ').replace(/\s+/g, ' ').trim();
  };

  const fields = collect('input, textarea')
    .filter(visible)
    .slice(0, 16)
    .map((element) => ({
      tag: String(element.tagName || '').toLowerCase(),
      type: String(element.type || '').toLowerCase(),
      name: String(element.name || ''),
      id: String(element.id || ''),
      placeholder: String(element.placeholder || ''),
      autocomplete: String(element.autocomplete || ''),
      input_mode: String(element.inputMode || ''),
      aria: String(element.getAttribute ? element.getAttribute('aria-label') || '' : ''),
      label: labelText(element),
      max_length: Number(element.maxLength || 0),
      value_length: String(element.value || '').length,
    }));

  const buttons = collect('button, input[type="submit"], [role="button"], a')
    .filter(visible)
    .slice(0, 24)
    .map((element) => ({
      tag: String(element.tagName || '').toLowerCase(),
      type: String(element.type || '').toLowerCase(),
      text: String(element.innerText || element.value || element.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
      disabled: !!element.disabled || element.getAttribute?.('aria-disabled') === 'true',
      href: String(element.href || ''),
      class_name: String(element.className || ''),
    }));

  const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 1800);
  return {
    href: String(location.href || ''),
    path: String(location.pathname || ''),
    title: String(document.title || ''),
    ready_state: String(document.readyState || ''),
    has_cloudflare: /just a moment|verify you are human|checking your browser|security check/i.test(bodyText) || !!document.querySelector('iframe[src*="challenge"], iframe[title*="challenge"], [name="cf-turnstile-response"]'),
    body_text: bodyText,
    fields,
    buttons,
  };
})()
"""


def detect_browser_path() -> str:
    local_appdata = Path(os.environ.get("LOCALAPPDATA") or "")
    program_files = Path(os.environ.get("PROGRAMFILES") or "")
    program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)") or "")
    candidates: list[Path] = []
    for base, relative in (
        (local_appdata, r"Google\Chrome\Application\chrome.exe"),
        (program_files, r"Google\Chrome\Application\chrome.exe"),
        (program_files_x86, r"Google\Chrome\Application\chrome.exe"),
        (local_appdata, r"Microsoft\Edge\Application\msedge.exe"),
        (program_files, r"Microsoft\Edge\Application\msedge.exe"),
        (program_files_x86, r"Microsoft\Edge\Application\msedge.exe"),
    ):
        if str(base):
            candidates.append(base / relative)
    for path in candidates:
        if path.exists():
            return str(path)
    return ""


def _default_save_dir() -> Path:
    return APP_DIR / "outputs" / "auth_2fa_browser"


def _default_profile_root(save_dir: Path) -> Path:
    return _ensure_dir(save_dir / "profiles")


def _sanitize_profile_name(email: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(email or "").strip().lower()).strip("._-")
    digest = hashlib.sha1(str(email or "").encode("utf-8")).hexdigest()[:10]
    return f"{cleaned[:48] or 'account'}_{digest}"


def _build_browser_command(
    *,
    browser_path: str,
    debug_port: int,
    profile_dir: Path,
    start_url: str,
    proxy_url: str,
) -> list[str]:
    command = [
        browser_path,
        f"--remote-debugging-port={int(debug_port)}",
        "--remote-allow-origins=*",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-default-apps",
        "--window-size=1360,900",
        "--new-window",
    ]
    if str(proxy_url or "").strip():
        command.append(f"--proxy-server={str(proxy_url).strip()}")
    command.append(start_url)
    return command


def _launch_browser(
    *,
    browser_path: str,
    debug_port: int,
    profile_dir: Path,
    start_url: str,
    proxy_url: str,
) -> subprocess.Popen[Any]:
    command = _build_browser_command(
        browser_path=browser_path,
        debug_port=debug_port,
        profile_dir=profile_dir,
        start_url=start_url,
        proxy_url=proxy_url,
    )
    return subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )


def _stop_browser(process: subprocess.Popen[Any] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=8)
        return
    except Exception:
        pass
    try:
        process.kill()
        process.wait(timeout=5)
    except Exception:
        pass


def _pick_target(targets: list[TargetInfo]) -> TargetInfo:
    filtered = [item for item in targets if not str(item.url or "").startswith("devtools://")]
    if not filtered:
        raise RuntimeError("没有找到可操作的浏览器页签")
    for item in filtered:
        if "auth.openai.com" in str(item.url or ""):
            return item
    for item in filtered:
        if str(item.url or "") == "about:blank":
            return item
    return filtered[0]


def _wait_for_target(debug_port: int, timeout: int) -> TargetInfo:
    deadline = time.time() + max(5, int(timeout))
    last_error = ""
    while time.time() < deadline:
        try:
            targets = load_targets(debug_port)
            if targets:
                return _pick_target(targets)
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.8)
    raise RuntimeError(f"浏览器调试端口没接上 {debug_port} {last_error}".strip())


def _absolute_auth_url(value: str, fallback: str) -> str:
    text = str(value or "").strip()
    if not text:
        text = fallback
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if not text.startswith("/"):
        text = "/" + text
    return f"{AUTH_BASE_URL}{text}"


def _runtime_eval(client: CDPClient, expression: str, *, timeout: int = 30) -> Any:
    result = client.call(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        },
        timeout=timeout,
    )
    if result.get("exceptionDetails"):
        details = result.get("exceptionDetails") or {}
        raise RuntimeError(str(details.get("text") or "Runtime.evaluate failed").strip())
    runtime_result = dict(result.get("result") or {})
    if "value" in runtime_result:
        return runtime_result.get("value")
    if "unserializableValue" in runtime_result:
        return runtime_result.get("unserializableValue")
    return None


def _get_page_state(client: CDPClient) -> dict[str, Any]:
    try:
        value = _runtime_eval(client, PAGE_STATE_JS, timeout=15)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _page_action_click_terms(terms: list[str]) -> str:
    payload = json.dumps({"terms": terms}, ensure_ascii=False)
    return f"""
(() => {{
  const request = {payload};
  const walkRoots = (root, out) => {{
    if (!root) return;
    out.push(root);
    const all = root.querySelectorAll ? root.querySelectorAll('*') : [];
    for (const node of all) {{
      if (node && node.shadowRoot) {{
        walkRoots(node.shadowRoot, out);
      }}
    }}
  }};
  const collect = (selector) => {{
    const roots = [];
    walkRoots(document, roots);
    const seen = new Set();
    const items = [];
    for (const root of roots) {{
      const found = root.querySelectorAll ? root.querySelectorAll(selector) : [];
      for (const element of found) {{
        if (!seen.has(element)) {{
          seen.add(element);
          items.push(element);
        }}
      }}
    }}
    return items;
  }};
  const visible = (element) => {{
    if (!element || !element.getBoundingClientRect) return false;
    const style = window.getComputedStyle(element);
    if (!style || style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity || '1') === 0) return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }};
  const buttons = collect('button, input[type="submit"], [role="button"], a').filter(visible).filter((element) => !element.disabled);
  const scored = buttons
    .map((element) => {{
      const text = String(element.innerText || element.value || element.getAttribute?.('aria-label') || '').replace(/\\s+/g, ' ').trim();
      const lowered = text.toLowerCase();
      let score = 0;
      for (const term of request.terms || []) {{
        const normalized = String(term || '').toLowerCase();
        if (!normalized) {{
          continue;
        }}
        if (lowered === normalized) {{
          score += 12;
        }} else if (lowered.includes(normalized)) {{
          score += 6;
        }}
      }}
      if (/primary|solid|cta|continue|accept|authorize|allow/.test(String(element.className || '').toLowerCase())) {{
        score += 2;
      }}
      return {{ element, text, score }};
    }})
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score);
  if (!scored.length) {{
    const forms = collect('form');
    if (forms[0] && forms[0].requestSubmit) {{
      forms[0].requestSubmit();
      return {{ ok: true, action: 'request_submit', text: '' }};
    }}
    return {{ ok: false, reason: 'button_not_found' }};
  }}
  const target = scored[0];
  target.element.click();
  return {{ ok: true, action: 'click', text: target.text }};
}})()
"""


def _browser_fetch_expression(payload: dict[str, Any]) -> str:
    literal = json.dumps(payload, ensure_ascii=False)
    return f"""
(async () => {{
  const request = {literal};
  const headers = new Headers(request.headers || {{}});
  const options = {{
    method: String(request.method || 'GET'),
    headers,
    credentials: 'include',
    redirect: 'follow',
  }};
  if (request.referrer) {{
    options.referrer = request.referrer;
  }}
  if (Object.prototype.hasOwnProperty.call(request, 'body')) {{
    options.body = request.body;
  }}
  const response = await fetch(request.url, options);
  const text = await response.text();
  let parsed = null;
  try {{
    parsed = JSON.parse(text);
  }} catch (error) {{
    parsed = null;
  }}
  return {{
    ok: response.ok,
    status: response.status,
    url: response.url,
    redirected: response.redirected,
    headers: Object.fromEntries(response.headers.entries()),
    text: String(text || '').slice(0, 8000),
    json: parsed,
    type: response.type,
  }};
}})()
"""


def _browser_fetch(
    client: CDPClient,
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    body_text: str | None = None,
    referrer: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "url": url,
        "method": method,
        "headers": dict(headers or {}),
        "referrer": referrer,
    }
    if json_body is not None:
        payload["body"] = json.dumps(json_body, ensure_ascii=False)
    elif body_text is not None:
        payload["body"] = body_text
    value = _runtime_eval(client, _browser_fetch_expression(payload), timeout=timeout)
    return value if isinstance(value, dict) else {}


def _browser_response_entry(step: str, response: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    payload = {"step": step, "ts": now_rfc3339()}
    if response:
        payload["status"] = int(response.get("status") or 0)
        payload["url"] = str(response.get("url") or "")
        payload["body"] = _snippet(response.get("text") or "")
        json_payload = response.get("json")
        if isinstance(json_payload, dict):
            payload["json"] = json_payload
    payload.update(extra)
    return payload


def _friendly_message(entry: dict[str, Any]) -> str:
    step = str(entry.get("step") or "")
    if step == "egress_probe":
        egress = _compact_egress_payload(entry.get("egress") or {})
        place = " / ".join([item for item in (egress.get("country"), egress.get("region"), egress.get("city")) if item])
        if egress.get("error"):
            return "准备中 出口地区没认出来，先继续跑"
        if place and egress.get("ip"):
            return f"准备中 这条线走到 {place} 了 {egress.get('ip')}"
        if egress.get("ip"):
            return f"准备中 出口先记成 {egress.get('ip')}"
        return "准备中 出口已经标记好了"
    if step == "browser_launch":
        return f"第1步 浏览器小窗已经起好了 端口 {int(entry.get('debug_port') or 0)}"
    if step == "browser_ready":
        return "第2步 浏览器链已经接上了"
    if step == "browser_cloudflare":
        return "第3步 正在等盾放行"
    if step == "sentinel_token":
        return "第4步 风控票据准备好了"
    if step == "authorize_continue":
        return "第5步 邮箱已经递上去了"
    if step == "password_verify":
        return "第6步 密码对上啦"
    if step == "browser_totp_fetch":
        return "第7步 2FA 小码拿到了"
    if step == "mfa_verify":
        return "第8步 2FA 通过啦"
    if step == "consent_page":
        return "第9步 授权页已经出来了"
    if step == "workspace_select":
        return "第10步 账号空间选好了"
    if step == "organization_page":
        return "第11步 组织页已经到啦"
    if step == "organization_select":
        return "第12步 组织也选好了"
    if step == "browser_navigate":
        return "收尾中 浏览器正在走最后几跳"
    if step == "browser_consent":
        return "收尾中 同意页已经点过了"
    if step == "callback_ready":
        return "完成啦 回调已经抓到啦"
    if step == "egress_recheck":
        egress = _compact_egress_payload(entry.get("egress") or {})
        place = " / ".join([item for item in (egress.get("country"), egress.get("region"), egress.get("city")) if item])
        if egress.get("error"):
            return "收尾中 出口复查没拿到，先按现有链路收尾"
        if place and egress.get("ip"):
            return f"收尾中 出口复查还是 {place} {egress.get('ip')}"
        if egress.get("ip"):
            return f"收尾中 出口复查还是 {egress.get('ip')}"
        return "收尾中 出口复查完成了"
    if step == "egress_drift":
        previous = _compact_egress_payload(entry.get("previous_egress") or {})
        current = _compact_egress_payload(entry.get("egress") or {})
        previous_text = " / ".join([item for item in (previous.get("country"), previous.get("region"), previous.get("city"), previous.get("ip")) if item]) or "未知出口"
        current_text = " / ".join([item for item in (current.get("country"), current.get("region"), current.get("city"), current.get("ip")) if item]) or "未知出口"
        return f"收尾中 出口漂了 从 {previous_text} 变成 {current_text}"
    return step or "处理中"


def _emit_log(entry: dict[str, Any], *, quiet: bool, include_secrets: bool, log_fn: Callable[[str], None] | None = None) -> None:
    sanitized = _sanitize_log_entry(entry, include_secrets=include_secrets)
    error = str(sanitized.get("error") or "")
    message = f"[{str(sanitized.get('step') or 'error')}] 小翻车了 {error}" if error else _friendly_message(sanitized)
    if callable(log_fn):
        log_fn(message)
    if not quiet:
        print(message, flush=True)


def _push_log(
    logs: list[dict[str, Any]],
    entry: dict[str, Any],
    *,
    quiet: bool,
    include_secrets: bool,
    log_fn: Callable[[str], None] | None = None,
) -> None:
    logs.append(entry)
    _emit_log(entry, quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)


def _save_report(
    *,
    account: AuthAccount,
    settings: dict[str, Any],
    start: Any,
    callback_url: str,
    token_data: dict[str, Any] | None,
    save_dir: Path,
    logs: list[dict[str, Any]],
    browser_path: str,
    debug_port: int,
    profile_dir: Path,
    error: str = "",
    token_path: str = "",
    include_secrets: bool = False,
    egress: dict[str, Any] | None = None,
    egress_start: dict[str, Any] | None = None,
    egress_end: dict[str, Any] | None = None,
    egress_drift: bool = False,
) -> Path:
    prefix = "auth_2fa_browser_fail" if error else "auth_2fa_browser"
    report_path = save_dir / f"{prefix}_{_timestamp_slug()}.json"
    payload = {
        "created_at": now_rfc3339(),
        "auth_mode": "browser",
        "proxy": str(settings.get("http_proxy") or ""),
        "oauth": dict(settings.get("oauth") or {}),
        "browser": {
            "path": browser_path,
            "debug_port": int(debug_port or 0),
            "profile_dir": str(profile_dir),
        },
        "start": _start_to_dict(start),
        "account": _sanitize_account_payload(account, include_secrets=include_secrets),
        "egress": _compact_egress_payload(egress or {}),
        "egress_start": _compact_egress_payload(egress_start or {}),
        "egress_end": _compact_egress_payload(egress_end or {}),
        "egress_drift": bool(egress_drift),
        "callback_url": callback_url,
        "token_summary": _token_summary(token_data or {}) if token_data else {},
        "token_data": token_data or {},
        "token_path": token_path,
        "error": error,
        "logs": [_sanitize_log_entry(item, include_secrets=include_secrets) for item in logs],
    }
    _write_json(report_path, payload)
    return report_path


def _save_batch_summary(
    *,
    settings: dict[str, Any],
    save_dir: Path,
    workers: int,
    save_token: bool,
    include_secrets: bool,
    parsed_count: int,
    input_errors: list[str],
    results: list[dict[str, Any]],
) -> Path:
    summary_path = save_dir / f"auth_2fa_browser_batch_{_timestamp_slug()}.json"
    compact_results = []
    for item in results:
        token_summary = dict(item.get("token_summary") or {})
        compact_results.append(
            {
                "ok": bool(item.get("ok")),
                "email": str(item.get("email") or ""),
                "message": str(item.get("message") or ""),
                "report_path": str(item.get("report_path") or ""),
                "token_path": str(item.get("token_path") or ""),
                "account_id": str(token_summary.get("account_id") or ""),
                "plan": str(token_summary.get("plan") or ""),
                "egress": _compact_egress_payload(item.get("egress") or {}),
                "egress_start": _compact_egress_payload(item.get("egress_start") or {}),
                "egress_end": _compact_egress_payload(item.get("egress_end") or {}),
                "egress_drift": bool(item.get("egress_drift")),
                "debug_port": int(item.get("debug_port") or 0),
                "browser_path": str(item.get("browser_path") or ""),
            }
        )
    payload = {
        "created_at": now_rfc3339(),
        "auth_mode": "browser",
        "proxy": str(settings.get("http_proxy") or ""),
        "workers": int(workers or 1),
        "save_token": bool(save_token),
        "include_secrets": bool(include_secrets),
        "parsed_count": parsed_count,
        "input_error_count": len(input_errors),
        "input_errors": input_errors,
        "success_count": sum(1 for item in results if item.get("ok")),
        "fail_count": sum(1 for item in results if not item.get("ok")),
        "results": compact_results,
    }
    _write_json(summary_path, payload)
    return summary_path


def _browser_headers(*, referer: str, sentinel: str = "", accept_json: bool = True) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "origin": AUTH_BASE_URL,
    }
    if referer:
        headers["referer"] = referer
    if accept_json:
        headers["accept"] = "application/json"
    if sentinel:
        headers["openai-sentinel-token"] = sentinel
    return headers


def _fetch_cookie_value(client: CDPClient, url: str, name: str) -> str:
    result = client.call("Network.getCookies", {"urls": [url]}, timeout=20)
    cookies = result.get("cookies") or []
    for item in cookies if isinstance(cookies, list) else []:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").strip() == name:
            return str(item.get("value") or "").strip()
    return ""


def _wait_for_cookie_value(client: CDPClient, url: str, name: str, timeout: int) -> str:
    deadline = time.time() + max(5, int(timeout))
    while time.time() < deadline:
        value = _fetch_cookie_value(client, url, name)
        if value:
            return value
        time.sleep(0.6)
    return ""


def _require_browser_ok(response: dict[str, Any], message: str) -> None:
    if int(response.get("status") or 0) == 200:
        return
    raise RuntimeError(f"{message}: HTTP {int(response.get('status') or 0)} {_snippet(response.get('text') or response)}")


def _wait_for_auth_ready(
    client: CDPClient,
    *,
    auth_url: str,
    logs: list[dict[str, Any]],
    quiet: bool,
    include_secrets: bool,
    log_fn: Callable[[str], None] | None = None,
    timeout: int = 90,
) -> tuple[dict[str, Any], str]:
    deadline = time.time() + max(20, int(timeout))
    last_cloudflare_log = 0.0
    while time.time() < deadline:
        state = _get_page_state(client)
        did = _fetch_cookie_value(client, auth_url, "oai-did")
        if did and not bool(state.get("has_cloudflare")):
            return state, did
        if bool(state.get("has_cloudflare")) and time.time() - last_cloudflare_log >= 6:
            _push_log(
                logs,
                {
                    "step": "browser_cloudflare",
                    "ts": now_rfc3339(),
                    "url": str(state.get("href") or ""),
                    "title": str(state.get("title") or ""),
                },
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
            last_cloudflare_log = time.time()
        time.sleep(1.0)
    raise RuntimeError("浏览器授权页一直没准备好")


def _fetch_browser_sentinel(client: CDPClient, did: str) -> str:
    payload = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'
    response = _browser_fetch(
        client,
        url=SENTINEL_URL,
        method="POST",
        headers={
            "origin": "https://sentinel.openai.com",
            "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
            "content-type": "text/plain;charset=UTF-8",
        },
        body_text=payload,
        timeout=30,
    )
    token = str(((response.get("json") or {}).get("token") if isinstance(response.get("json"), dict) else "") or "").strip()
    if token:
        return token
    raise RuntimeError(f"sentinel 取 token 失败: HTTP {int(response.get('status') or 0)} {_snippet(response.get('text') or response)}")


def _click_terms(client: CDPClient, terms: list[str]) -> dict[str, Any]:
    value = _runtime_eval(client, _page_action_click_terms(terms), timeout=20)
    return value if isinstance(value, dict) else {}


def _navigate_browser_page(client: CDPClient, url: str, *, timeout: int = 30) -> dict[str, Any]:
    client.call("Page.navigate", {"url": url}, timeout=20)
    deadline = time.time() + max(8, int(timeout))
    last_state: dict[str, Any] = {}
    while time.time() < deadline:
        state = _get_page_state(client)
        if state:
            last_state = state
        href = str((state or {}).get("href") or "").strip()
        ready_state = str((state or {}).get("ready_state") or "").strip().lower()
        if href and ready_state in {"interactive", "complete"}:
            return state
        time.sleep(0.5)
    return last_state


def _follow_browser_to_callback(
    client: CDPClient,
    server: OAuthCallbackServer,
    next_url: str,
    *,
    timeout: int,
    logs: list[dict[str, Any]],
    quiet: bool,
    include_secrets: bool,
    log_fn: Callable[[str], None] | None = None,
) -> str:
    client.call("Page.navigate", {"url": next_url}, timeout=20)
    _push_log(
        logs,
        {"step": "browser_navigate", "ts": now_rfc3339(), "url": next_url},
        quiet=quiet,
        include_secrets=include_secrets,
        log_fn=log_fn,
    )
    deadline = time.time() + max(20, int(timeout))
    clicked_at = 0.0
    clicked_url = ""
    while time.time() < deadline:
        try:
            callback_url = server.wait(1)
            if callback_url:
                return callback_url
        except TimeoutError:
            pass
        state = _get_page_state(client)
        current_url = str(state.get("href") or "")
        if current_url and "code=" in current_url and "state=" in current_url:
            return current_url
        if "consent_challenge=" in current_url:
            now = time.time()
            if current_url != clicked_url or now - clicked_at >= 3:
                clicked = _click_terms(client, ["accept", "authorize", "allow", "continue", "同意", "授权", "继续"])
                if bool(clicked.get("ok")):
                    _push_log(
                        logs,
                        {
                            "step": "browser_consent",
                            "ts": now_rfc3339(),
                            "url": current_url,
                            "button": str(clicked.get("text") or ""),
                        },
                        quiet=quiet,
                        include_secrets=include_secrets,
                        log_fn=log_fn,
                    )
                    clicked_at = now
                    clicked_url = current_url
                    time.sleep(1.5)
                    continue
        if bool(state.get("has_cloudflare")):
            time.sleep(1.0)
            continue
    raise RuntimeError("浏览器链没有等到 callback_url")


def authorize_account_browser(
    account: AuthAccount,
    settings: dict[str, Any],
    *,
    browser_path: str = "",
    debug_port: int = 0,
    timeout: int = 300,
    save_dir: Path | None = None,
    save_token: bool = False,
    include_secrets: bool = False,
    quiet: bool = False,
    log_fn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    save_dir = _ensure_dir(save_dir or _default_save_dir())
    proxy_url = str(settings.get("http_proxy") or "")
    resolved_browser_path = str(browser_path or settings.get("browser_executable_path") or detect_browser_path()).strip()
    if not resolved_browser_path:
        raise RuntimeError("没有找到浏览器路径，请在设置里填 Chrome 或 Edge 的 exe 路径")
    if not Path(resolved_browser_path).exists():
        raise RuntimeError(f"浏览器路径不存在 {resolved_browser_path}")

    start = generate_oauth_start(settings)
    logs: list[dict[str, Any]] = []
    browser_process: subprocess.Popen[Any] | None = None
    client: CDPClient | None = None
    callback_server: OAuthCallbackServer | None = None
    callback_url = ""
    token_data: dict[str, Any] | None = None
    token_path = ""
    egress_start = _resolve_proxy_egress(proxy_url)
    egress_end = dict(egress_start)
    egress_drift = False
    egress = _select_effective_egress(egress_start, egress_end)
    profile_dir = _default_profile_root(save_dir) / _sanitize_profile_name(account.email)
    profile_dir.mkdir(parents=True, exist_ok=True)
    resolved_debug_port = int(debug_port or int(settings.get("browser_auth_start_port") or DEFAULT_DEBUG_PORT_BASE))

    try:
        _push_log(
            logs,
            {"step": "egress_probe", "ts": now_rfc3339(), "egress": egress_start},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        callback_server = OAuthCallbackServer(start.redirect_uri)
        callback_server.start()

        browser_process = _launch_browser(
            browser_path=resolved_browser_path,
            debug_port=resolved_debug_port,
            profile_dir=profile_dir,
            start_url=start.auth_url,
            proxy_url=proxy_url,
        )
        _push_log(
            logs,
            {
                "step": "browser_launch",
                "ts": now_rfc3339(),
                "browser_path": resolved_browser_path,
                "debug_port": resolved_debug_port,
                "profile_dir": str(profile_dir),
            },
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        target = _wait_for_target(resolved_debug_port, 35)
        client = CDPClient(target.web_socket_debugger_url)
        client.call("Page.enable")
        client.call("Runtime.enable")
        client.call("Network.enable")
        client.call("Network.setCacheDisabled", {"cacheDisabled": True})
        client.call("Page.navigate", {"url": start.auth_url}, timeout=20)
        _push_log(
            logs,
            {
                "step": "browser_ready",
                "ts": now_rfc3339(),
                "target_title": str(target.title or ""),
                "target_url": str(target.url or ""),
            },
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        _state, did = _wait_for_auth_ready(
            client,
            auth_url=start.auth_url,
            logs=logs,
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
            timeout=min(timeout, 120),
        )
        sentinel_token = _fetch_browser_sentinel(client, did)
        sentinel = f'{{"p": "", "t": "", "c": "{sentinel_token}", "id": "{did}", "flow": "authorize_continue"}}'
        _push_log(
            logs,
            {"step": "sentinel_token", "ts": now_rfc3339(), "did": did, "token_len": len(sentinel_token)},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        login_response = _browser_fetch(
            client,
            url=AUTH_CONTINUE_URL,
            method="POST",
            headers=_browser_headers(referer=f"{AUTH_BASE_URL}/log-in", sentinel=sentinel),
            json_body={"username": {"kind": "email", "value": account.email}},
            referrer=f"{AUTH_BASE_URL}/log-in",
        )
        _push_log(logs, _browser_response_entry("authorize_continue", login_response), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_browser_ok(login_response, "邮箱提交失败")

        password_response = _browser_fetch(
            client,
            url=PASSWORD_VERIFY_URL,
            method="POST",
            headers=_browser_headers(referer=f"{AUTH_BASE_URL}/log-in/password", sentinel=sentinel),
            json_body={"password": account.password},
            referrer=f"{AUTH_BASE_URL}/log-in/password",
        )
        _push_log(logs, _browser_response_entry("password_verify", password_response), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_browser_ok(password_response, "密码校验失败")

        password_payload = password_response.get("json") or {}
        if not isinstance(password_payload, dict):
            raise RuntimeError("密码校验返回异常")
        factor_id = ""
        factors = (((password_payload.get("page") or {}).get("payload") or {}).get("factors") or []) if isinstance(password_payload.get("page"), dict) else []
        for item in factors if isinstance(factors, list) else []:
            if not isinstance(item, dict):
                continue
            if str(item.get("factor_type") or "").strip().lower() == "totp":
                factor_id = str(item.get("id") or "").strip()
                if factor_id:
                    break
        if not factor_id:
            raise RuntimeError(f"没有找到 totp 因子 {_snippet(password_payload)}")

        mfa_page_url = f"{AUTH_BASE_URL}/log-in/password"
        issue_response = _browser_fetch(
            client,
            url=MFA_ISSUE_CHALLENGE_URL,
            method="POST",
            headers=_browser_headers(referer=mfa_page_url, accept_json=False),
            json_body={"id": factor_id, "type": "totp", "force_fresh_challenge": False},
            referrer=mfa_page_url,
        )
        _push_log(logs, _browser_response_entry("mfa_issue_challenge", issue_response, factor_id=factor_id), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_browser_ok(issue_response, "2FA challenge 初始化失败")

        verify_payload: dict[str, Any] = {}
        verify_error = ""
        for attempt in range(1, 4):
            totp_code = _fetch_live_totp_code(account.totp_secret, proxy_url)
            _push_log(
                logs,
                {"step": "browser_totp_fetch", "ts": now_rfc3339(), "attempt": attempt, "totp_code": totp_code},
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
            verify_response = _browser_fetch(
                client,
                url=MFA_VERIFY_URL,
                method="POST",
                headers=_browser_headers(referer=mfa_page_url),
                json_body={"id": factor_id, "type": "totp", "code": totp_code},
                referrer=mfa_page_url,
            )
            _push_log(
                logs,
                _browser_response_entry("mfa_verify", verify_response, factor_id=factor_id, attempt=attempt, totp_code=totp_code),
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
            if int(verify_response.get("status") or 0) == 200 and isinstance(verify_response.get("json"), dict):
                verify_payload = dict(verify_response.get("json") or {})
                verify_error = ""
                break
            verify_error = f"2FA 验证失败: HTTP {int(verify_response.get('status') or 0)} {_snippet(verify_response.get('text') or verify_response)}"
            if attempt < 3:
                time.sleep(31)
        if verify_error:
            raise RuntimeError(verify_error)

        consent_url = _absolute_auth_url(
            str(verify_payload.get("continue_url") or ""),
            "/sign-in-with-chatgpt/codex/consent",
        )
        consent_page = _navigate_browser_page(client, consent_url, timeout=30)
        _push_log(
            logs,
            {
                "step": "consent_page",
                "ts": now_rfc3339(),
                "url": str(consent_page.get("href") or consent_url),
                "title": str(consent_page.get("title") or ""),
                "path": str(consent_page.get("path") or ""),
                "body": _snippet(consent_page.get("body_text") or ""),
            },
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        auth_cookie = _wait_for_cookie_value(client, AUTH_BASE_URL, "oai-client-auth-session", 20)
        if not auth_cookie:
            raise RuntimeError("没有拿到 oai-client-auth-session")
        workspace_id = _select_workspace(auth_cookie)

        workspace_response = _browser_fetch(
            client,
            url=WORKSPACE_SELECT_URL,
            method="POST",
            headers=_browser_headers(referer=str(consent_page.get("href") or consent_url)),
            json_body={"workspace_id": workspace_id},
            referrer=str(consent_page.get("href") or consent_url),
        )
        _push_log(logs, _browser_response_entry("workspace_select", workspace_response, workspace_id=workspace_id), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_browser_ok(workspace_response, "workspace 选择失败")
        workspace_data = workspace_response.get("json") or {}
        if not isinstance(workspace_data, dict):
            raise RuntimeError("workspace 返回异常")

        orgs = ((workspace_data.get("data") or {}).get("orgs") or []) if isinstance(workspace_data.get("data"), dict) else []
        if not orgs:
            raise RuntimeError("workspace 返回里没有 orgs")
        org = orgs[0] or {}
        org_id = str(org.get("id") or "").strip()
        if not org_id:
            raise RuntimeError("org_id 为空")
        body: dict[str, str] = {"org_id": org_id}
        projects = org.get("projects") or []
        if isinstance(projects, list) and projects:
            project_id = str((projects[0] or {}).get("id") or "").strip()
            if project_id:
                body["project_id"] = project_id

        org_page_url = _absolute_auth_url(
            str(workspace_data.get("continue_url") or ""),
            "/sign-in-with-chatgpt/codex/organization",
        )
        organization_page = _navigate_browser_page(client, org_page_url, timeout=30)
        _push_log(
            logs,
            {
                "step": "organization_page",
                "ts": now_rfc3339(),
                "url": str(organization_page.get("href") or org_page_url),
                "title": str(organization_page.get("title") or ""),
                "path": str(organization_page.get("path") or ""),
                "body": _snippet(organization_page.get("body_text") or ""),
            },
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        organization_response = _browser_fetch(
            client,
            url=ORGANIZATION_SELECT_URL,
            method="POST",
            headers=_browser_headers(referer=str(organization_page.get("href") or org_page_url)),
            json_body=body,
            referrer=str(organization_page.get("href") or org_page_url),
        )
        _push_log(logs, _browser_response_entry("organization_select", organization_response, org_id=org_id, project_id=body.get("project_id", "")), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_browser_ok(organization_response, "组织选择失败")
        organization_data = organization_response.get("json") or {}
        if not isinstance(organization_data, dict):
            raise RuntimeError("组织选择返回异常")

        next_url = str(
            organization_data.get("continue_url")
            or ((organization_data.get("page") or {}).get("payload") or {}).get("url")
            or ""
        ).strip()
        if not next_url:
            raise RuntimeError("组织选择后没有继续 URL")
        next_url = _absolute_auth_url(next_url, "/sign-in-with-chatgpt/codex/organization")

        callback_url = _follow_browser_to_callback(
            client,
            callback_server,
            next_url,
            timeout=max(30, int(timeout)),
            logs=logs,
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        _push_log(
            logs,
            {"step": "callback_ready", "ts": now_rfc3339(), "callback_url": callback_url},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        parse_callback_url(callback_url)

        egress_end = _resolve_proxy_egress(proxy_url)
        egress_drift = _detect_egress_drift(egress_start, egress_end)
        egress = _select_effective_egress(egress_start, egress_end)
        _push_log(
            logs,
            {
                "step": "egress_drift" if egress_drift else "egress_recheck",
                "ts": now_rfc3339(),
                "egress": egress_end,
                "previous_egress": egress_start,
            },
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        token_data = exchange_callback(callback_url, start, settings, proxy_url=proxy_url)
        if save_token:
            store = TokenStore(settings)
            token_path = str(store.save_token_response(token_data, metadata={"auth_mode": "2fa_browser"}))

        report_path = _save_report(
            account=account,
            settings=settings,
            start=start,
            callback_url=callback_url,
            token_data=token_data,
            save_dir=save_dir,
            logs=logs,
            browser_path=resolved_browser_path,
            debug_port=resolved_debug_port,
            profile_dir=profile_dir,
            token_path=token_path,
            include_secrets=include_secrets,
            egress=egress,
            egress_start=egress_start,
            egress_end=egress_end,
            egress_drift=egress_drift,
        )
        return {
            "ok": True,
            "email": str(token_data.get("email") or account.email),
            "message": "ok",
            "callback_url": callback_url,
            "report_path": str(report_path),
            "token_path": token_path,
            "token_data": token_data,
            "token_summary": _token_summary(token_data),
            "egress": egress,
            "egress_start": egress_start,
            "egress_end": egress_end,
            "egress_drift": egress_drift,
            "debug_port": resolved_debug_port,
            "browser_path": resolved_browser_path,
        }
    except Exception as exc:
        egress_end = _resolve_proxy_egress(proxy_url)
        egress_drift = _detect_egress_drift(egress_start, egress_end)
        egress = _select_effective_egress(egress_start, egress_end)
        if egress_drift:
            _push_log(
                logs,
                {
                    "step": "egress_drift",
                    "ts": now_rfc3339(),
                    "egress": egress_end,
                    "previous_egress": egress_start,
                },
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
        report_path = _save_report(
            account=account,
            settings=settings,
            start=start,
            callback_url=callback_url,
            token_data=token_data,
            save_dir=save_dir,
            logs=logs,
            browser_path=resolved_browser_path,
            debug_port=resolved_debug_port,
            profile_dir=profile_dir,
            error=str(exc),
            token_path=token_path,
            include_secrets=include_secrets,
            egress=egress,
            egress_start=egress_start,
            egress_end=egress_end,
            egress_drift=egress_drift,
        )
        if callable(log_fn):
            log_fn(f"{account.email} 浏览器链翻车了 {exc}")
        elif not quiet:
            print(f"error: {exc}", flush=True)
            print(f"report: {report_path}", flush=True)
        return {
            "ok": False,
            "email": account.email,
            "message": str(exc),
            "callback_url": callback_url,
            "report_path": str(report_path),
            "token_path": token_path,
            "token_data": token_data or {},
            "token_summary": _token_summary(token_data or {}),
            "egress": egress,
            "egress_start": egress_start,
            "egress_end": egress_end,
            "egress_drift": egress_drift,
            "debug_port": resolved_debug_port,
            "browser_path": resolved_browser_path,
        }
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if callback_server is not None:
            try:
                callback_server.close()
            except Exception:
                pass
        _stop_browser(browser_process)


def run_authorize_batch_lines_browser(
    raw_text: str,
    settings: dict[str, Any],
    *,
    workers: int,
    browser_path: str = "",
    debug_port_base: int = DEFAULT_DEBUG_PORT_BASE,
    timeout: int = 300,
    save_dir: Path | str | None = None,
    save_token: bool = False,
    include_secrets: bool = False,
    quiet: bool = True,
    log_fn: Callable[[str], None] | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    resolved_save_dir = _ensure_dir(Path(save_dir).resolve() if save_dir else _default_save_dir())
    accounts, input_errors = parse_account_lines(raw_text)
    for item in input_errors:
        if callable(log_fn):
            log_fn(item)

    total = len(accounts)
    if total == 0:
        summary_path = _save_batch_summary(
            settings=settings,
            save_dir=resolved_save_dir,
            workers=workers,
            save_token=save_token,
            include_secrets=include_secrets,
            parsed_count=0,
            input_errors=input_errors,
            results=[],
        )
        return {
            "success_count": 0,
            "fail_count": 0,
            "parsed_count": 0,
            "input_error_count": len(input_errors),
            "input_errors": input_errors,
            "results": [],
            "summary_path": str(summary_path),
        }

    worker_count = max(1, min(int(workers or 1), total))
    completed = 0
    results: list[dict[str, Any]] = []
    port_counter = count(max(1024, int(debug_port_base or DEFAULT_DEBUG_PORT_BASE)))

    def _account_log(email: str):
        def _writer(message: str) -> None:
            if callable(log_fn):
                log_fn(f"{email} {message}")
        return _writer

    def _run_one(account: AuthAccount, port: int) -> dict[str, Any]:
        return authorize_account_browser(
            account,
            settings,
            browser_path=browser_path,
            debug_port=port,
            timeout=timeout,
            save_dir=resolved_save_dir,
            save_token=save_token,
            include_secrets=include_secrets,
            quiet=quiet,
            log_fn=_account_log(account.email),
        )

    if worker_count == 1:
        for account in accounts:
            result = _run_one(account, next(port_counter))
            completed += 1
            results.append(result)
            if callable(progress_cb):
                progress_cb(completed, total, account.email)
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(_run_one, account, next(port_counter)): account
                for account in accounts
            }
            for future in as_completed(future_map):
                account = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "ok": False,
                        "email": account.email,
                        "message": str(exc),
                        "callback_url": "",
                        "report_path": "",
                        "token_path": "",
                        "token_data": {},
                        "token_summary": {},
                        "egress": {},
                        "egress_start": {},
                        "egress_end": {},
                        "egress_drift": False,
                        "debug_port": 0,
                        "browser_path": browser_path,
                    }
                completed += 1
                results.append(result)
                if callable(progress_cb):
                    progress_cb(completed, total, account.email)

    summary_path = _save_batch_summary(
        settings=settings,
        save_dir=resolved_save_dir,
        workers=worker_count,
        save_token=save_token,
        include_secrets=include_secrets,
        parsed_count=total,
        input_errors=input_errors,
        results=results,
    )
    success_count = sum(1 for item in results if item.get("ok"))
    fail_count = len(results) - success_count
    if callable(log_fn):
        log_fn(f"浏览器链批量授权结束 成功 {success_count} 失败 {fail_count}")
        log_fn(f"批量汇总已保存 {summary_path}")
    return {
        "success_count": success_count,
        "fail_count": fail_count,
        "parsed_count": total,
        "input_error_count": len(input_errors),
        "input_errors": input_errors,
        "results": results,
        "summary_path": str(summary_path),
    }


def _load_settings(args: argparse.Namespace) -> dict[str, Any]:
    settings = load_app_config()
    oauth = dict(settings.get("oauth") or {})
    if args.auth_url:
        oauth["auth_url"] = args.auth_url.strip()
    if args.token_url:
        oauth["token_url"] = args.token_url.strip()
    if args.client_id:
        oauth["client_id"] = args.client_id.strip()
    if args.redirect_uri:
        oauth["redirect_uri"] = args.redirect_uri.strip()
    if args.scope:
        oauth["scope"] = args.scope.strip()
    settings["oauth"] = oauth
    if args.proxy:
        settings["http_proxy"] = args.proxy.strip()
    if args.browser_path:
        settings["browser_executable_path"] = args.browser_path.strip()
    if args.debug_port_base:
        settings["browser_auth_start_port"] = int(args.debug_port_base)
    return settings


def run_authorize(args: argparse.Namespace) -> int:
    settings = _load_settings(args)
    accounts, errors = parse_account_lines(args.line)
    if errors or not accounts:
        raise ValueError(errors[0] if errors else "账号格式不对")
    save_dir = Path(args.save_dir).resolve() if args.save_dir else _default_save_dir()
    result = authorize_account_browser(
        accounts[0],
        settings,
        browser_path=str(settings.get("browser_executable_path") or ""),
        debug_port=int(settings.get("browser_auth_start_port") or DEFAULT_DEBUG_PORT_BASE),
        timeout=int(args.timeout or 300),
        save_dir=save_dir,
        save_token=bool(args.save_token),
        include_secrets=bool(args.include_secrets),
        quiet=False,
    )
    if result.get("ok"):
        print(f"email: {result.get('email', '')}")
        print(f"callback_url: {result.get('callback_url', '')}")
        print(f"report: {result.get('report_path', '')}")
        if result.get("token_path"):
            print(f"token_path: {result.get('token_path', '')}")
        return 0
    print(f"error: {result.get('message', '')}")
    print(f"report: {result.get('report_path', '')}")
    return 1


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth-url", default="", help="覆盖 OAuth auth_url")
    parser.add_argument("--token-url", default="", help="覆盖 OAuth token_url")
    parser.add_argument("--client-id", default="", help="覆盖 OAuth client_id")
    parser.add_argument("--redirect-uri", default="", help="覆盖 OAuth redirect_uri")
    parser.add_argument("--scope", default="", help="覆盖 OAuth scope")
    parser.add_argument("--proxy", default="", help="覆盖全局代理")
    parser.add_argument("--browser-path", default="", help="浏览器 exe 路径")
    parser.add_argument("--debug-port-base", type=int, default=DEFAULT_DEBUG_PORT_BASE, help="浏览器调试起始端口")
    parser.add_argument("--save-dir", default="", help="报告输出目录，默认 outputs/auth_2fa_browser")
    parser.add_argument("--timeout", type=int, default=300, help="单账号等待秒数")
    parser.add_argument("--save-token", action="store_true", help="成功后写入 Tokens")
    parser.add_argument("--include-secrets", action="store_true", help="报告中保留密码和 2FA 明文")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="真实浏览器链 2FA 授权")
    subparsers = parser.add_subparsers(dest="command", required=True)

    auth_parser = subparsers.add_parser("authorize", help="单账号跑浏览器链")
    _add_common_options(auth_parser)
    auth_parser.add_argument("--line", required=True, help="账号行，格式 账号----密码----2FA密匙")
    auth_parser.set_defaults(func=run_authorize)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
