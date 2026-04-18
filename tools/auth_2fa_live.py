from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from curl_cffi import requests as curl_requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from token_manager.config import load_app_config
from token_manager.constants import APP_DIR
from token_manager.oauth import OAuthStart, exchange_callback, generate_oauth_start
from token_manager.store import TokenStore
from token_manager.utils import decode_jwt, now_rfc3339


AUTH_BASE_URL = "https://auth.openai.com"
AUTH_CONTINUE_URL = f"{AUTH_BASE_URL}/api/accounts/authorize/continue"
PASSWORD_VERIFY_URL = f"{AUTH_BASE_URL}/api/accounts/password/verify"
MFA_ISSUE_CHALLENGE_URL = f"{AUTH_BASE_URL}/api/accounts/mfa/issue_challenge"
MFA_VERIFY_URL = f"{AUTH_BASE_URL}/api/accounts/mfa/verify"
WORKSPACE_SELECT_URL = f"{AUTH_BASE_URL}/api/accounts/workspace/select"
ORGANIZATION_SELECT_URL = f"{AUTH_BASE_URL}/api/accounts/organization/select"
SENTINEL_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
TWOFA_LIVE_URL = "https://2fa.live/tok/"
EGRESS_GEO_URL = "https://ipwho.is/"
LINE_SPLIT_RE = re.compile(r"-{2,}")
LOGIN_VERIFIER_RE = re.compile(r"https://auth\.openai\.com/api/oauth/oauth2/auth[^\"'\s>]+", re.I)
META_REFRESH_RE = re.compile(r'content=["\']?\d+;\s*url=([^"\'>\s]+)', re.I)
_EGRESS_CACHE_LOCK = threading.Lock()
_EGRESS_CACHE: dict[str, dict[str, Any]] = {}


@dataclass(slots=True)
class AuthAccount:
    email: str
    password: str
    totp_secret: str
    raw_line: str


def _mask_value(value: str, *, prefix: int = 2, suffix: int = 2) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= prefix + suffix:
        return "*" * len(text)
    head = text[:prefix] if prefix > 0 else ""
    tail = text[-suffix:] if suffix > 0 else ""
    return f"{head}{'*' * (len(text) - prefix - suffix)}{tail}"


def _sanitize_account_payload(account: AuthAccount, *, include_secrets: bool) -> dict[str, Any]:
    payload = {
        "email": account.email,
        "totp_provider": "2fa.live",
        "input_format": "email----password----totp_secret",
        "password_length": len(account.password),
        "totp_secret_length": len(account.totp_secret),
    }
    if include_secrets:
        payload["raw_line"] = account.raw_line
    else:
        payload["line_masked"] = f"{account.email}----{'*' * len(account.password)}----{_mask_value(account.totp_secret, prefix=4, suffix=4)}"
    return payload


def _sanitize_log_entry(entry: dict[str, Any], *, include_secrets: bool) -> dict[str, Any]:
    payload = dict(entry)
    if not include_secrets and payload.get("totp_code"):
        payload["totp_code"] = _mask_value(str(payload.get("totp_code") or ""), prefix=0, suffix=0)
    return payload


def _compact_egress_payload(egress: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": str(egress.get("ip") or ""),
        "country": str(egress.get("country") or ""),
        "region": str(egress.get("region") or ""),
        "city": str(egress.get("city") or ""),
        "timezone": str(egress.get("timezone") or ""),
        "isp": str(egress.get("isp") or ""),
        "proxy": str(egress.get("proxy") or ""),
        "error": str(egress.get("error") or ""),
    }


def _timestamp_slug() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def _default_save_dir() -> Path:
    return APP_DIR / "outputs" / "auth_2fa_live"


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _snippet(value: Any, max_len: int = 500) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _safe_json(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _build_requests_proxies(proxy_url: str) -> dict[str, str] | None:
    value = str(proxy_url or "").strip()
    if not value:
        return None
    return {"http": value, "https": value}


def _new_session(proxy_url: str) -> Any:
    return curl_requests.Session(
        proxies=_build_requests_proxies(proxy_url),
        impersonate="safari",
    )


def _close_session(session: Any) -> None:
    if session is None:
        return
    try:
        session.close()
    except Exception:
        pass


def _response_entry(step: str, response: Any | None = None, **extra: Any) -> dict[str, Any]:
    payload = {"step": step, "ts": now_rfc3339()}
    if response is not None:
        payload["status"] = int(getattr(response, "status_code", 0) or 0)
        payload["url"] = str(getattr(response, "url", "") or "")
        payload["body"] = _snippet(getattr(response, "text", ""))
        parsed = _safe_json(response)
        if parsed:
            payload["json"] = parsed
        try:
            location = str(response.headers.get("Location") or "")
        except Exception:
            location = ""
        if location:
            payload["location"] = location
    payload.update(extra)
    return payload


_STEP_ORDER = {
    "dry_run_totp": "试跑",
    "egress_probe": "准备中",
    "oauth_start": "第1步",
    "sentinel_token": "第2步",
    "authorize_continue": "第3步",
    "password_verify": "第4步",
    "totp_factor": "第5步",
    "mfa_issue_challenge": "第6步",
    "mfa_verify": "第7步",
    "consent_page": "第8步",
    "workspace_select": "第9步",
    "organization_page": "第10步",
    "organization_select": "第11步",
    "follow_redirect": "收尾中",
    "consent_accept": "收尾中",
    "callback_ready": "完成啦",
}


def _friendly_message(entry: dict[str, Any]) -> str:
    step = str(entry.get("step") or "")
    label = _STEP_ORDER.get(step, step)
    if step == "dry_run_totp":
        return f"{label} 2FA 小码已经拿到了"
    if step == "egress_probe":
        egress = _compact_egress_payload(entry.get("egress") or {})
        place = " / ".join([item for item in (egress.get("country"), egress.get("region"), egress.get("city")) if item])
        if egress.get("error"):
            return f"{label} 出口地区没认出来，先继续跑"
        if place and egress.get("ip"):
            return f"{label} 这条线走到 {place} 了 {egress.get('ip')}"
        if place:
            return f"{label} 这条线走到 {place} 了"
        return f"{label} 出口已经标记好了"
    if step == "oauth_start":
        return f"{label} 登录入口已经打开啦"
    if step == "sentinel_token":
        return f"{label} 风控票据准备好了"
    if step == "authorize_continue":
        return f"{label} 邮箱已经递上去了"
    if step == "password_verify":
        return f"{label} 密码对上啦"
    if step == "totp_factor":
        return f"{label} 找到 2FA 这扇小门了"
    if step == "mfa_issue_challenge":
        return f"{label} 2FA 校验准备好了"
    if step == "mfa_verify":
        return f"{label} 2FA 通过啦"
    if step == "consent_page":
        return f"{label} 授权页已经出来了"
    if step == "workspace_select":
        return f"{label} 账号空间选好了"
    if step == "organization_page":
        return f"{label} 组织页已经到啦"
    if step == "organization_select":
        return f"{label} 组织也选好了"
    if step == "follow_redirect":
        location = str(entry.get("location") or "")
        if "consent_challenge=" in location:
            return f"{label} 正在去领授权确认"
        if "consent_verifier=" in location:
            return f"{label} 授权确认已经接上了"
        if "code=" in location and "state=" in location:
            return f"{label} 最后一跳快到了"
        return f"{label} 正在跳最后几下"
    if step == "consent_accept":
        return f"{label} 已经替你点了同意"
    if step == "callback_ready":
        return f"{label} 回调已经抓到啦"
    return f"{label} 已完成"


def _emit_log(entry: dict[str, Any], *, quiet: bool, include_secrets: bool, log_fn: Callable[[str], None] | None = None) -> None:
    entry = _sanitize_log_entry(entry, include_secrets=include_secrets)
    error = str(entry.get("error") or "")
    if error:
        step = str(entry.get("step") or "")
        label = _STEP_ORDER.get(step, step)
        message = f"[{label}] 小翻车了 {error}"
        if callable(log_fn):
            log_fn(message)
        if not quiet:
            print(message, flush=True)
        return
    message = _friendly_message(entry)
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


def _require_ok(response: Any, message: str) -> None:
    if int(response.status_code) == 200:
        return
    raise RuntimeError(f"{message}: HTTP {response.status_code} {_snippet(response.text)}")


def _is_cloudflare_page(text: str) -> bool:
    lowered = str(text or "").lower()
    return "just a moment" in lowered and "_cf_chl_opt" in lowered


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
    if args.proxy is not None:
        settings["http_proxy"] = args.proxy.strip()
    if args.tokens_dir:
        settings["tokens_dir"] = args.tokens_dir.strip()
    if args.outputs_dir:
        settings["outputs_dir"] = args.outputs_dir.strip()
    return settings


def _parse_account_line(raw: str) -> AuthAccount:
    parts = [part.strip() for part in LINE_SPLIT_RE.split(str(raw or "").strip()) if part.strip()]
    if len(parts) != 3:
        raise ValueError("账号格式不对，要求 账号----密码----2FA密匙")
    email, password, totp_secret = parts
    if "@" not in email:
        raise ValueError("邮箱格式不对")
    if not password:
        raise ValueError("密码为空")
    if not totp_secret:
        raise ValueError("2FA 密匙为空")
    return AuthAccount(email=email, password=password, totp_secret=totp_secret, raw_line=str(raw or "").strip())


def parse_account_lines(raw_text: str) -> tuple[list[AuthAccount], list[str]]:
    accounts: list[AuthAccount] = []
    errors: list[str] = []
    for idx, raw in enumerate(str(raw_text or "").splitlines(), start=1):
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        try:
            account = _parse_account_line(line)
        except Exception as exc:
            errors.append(f"第 {idx} 行 {exc}")
            continue
        accounts.append(account)
    return accounts, errors


def _start_to_dict(start: OAuthStart) -> dict[str, Any]:
    return {
        "auth_url": start.auth_url,
        "state": start.state,
        "code_verifier": start.code_verifier,
        "redirect_uri": start.redirect_uri,
    }


def _token_summary(token_data: dict[str, Any]) -> dict[str, Any]:
    access_claims = decode_jwt(str(token_data.get("access_token") or ""))
    id_claims = decode_jwt(str(token_data.get("id_token") or ""))
    access_auth = access_claims.get("https://api.openai.com/auth") or {}
    id_auth = id_claims.get("https://api.openai.com/auth") or {}
    return {
        "email": str(token_data.get("email") or id_claims.get("email") or ""),
        "account_id": str(
            token_data.get("account_id")
            or access_auth.get("chatgpt_account_id")
            or id_auth.get("chatgpt_account_id")
            or ""
        ),
        "access_exp": access_claims.get("exp"),
        "id_exp": id_claims.get("exp"),
        "plan": str(access_auth.get("chatgpt_plan_type") or id_auth.get("chatgpt_plan_type") or ""),
    }


def _save_report(
    *,
    account: AuthAccount,
    settings: dict[str, Any],
    start: OAuthStart,
    callback_url: str,
    token_data: dict[str, Any] | None,
    save_dir: Path,
    logs: list[dict[str, Any]],
    error: str = "",
    token_path: str = "",
    include_secrets: bool = False,
    egress: dict[str, Any] | None = None,
) -> Path:
    prefix = "auth_2fa_live_fail" if error else "auth_2fa_live"
    report_path = save_dir / f"{prefix}_{_timestamp_slug()}.json"
    payload = {
        "created_at": now_rfc3339(),
        "proxy": str(settings.get("http_proxy") or ""),
        "oauth": dict(settings.get("oauth") or {}),
        "start": _start_to_dict(start),
        "account": _sanitize_account_payload(account, include_secrets=include_secrets),
        "egress": _compact_egress_payload(egress or {}),
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
    summary_path = save_dir / f"auth_2fa_live_batch_{_timestamp_slug()}.json"
    compact_results = []
    for item in results:
        token_summary = dict(item.get("token_summary") or {})
        egress = _compact_egress_payload(item.get("egress") or {})
        compact_results.append(
            {
                "ok": bool(item.get("ok")),
                "email": str(item.get("email") or ""),
                "message": str(item.get("message") or ""),
                "report_path": str(item.get("report_path") or ""),
                "token_path": str(item.get("token_path") or ""),
                "account_id": str(token_summary.get("account_id") or ""),
                "plan": str(token_summary.get("plan") or ""),
                "egress": egress,
            }
        )
    payload = {
        "created_at": now_rfc3339(),
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


def _resolve_proxy_egress(proxy_url: str) -> dict[str, Any]:
    cache_key = str(proxy_url or "").strip() or "__direct__"
    with _EGRESS_CACHE_LOCK:
        cached = _EGRESS_CACHE.get(cache_key)
        if cached is not None:
            return dict(cached)

    result: dict[str, Any]
    try:
        response = curl_requests.get(
            EGRESS_GEO_URL,
            params={"fields": "success,ip,country,region,city,timezone.id,connection.isp"},
            proxies=_build_requests_proxies(proxy_url),
            timeout=20,
            impersonate="safari",
        )
        data = _safe_json(response)
        ok = bool(data.get("success")) if data else response.status_code == 200
        if ok:
            timezone_data = data.get("timezone") or {}
            connection_data = data.get("connection") or {}
            result = {
                "ip": str(data.get("ip") or "").strip(),
                "country": str(data.get("country") or "").strip(),
                "region": str(data.get("region") or "").strip(),
                "city": str(data.get("city") or "").strip(),
                "timezone": str((timezone_data.get("id") if isinstance(timezone_data, dict) else "") or "").strip(),
                "isp": str((connection_data.get("isp") if isinstance(connection_data, dict) else "") or "").strip(),
                "proxy": cache_key if cache_key != "__direct__" else "",
                "error": "",
            }
        else:
            result = {
                "ip": "",
                "country": "",
                "region": "",
                "city": "",
                "timezone": "",
                "isp": "",
                "proxy": cache_key if cache_key != "__direct__" else "",
                "error": _snippet(data.get("message") if isinstance(data, dict) else response.text),
            }
    except Exception as exc:
        result = {
            "ip": "",
            "country": "",
            "region": "",
            "city": "",
            "timezone": "",
            "isp": "",
            "proxy": cache_key if cache_key != "__direct__" else "",
            "error": str(exc),
        }

    with _EGRESS_CACHE_LOCK:
        _EGRESS_CACHE[cache_key] = dict(result)
    return result


def _fetch_live_totp_code(secret: str, proxy_url: str) -> str:
    encoded = urllib.parse.quote(str(secret or "").strip(), safe="")
    response = curl_requests.get(
        f"{TWOFA_LIVE_URL}{encoded}",
        proxies=_build_requests_proxies(proxy_url),
        timeout=20,
        impersonate="safari",
    )
    data = _safe_json(response)
    code = str(data.get("token") or data.get("otp") or "").strip()
    if response.status_code == 200 and re.fullmatch(r"\d{6}", code):
        return code
    raise RuntimeError(f"2fa.live 返回异常: HTTP {response.status_code} {_snippet(data or response.text)}")


def _fetch_sentinel_token(session: Any, did: str) -> str:
    payload = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'
    response = session.post(
        SENTINEL_URL,
        headers={
            "origin": "https://sentinel.openai.com",
            "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
            "content-type": "text/plain;charset=UTF-8",
        },
        data=payload,
        timeout=20,
        verify=True,
    )
    data = _safe_json(response)
    token = str(data.get("token") or "").strip()
    if token:
        return token
    raise RuntimeError(f"sentinel 取 token 失败: HTTP {response.status_code} {_snippet(data or response.text)}")


def _build_sentinel_header(did: str, token: str) -> str:
    return f'{{"p": "", "t": "", "c": "{token}", "id": "{did}", "flow": "authorize_continue"}}'


def _make_json_headers(*, referer: str, accept_json: bool = True, sentinel: str = "") -> dict[str, str]:
    headers = {
        "origin": AUTH_BASE_URL,
        "referer": referer,
        "content-type": "application/json",
    }
    if accept_json:
        headers["accept"] = "application/json"
    if sentinel:
        headers["openai-sentinel-token"] = sentinel
    return headers


def _parse_auth_cookie(auth_cookie: str) -> dict[str, Any]:
    raw = urllib.parse.unquote(str(auth_cookie or "").strip())
    for part in raw.split("."):
        part = part.strip()
        if not part:
            continue
        padding = "=" * ((4 - len(part) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode((part + padding).encode("ascii")).decode("utf-8")
            data = json.loads(decoded)
        except Exception:
            continue
        if isinstance(data, dict) and data.get("workspaces"):
            return data
    return {}


def _extract_totp_factor(payload: dict[str, Any]) -> tuple[str, str]:
    page = payload.get("page") or {}
    page_payload = page.get("payload") or {}
    factors = page_payload.get("factors") or []
    for item in factors:
        if not isinstance(item, dict):
            continue
        if str(item.get("factor_type") or "").strip().lower() == "totp":
            factor_id = str(item.get("id") or page_payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id, str(item.get("factor_type") or "totp").strip().lower()
    raise RuntimeError(f"没有找到 totp 因子: {_snippet(payload)}")


def _extract_next_url_from_html(current_url: str, html: str) -> str:
    match = META_REFRESH_RE.search(html or "")
    if match:
        return urllib.parse.urljoin(current_url, match.group(1))
    match = LOGIN_VERIFIER_RE.search(html or "")
    if match:
        return urllib.parse.unquote(match.group(0))
    return ""


def _follow_callback_chain(
    session: Any,
    current_url: str,
    logs: list[dict[str, Any]],
    *,
    quiet: bool,
    include_secrets: bool,
    log_fn: Callable[[str], None] | None = None,
) -> str:
    url = current_url
    for _ in range(20):
        response = session.get(url, allow_redirects=False, timeout=20, verify=True)
        _push_log(logs, _response_entry("follow_redirect", response), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)

        next_url = ""
        if response.status_code in {301, 302, 303, 307, 308}:
            next_url = urllib.parse.urljoin(url, str(response.headers.get("Location") or ""))
        elif response.status_code == 200:
            if "consent_challenge=" in url:
                consent = session.post(
                    url,
                    data={"action": "accept"},
                    allow_redirects=False,
                    timeout=20,
                    verify=True,
                )
                _push_log(logs, _response_entry("consent_accept", consent), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
                next_url = urllib.parse.urljoin(url, str(consent.headers.get("Location") or ""))
            else:
                next_url = _extract_next_url_from_html(url, response.text)

        if not next_url:
            break
        if "code=" in next_url and "state=" in next_url:
            return next_url
        url = next_url
    raise RuntimeError("没有拿到 callback_url")


def _select_workspace(auth_cookie: str) -> str:
    auth_data = _parse_auth_cookie(auth_cookie)
    workspaces = auth_data.get("workspaces") or []
    if not workspaces:
        raise RuntimeError("auth cookie 里没有 workspace")
    workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
    if not workspace_id:
        raise RuntimeError("workspace_id 为空")
    return workspace_id


def authorize_account(
    account: AuthAccount,
    settings: dict[str, Any],
    *,
    save_dir: Path | None = None,
    save_token: bool = False,
    include_secrets: bool = False,
    quiet: bool = False,
    log_fn: Callable[[str], None] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    save_dir = _ensure_dir(save_dir or _default_save_dir())
    proxy_url = str(settings.get("http_proxy") or "")
    logs: list[dict[str, Any]] = []
    start = generate_oauth_start(settings)
    egress = _resolve_proxy_egress(proxy_url)
    callback_url = ""
    token_data: dict[str, Any] | None = None
    token_path = ""
    session = None

    try:
        _push_log(
            logs,
            {"step": "egress_probe", "ts": now_rfc3339(), "egress": egress},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        if dry_run:
            totp_code = _fetch_live_totp_code(account.totp_secret, proxy_url)
            _push_log(
                logs,
                {"step": "dry_run_totp", "ts": now_rfc3339(), "totp_code": totp_code},
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
            report_path = _save_report(
                account=account,
                settings=settings,
                start=start,
                callback_url="",
                token_data=None,
                save_dir=save_dir,
                logs=logs,
                include_secrets=include_secrets,
                egress=egress,
            )
            return {
                "ok": True,
                "email": account.email,
                "message": "dry_run",
                "callback_url": "",
                "report_path": str(report_path),
                "token_path": "",
                "token_data": {},
                "token_summary": {},
                "egress": egress,
                "totp_code": totp_code if include_secrets else _mask_value(totp_code, prefix=0, suffix=0),
            }

        session = _new_session(proxy_url)
        oauth_start_response = session.get(start.auth_url, timeout=20, verify=True)
        _push_log(
            logs,
            _response_entry("oauth_start", oauth_start_response, auth_url=start.auth_url),
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        if _is_cloudflare_page(oauth_start_response.text):
            raise RuntimeError("启动后被 Cloudflare 拦截了")

        did = str(session.cookies.get("oai-did") or "").strip()
        if not did:
            raise RuntimeError("缺少 oai-did")

        sentinel_token = _fetch_sentinel_token(session, did)
        sentinel = _build_sentinel_header(did, sentinel_token)
        _push_log(
            logs,
            {"step": "sentinel_token", "ts": now_rfc3339(), "did": did, "token_len": len(sentinel_token)},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        login_response = session.post(
            AUTH_CONTINUE_URL,
            headers=_make_json_headers(
                referer=f"{AUTH_BASE_URL}/log-in",
                sentinel=sentinel,
            ),
            json={"username": {"kind": "email", "value": account.email}},
            timeout=20,
            verify=True,
        )
        _push_log(logs, _response_entry("authorize_continue", login_response), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_ok(login_response, "邮箱提交失败")

        password_response = session.post(
            PASSWORD_VERIFY_URL,
            headers=_make_json_headers(
                referer=f"{AUTH_BASE_URL}/log-in/password",
                sentinel=sentinel,
            ),
            json={"password": account.password},
            timeout=20,
            verify=True,
        )
        _push_log(logs, _response_entry("password_verify", password_response), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)
        _require_ok(password_response, "密码校验失败")

        password_payload = _safe_json(password_response)
        factor_id, factor_type = _extract_totp_factor(password_payload)
        mfa_page_url = urllib.parse.urljoin(
            AUTH_BASE_URL,
            str(password_payload.get("continue_url") or f"/mfa-challenge/{factor_id}"),
        )
        _push_log(
            logs,
            {"step": "totp_factor", "ts": now_rfc3339(), "factor_id": factor_id, "factor_type": factor_type},
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )

        issue_response = session.post(
            MFA_ISSUE_CHALLENGE_URL,
            headers=_make_json_headers(
                referer=f"{AUTH_BASE_URL}/log-in/password",
                accept_json=False,
            ),
            json={"id": factor_id, "type": "totp", "force_fresh_challenge": False},
            timeout=20,
            verify=True,
        )
        _push_log(
            logs,
            _response_entry("mfa_issue_challenge", issue_response, factor_id=factor_id),
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        _require_ok(issue_response, "2FA challenge 初始化失败")

        verify_payload: dict[str, Any] = {}
        verify_error = ""
        for attempt in range(1, 4):
            totp_code = _fetch_live_totp_code(account.totp_secret, proxy_url)
            verify_response = session.post(
                MFA_VERIFY_URL,
                headers=_make_json_headers(
                    referer=mfa_page_url,
                ),
                json={"id": factor_id, "type": "totp", "code": totp_code},
                timeout=20,
                verify=True,
            )
            _push_log(
                logs,
                _response_entry("mfa_verify", verify_response, factor_id=factor_id, attempt=attempt, totp_code=totp_code),
                quiet=quiet,
                include_secrets=include_secrets,
                log_fn=log_fn,
            )
            if verify_response.status_code == 200:
                verify_payload = _safe_json(verify_response)
                verify_error = ""
                break
            verify_error = f"2FA 验证失败: HTTP {verify_response.status_code} {_snippet(verify_response.text)}"
            if attempt < 3:
                time.sleep(31)
        if verify_error:
            raise RuntimeError(verify_error)

        consent_url = urllib.parse.urljoin(
            AUTH_BASE_URL,
            str(verify_payload.get("continue_url") or "/sign-in-with-chatgpt/codex/consent"),
        )
        consent_page = session.get(consent_url, allow_redirects=False, timeout=20, verify=True)
        _push_log(logs, _response_entry("consent_page", consent_page), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)

        auth_cookie = str(session.cookies.get("oai-client-auth-session") or "").strip()
        if not auth_cookie:
            raise RuntimeError("没有拿到 oai-client-auth-session")
        workspace_id = _select_workspace(auth_cookie)

        workspace_response = session.post(
            WORKSPACE_SELECT_URL,
            headers=_make_json_headers(
                referer=consent_url,
            ),
            json={"workspace_id": workspace_id},
            timeout=20,
            verify=True,
        )
        _push_log(
            logs,
            _response_entry("workspace_select", workspace_response, workspace_id=workspace_id),
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        _require_ok(workspace_response, "workspace 选择失败")

        workspace_data = _safe_json(workspace_response)
        org_page_url = urllib.parse.urljoin(
            AUTH_BASE_URL,
            str(workspace_data.get("continue_url") or "/sign-in-with-chatgpt/codex/organization"),
        )
        org_page = session.get(org_page_url, allow_redirects=False, timeout=20, verify=True)
        _push_log(logs, _response_entry("organization_page", org_page), quiet=quiet, include_secrets=include_secrets, log_fn=log_fn)

        orgs = ((workspace_data.get("data") or {}).get("orgs") or []) if isinstance(workspace_data, dict) else []
        if not orgs:
            raise RuntimeError("workspace 返回里没有 orgs")
        org = orgs[0] or {}
        org_id = str(org.get("id") or "").strip()
        if not org_id:
            raise RuntimeError("org_id 为空")
        body: dict[str, str] = {"org_id": org_id}
        projects = org.get("projects") or []
        if projects:
            project_id = str((projects[0] or {}).get("id") or "").strip()
            if project_id:
                body["project_id"] = project_id

        organization_response = session.post(
            ORGANIZATION_SELECT_URL,
            headers=_make_json_headers(
                referer=org_page_url,
            ),
            json=body,
            timeout=20,
            verify=True,
        )
        _push_log(
            logs,
            _response_entry("organization_select", organization_response, org_id=org_id, project_id=body.get("project_id", "")),
            quiet=quiet,
            include_secrets=include_secrets,
            log_fn=log_fn,
        )
        _require_ok(organization_response, "组织选择失败")

        organization_data = _safe_json(organization_response)
        next_url = str(
            organization_data.get("continue_url")
            or ((organization_data.get("page") or {}).get("payload") or {}).get("url")
            or org_page_url
        ).strip()
        callback_url = _follow_callback_chain(
            session,
            urllib.parse.urljoin(AUTH_BASE_URL, next_url),
            logs,
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
        token_data = exchange_callback(
            callback_url,
            start,
            settings,
            proxy_url=proxy_url,
        )
        _close_session(session)

        if save_token:
            store = TokenStore(settings)
            token_path = str(store.save_token_response(token_data, metadata={"auth_mode": "2fa_live"}))

        report_path = _save_report(
            account=account,
            settings=settings,
            start=start,
            callback_url=callback_url,
            token_data=token_data,
            save_dir=save_dir,
            logs=logs,
            token_path=token_path,
            include_secrets=include_secrets,
            egress=egress,
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
            "totp_code": "",
        }
    except Exception as exc:
        _close_session(session)
        report_path = _save_report(
            account=account,
            settings=settings,
            start=start,
            callback_url=callback_url,
            token_data=token_data,
            save_dir=save_dir,
            logs=logs,
            error=str(exc),
            token_path=token_path,
            include_secrets=include_secrets,
            egress=egress,
        )
        if callable(log_fn):
            log_fn(f"{account.email} 小翻车了 {exc}")
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
            "totp_code": "",
        }


def run_authorize_batch_lines(
    raw_text: str,
    settings: dict[str, Any],
    *,
    workers: int,
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

    def _account_log(email: str):
        def _writer(message: str) -> None:
            if callable(log_fn):
                log_fn(f"{email} {message}")
        return _writer

    if worker_count == 1:
        for account in accounts:
            result = authorize_account(
                account,
                settings,
                save_dir=resolved_save_dir,
                save_token=save_token,
                include_secrets=include_secrets,
                quiet=quiet,
                log_fn=_account_log(account.email),
            )
            completed += 1
            results.append(result)
            if callable(progress_cb):
                progress_cb(completed, total, account.email)
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(
                    authorize_account,
                    account,
                    settings,
                    save_dir=resolved_save_dir,
                    save_token=save_token,
                    include_secrets=include_secrets,
                    quiet=quiet,
                    log_fn=_account_log(account.email),
                ): account
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
                        "totp_code": "",
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
        log_fn(f"2FA 批量授权结束 成功 {success_count} 失败 {fail_count}")
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


def run_authorize(args: argparse.Namespace) -> int:
    account = _parse_account_line(args.line)
    settings = _load_settings(args)
    save_dir = Path(args.save_dir).resolve() if args.save_dir else _default_save_dir()
    result = authorize_account(
        account,
        settings,
        save_dir=save_dir,
        save_token=bool(args.save_token),
        include_secrets=bool(args.unsafe_include_secrets),
        quiet=bool(args.quiet),
        dry_run=bool(args.dry_run),
    )
    if result.get("ok"):
        print(f"email: {result.get('email', '')}")
        if result.get("totp_code"):
            print(f"totp_code: {result.get('totp_code', '')}")
        token_summary = result.get("token_summary") or {}
        if token_summary.get("account_id"):
            print(f"account_id: {token_summary.get('account_id', '')}")
        if result.get("callback_url"):
            print(f"callback_url: {result.get('callback_url', '')}")
        if result.get("token_path"):
            print(f"token_path: {result.get('token_path', '')}")
        print(f"report: {result.get('report_path', '')}")
        return 0
    print(f"error: {result.get('message', '')}")
    print(f"report: {result.get('report_path', '')}")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="2FA.live 单账号协议授权测试脚本")
    parser.add_argument("--line", required=True, help="账号行，格式 账号----密码----2FA密匙")
    parser.add_argument("--proxy", default="", help="单代理，传空字符串表示不用代理")
    parser.add_argument("--save-dir", default="", help="报告输出目录，默认 outputs/auth_2fa_live")
    parser.add_argument("--tokens-dir", default="", help="覆盖 tokens_dir")
    parser.add_argument("--outputs-dir", default="", help="覆盖 outputs_dir")
    parser.add_argument("--auth-url", default="", help="覆盖 auth_url")
    parser.add_argument("--token-url", default="", help="覆盖 token_url")
    parser.add_argument("--client-id", default="", help="覆盖 client_id")
    parser.add_argument("--redirect-uri", default="", help="覆盖 redirect_uri")
    parser.add_argument("--scope", default="", help="覆盖 scope")
    parser.add_argument("--save-token", action="store_true", help="成功后也写入 tokens 目录")
    parser.add_argument("--dry-run", action="store_true", help="只测试解析、OAuth 起点和 2fa.live")
    parser.add_argument("--quiet", action="store_true", help="关闭实时日志输出")
    parser.add_argument("--unsafe-include-secrets", action="store_true", help="在日志和报告里保留敏感明文")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_authorize(args)


if __name__ == "__main__":
    raise SystemExit(main())
