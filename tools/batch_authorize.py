from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from curl_cffi import requests as curl_requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from token_manager.config import load_app_config
from token_manager.constants import APP_DIR
from token_manager.oauth import exchange_callback, generate_oauth_start
from token_manager.store import TokenStore


AUTH_BASE_URL = "https://auth.openai.com"
AUTH_CONTINUE_URL = f"{AUTH_BASE_URL}/api/accounts/authorize/continue"
PASSWORD_VERIFY_URL = f"{AUTH_BASE_URL}/api/accounts/password/verify"
EMAIL_OTP_VALIDATE_URL = f"{AUTH_BASE_URL}/api/accounts/email-otp/validate"
WORKSPACE_SELECT_URL = f"{AUTH_BASE_URL}/api/accounts/workspace/select"
ORGANIZATION_SELECT_URL = f"{AUTH_BASE_URL}/api/accounts/organization/select"
SENTINEL_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
LINE_SPLIT_RE = re.compile(r"-{2,}")
OTP_CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
OPENAI_MAIL_FROM_RE = re.compile(r"openai\.com", re.I)


PRINT_LOCK = threading.Lock()


@dataclass(slots=True)
class AuthAccount:
    email: str
    password: str
    raw_line: str
    mailbox_mode: str = ""
    mailbox_client_id: str = ""
    mailbox_refresh_token: str = ""
    mailapi_url: str = ""
    totp_secret: str = ""


@dataclass(slots=True)
class WorkerResult:
    ok: bool
    email: str
    proxy: str
    message: str
    token_path: str = ""
    report_path: str = ""
    callback_url: str = ""
    logs: list[dict[str, Any]] = field(default_factory=list)


class ProxyRotator:
    def __init__(self, proxies: list[str]) -> None:
        self._proxies = [item.strip() for item in proxies if item.strip()]
        self._index = 0
        self._lock = threading.Lock()

    def next(self) -> str:
        if not self._proxies:
            return ""
        with self._lock:
            value = self._proxies[self._index % len(self._proxies)]
            self._index += 1
            return value


def log_line(text: str) -> None:
    with PRINT_LOCK:
        print(text, flush=True)


def build_requests_proxies(proxy_url: str) -> dict[str, str] | None:
    value = str(proxy_url or "").strip()
    if not value:
        return None
    return {"http": value, "https": value}


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def safe_json(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def snippet(value: Any, max_len: int = 260) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def report_dir() -> Path:
    path = APP_DIR / "outputs" / "AuthBatch"
    path.mkdir(parents=True, exist_ok=True)
    return path


def split_line(raw: str) -> list[str]:
    line = str(raw or "").strip()
    if not line or line.startswith("#"):
        return []
    return [part.strip() for part in LINE_SPLIT_RE.split(line) if part.strip()]


def looks_like_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def parse_account_line(raw: str) -> AuthAccount | None:
    parts = split_line(raw)
    if not parts:
        return None

    if len(parts) == 2:
        email, second = parts
        if looks_like_url(second):
            return AuthAccount(email=email, password="", raw_line=raw.strip(), mailbox_mode="mailapi", mailapi_url=second)
        return None

    if len(parts) == 3:
        email, password, third = parts
        if looks_like_url(third):
            return AuthAccount(email=email, password=password, raw_line=raw.strip(), mailbox_mode="mailapi", mailapi_url=third)
        return AuthAccount(email=email, password=password, raw_line=raw.strip(), totp_secret=third)

    if len(parts) == 4:
        email, password, third, fourth = parts
        if looks_like_url(third):
            return AuthAccount(email=email, password=password, raw_line=raw.strip(), mailbox_mode="mailapi", mailapi_url=third, totp_secret=fourth)
        return AuthAccount(
            email=email,
            password=password,
            raw_line=raw.strip(),
            mailbox_mode="outlook_oauth",
            mailbox_client_id=third,
            mailbox_refresh_token=fourth,
        )

    email, password, third, fourth, fifth = parts[:5]
    if looks_like_url(third):
        return AuthAccount(email=email, password=password, raw_line=raw.strip(), mailbox_mode="mailapi", mailapi_url=third, totp_secret=fifth)
    return AuthAccount(
        email=email,
        password=password,
        raw_line=raw.strip(),
        mailbox_mode="outlook_oauth",
        mailbox_client_id=third,
        mailbox_refresh_token=fourth,
        totp_secret=fifth,
    )


def load_accounts(path: Path) -> tuple[list[AuthAccount], list[str]]:
    accounts: list[AuthAccount] = []
    errors: list[str] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        account = parse_account_line(raw)
        if account is None:
            if raw.strip() and not raw.strip().startswith("#"):
                errors.append(f"第 {idx} 行格式不支持: {raw.strip()}")
            continue
        if not account.email or "@" not in account.email:
            errors.append(f"第 {idx} 行邮箱无效: {raw.strip()}")
            continue
        if not account.password:
            errors.append(f"第 {idx} 行缺少登录密码，当前脚本不能只靠邮箱直接登录: {raw.strip()}")
            continue
        if not account.totp_secret and not account.mailbox_mode:
            errors.append(f"第 {idx} 行缺少邮箱验证码来源或 2FA 密钥: {raw.strip()}")
            continue
        accounts.append(account)
    return accounts, errors


def load_proxies(proxy_file: str, single_proxy: str) -> list[str]:
    results: list[str] = []
    if single_proxy.strip():
        results.append(single_proxy.strip())
    file_path = Path(proxy_file)
    if proxy_file.strip() and file_path.exists():
        for raw in file_path.read_text(encoding="utf-8-sig").splitlines():
            value = raw.strip()
            if value and not value.startswith("#"):
                results.append(value)
    return results


def decode_b32_secret(secret: str) -> bytes:
    cleaned = re.sub(r"\s+", "", str(secret or "").strip().upper())
    cleaned = cleaned.replace("-", "")
    if not cleaned:
        raise ValueError("empty totp secret")
    cleaned += "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned, casefold=True)


def generate_totp_code(secret: str, *, step: int = 30, digits: int = 6, offset_seconds: int = 0) -> str:
    key = decode_b32_secret(secret)
    counter = int((time.time() + offset_seconds) // step)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    binary = int.from_bytes(digest[pos : pos + 4], "big") & 0x7FFFFFFF
    code = binary % (10**digits)
    return str(code).zfill(digits)


def refresh_outlook_graph_token(client_id: str, refresh_token: str, proxy_url: str) -> str:
    response = curl_requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "https://graph.microsoft.com/.default",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies=build_requests_proxies(proxy_url),
        timeout=30,
        impersonate="safari",
    )
    payload = safe_json(response)
    token = str(payload.get("access_token") or "").strip()
    if token:
        return token
    raise RuntimeError(snippet(payload or response.text or "graph token failed"))


def fetch_outlook_openai_messages(access_token: str, proxy_url: str, top: int = 20) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    params = {
        "$select": "id,subject,body,from,receivedDateTime",
        "$orderby": "receivedDateTime desc",
        "$top": str(top),
    }
    messages: list[dict[str, Any]] = []
    for folder in ("inbox", "junkemail"):
        response = curl_requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages",
            headers=headers,
            params=params,
            proxies=build_requests_proxies(proxy_url),
            timeout=30,
            impersonate="safari",
        )
        data = safe_json(response)
        values = data.get("value") or []
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    sender = str(((item.get("from") or {}).get("emailAddress") or {}).get("address") or "")
                    if OPENAI_MAIL_FROM_RE.search(sender):
                        messages.append(item)
    return messages


def extract_otp_code(text: str) -> str:
    raw = str(text or "")
    match = OTP_CODE_RE.search(raw)
    return match.group(1) if match else ""


def get_known_outlook_ids(account: AuthAccount, proxy_url: str) -> set[str]:
    token = refresh_outlook_graph_token(account.mailbox_client_id, account.mailbox_refresh_token, proxy_url)
    messages = fetch_outlook_openai_messages(token, proxy_url)
    return {str(item.get("id") or "").strip() for item in messages if str(item.get("id") or "").strip()}


def wait_outlook_otp(account: AuthAccount, proxy_url: str, known_ids: set[str], timeout: int) -> str:
    token = refresh_outlook_graph_token(account.mailbox_client_id, account.mailbox_refresh_token, proxy_url)
    start = time.time()
    while time.time() - start < timeout:
        messages = fetch_outlook_openai_messages(token, proxy_url)
        for item in messages:
            msg_id = str(item.get("id") or "").strip()
            if not msg_id or msg_id in known_ids:
                continue
            subject = str(item.get("subject") or "")
            body = str(((item.get("body") or {}).get("content") or ""))
            code = extract_otp_code(subject + "\n" + body)
            if code:
                return code
        time.sleep(3)
    raise TimeoutError("email otp timeout")


def get_known_mailapi_codes(account: AuthAccount, proxy_url: str) -> set[str]:
    response = curl_requests.get(
        account.mailapi_url,
        proxies=build_requests_proxies(proxy_url),
        timeout=20,
        impersonate="safari",
    )
    code = extract_otp_code(response.text)
    return {code} if code else set()


def wait_mailapi_otp(account: AuthAccount, proxy_url: str, known_codes: set[str], timeout: int) -> str:
    start = time.time()
    while time.time() - start < timeout:
        response = curl_requests.get(
            account.mailapi_url,
            proxies=build_requests_proxies(proxy_url),
            timeout=20,
            impersonate="safari",
        )
        code = extract_otp_code(response.text)
        if code and code not in known_codes:
            return code
        time.sleep(3)
    raise TimeoutError("mailapi otp timeout")


def new_session(proxy_url: str) -> Any:
    return curl_requests.Session(
        proxies=build_requests_proxies(proxy_url),
        impersonate="safari",
    )


def is_cloudflare_page(text: str) -> bool:
    lowered = str(text or "").lower()
    return "just a moment" in lowered and "_cf_chl_opt" in lowered


def response_entry(step: str, response: Any | None = None, **extra: Any) -> dict[str, Any]:
    payload = {"step": step, "ts": now_rfc3339()}
    if response is not None:
        payload["status"] = int(getattr(response, "status_code", 0) or 0)
        payload["url"] = str(getattr(response, "url", "") or "")
        payload["body"] = snippet(getattr(response, "text", ""))
        try:
            payload["json"] = safe_json(response)
        except Exception:
            pass
        location = ""
        try:
            location = str(response.headers.get("Location") or "")
        except Exception:
            pass
        if location:
            payload["location"] = location
    payload.update(extra)
    return payload


def parse_auth_cookie(auth_cookie: str) -> dict[str, Any]:
    raw = urllib.parse.unquote(str(auth_cookie or "").strip())
    for part in raw.split("."):
        part = part.strip()
        if not part:
            continue
        padding = "=" * ((4 - len(part) % 4) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode((part + padding).encode("ascii")).decode("utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("workspaces"):
            return data
    return {}


def fetch_sentinel_token(did: str, proxy_url: str) -> str:
    payload = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'
    response = curl_requests.post(
        SENTINEL_URL,
        headers={
            "origin": "https://sentinel.openai.com",
            "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
            "content-type": "text/plain;charset=UTF-8",
        },
        data=payload,
        proxies=build_requests_proxies(proxy_url),
        timeout=20,
        impersonate="safari",
    )
    data = safe_json(response)
    token = str(data.get("token") or "").strip()
    if token:
        return token
    raise RuntimeError(f"sentinel failed: {snippet(response.text)}")


def build_sentinel_header(did: str, token: str) -> str:
    return f'{{"p": "", "t": "", "c": "{token}", "id": "{did}", "flow": "authorize_continue"}}'


def require_ok(response: Any, message: str) -> None:
    if int(response.status_code) == 200:
        return
    raise RuntimeError(f"{message}: HTTP {response.status_code} {snippet(response.text)}")


def is_email_otp_payload(data: dict[str, Any]) -> bool:
    text = json.dumps(data, ensure_ascii=False).lower()
    return "email-otp" in text or "email-verification" in text or "\"otp\"" in text or "verification" in str((data.get("page") or {}).get("type") or "").lower()


def is_totp_payload(data: dict[str, Any]) -> bool:
    text = json.dumps(data, ensure_ascii=False).lower()
    markers = ("totp", "authenticator", "mfa", "2fa", "two-factor")
    return any(marker in text for marker in markers)


def candidate_totp_urls(payload: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    continue_url = str(payload.get("continue_url") or "").strip()
    if continue_url:
        urls.append(urllib.parse.urljoin(AUTH_BASE_URL, continue_url))
    urls.extend(
        [
            f"{AUTH_BASE_URL}/api/accounts/mfa/verify",
            f"{AUTH_BASE_URL}/api/accounts/totp/verify",
            f"{AUTH_BASE_URL}/api/accounts/authenticator/verify",
            f"{AUTH_BASE_URL}/api/accounts/two-factor/verify",
            f"{AUTH_BASE_URL}/api/accounts/otp/validate",
        ]
    )
    unique: list[str] = []
    seen: set[str] = set()
    for item in urls:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def try_totp_validation(session: Any, payload: dict[str, Any], code: str, sentinel: str, proxy_url: str, logs: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_payloads = [
        {"code": code},
        {"otp": code},
        {"verification_code": code},
    ]
    last_error = "totp verify failed"
    for url in candidate_totp_urls(payload):
        for body in candidate_payloads:
            response = session.post(
                url,
                headers={
                    "content-type": "application/json",
                    "accept": "application/json",
                    "openai-sentinel-token": sentinel,
                },
                json=body,
                timeout=20,
                verify=True,
            )
            data = safe_json(response)
            logs.append(response_entry("totp_probe", response, candidate_body=body))
            if response.status_code == 200:
                if not is_totp_payload(data):
                    return data
                if session.cookies.get("oai-client-auth-session"):
                    return data
            if response.status_code in {400, 401, 403, 429}:
                last_error = f"{url} {body} -> {response.status_code} {snippet(data or response.text)}"
                return _raise_or_empty(last_error)
            last_error = f"{url} {body} -> {response.status_code} {snippet(data or response.text)}"
    raise RuntimeError(last_error)


def _raise_or_empty(msg: str):
    raise RuntimeError(msg)


def maybe_handle_email_otp(session: Any, account: AuthAccount, payload: dict[str, Any], sentinel: str, proxy_url: str, timeout: int, logs: list[dict[str, Any]]) -> dict[str, Any]:
    if not is_email_otp_payload(payload):
        return payload
    if account.mailbox_mode == "outlook_oauth":
        known_ids = get_known_outlook_ids(account, proxy_url)
        code = wait_outlook_otp(account, proxy_url, known_ids, timeout)
    elif account.mailbox_mode == "mailapi":
        known_codes = get_known_mailapi_codes(account, proxy_url)
        code = wait_mailapi_otp(account, proxy_url, known_codes, timeout)
    else:
        raise RuntimeError("account missing mailbox source for email otp")

    response = session.post(
        EMAIL_OTP_VALIDATE_URL,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "openai-sentinel-token": sentinel,
        },
        json={"code": code},
        timeout=20,
        verify=True,
    )
    logs.append(response_entry("email_otp_validate", response, otp_code=code))
    require_ok(response, "email otp validate failed")
    return safe_json(response)


def maybe_handle_totp(session: Any, account: AuthAccount, payload: dict[str, Any], sentinel: str, proxy_url: str, logs: list[dict[str, Any]]) -> dict[str, Any]:
    if not is_totp_payload(payload):
        return payload
    if not account.totp_secret:
        raise RuntimeError("account missing totp secret")
    last_error = ""
    for attempt in range(1, 4):
        code = generate_totp_code(account.totp_secret)
        try:
            return try_totp_validation(session, payload, code, sentinel, proxy_url, logs)
        except RuntimeError as exc:
            last_error = str(exc)
            logs.append(response_entry("totp_retry", attempt=attempt, error=last_error))
            if attempt < 3:
                time.sleep(31)
    raise RuntimeError(last_error or "totp verify failed after retries")


def maybe_prime_auth_cookie(session: Any, payload: dict[str, Any], proxy_url: str, logs: list[dict[str, Any]]) -> None:
    if session.cookies.get("oai-client-auth-session"):
        return
    continue_url = str(payload.get("continue_url") or "").strip()
    if not continue_url:
        return
    url = urllib.parse.urljoin(AUTH_BASE_URL, continue_url)
    response = session.get(url, allow_redirects=False, timeout=20, verify=True)
    logs.append(response_entry("prime_auth_cookie", response))


def follow_callback_chain(session: Any, current_url: str, proxy_url: str, logs: list[dict[str, Any]]) -> str:
    url = current_url
    for _ in range(20):
        response = session.get(url, allow_redirects=False, timeout=20, verify=True)
        logs.append(response_entry("follow_redirect", response))
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
                logs.append(response_entry("consent_accept", consent))
                next_url = urllib.parse.urljoin(url, str(consent.headers.get("Location") or ""))
            else:
                match = re.search(r'content=["\']?\d+;\s*url=([^"\'>\s]+)', response.text, re.I)
                next_url = urllib.parse.urljoin(url, match.group(1)) if match else ""
        else:
            next_url = ""
        if not next_url:
            break
        if "code=" in next_url and "state=" in next_url:
            return next_url
        url = next_url
    raise RuntimeError("callback url not found")


def authorize_one(account: AuthAccount, settings: dict[str, Any], proxy_url: str, otp_timeout: int) -> WorkerResult:
    logs: list[dict[str, Any]] = []
    session = new_session(proxy_url)
    try:
        return _authorize_one_inner(account, settings, proxy_url, otp_timeout, session, logs)
    finally:
        try:
            session.close()
        except Exception:
            pass


def _authorize_one_inner(account: AuthAccount, settings: dict[str, Any], proxy_url: str, otp_timeout: int, session: Any, logs: list[dict[str, Any]]) -> WorkerResult:
    try:
        start = generate_oauth_start(settings)
        response = session.get(start.auth_url, timeout=20, verify=True)
        logs.append(response_entry("oauth_start", response))
        if is_cloudflare_page(response.text):
            raise RuntimeError("cloudflare challenge blocked the session")

        did = str(session.cookies.get("oai-did") or "").strip()
        if not did:
            raise RuntimeError("missing oai-did")
        sentinel_token = fetch_sentinel_token(did, proxy_url)
        sentinel = build_sentinel_header(did, sentinel_token)

        login_response = session.post(
            AUTH_CONTINUE_URL,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "openai-sentinel-token": sentinel,
            },
            json={"username": {"value": account.email, "kind": "email"}, "screen_hint": "login"},
            timeout=20,
            verify=True,
        )
        logs.append(response_entry("authorize_continue", login_response))
        require_ok(login_response, "authorize continue failed")

        password_response = session.post(
            PASSWORD_VERIFY_URL,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "openai-sentinel-token": sentinel,
            },
            json={"password": account.password},
            timeout=20,
            verify=True,
        )
        logs.append(response_entry("password_verify", password_response))
        require_ok(password_response, "password verify failed")
        flow_payload = safe_json(password_response)
        if flow_payload:
            flow_payload = maybe_handle_email_otp(session, account, flow_payload, sentinel, proxy_url, otp_timeout, logs)
            flow_payload = maybe_handle_totp(session, account, flow_payload, sentinel, proxy_url, logs)
            maybe_prime_auth_cookie(session, flow_payload, proxy_url, logs)

        auth_cookie = str(session.cookies.get("oai-client-auth-session") or "").strip()
        if not auth_cookie:
            raise RuntimeError("missing oai-client-auth-session")

        auth_data = parse_auth_cookie(auth_cookie)
        workspaces = auth_data.get("workspaces") or []
        if not workspaces:
            raise RuntimeError("workspace not found in auth cookie")
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            raise RuntimeError("workspace id missing")

        workspace_response = session.post(
            WORKSPACE_SELECT_URL,
            headers={
                "content-type": "application/json",
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            },
            data=json.dumps({"workspace_id": workspace_id}, ensure_ascii=False, separators=(",", ":")),
            timeout=20,
            verify=True,
        )
        logs.append(response_entry("workspace_select", workspace_response, workspace_id=workspace_id))
        require_ok(workspace_response, "workspace select failed")
        workspace_data = safe_json(workspace_response)
        continue_url = str(workspace_data.get("continue_url") or "").strip()

        orgs = ((workspace_data.get("data") or {}).get("orgs") or []) if isinstance(workspace_data, dict) else []
        if orgs:
            org = orgs[0] or {}
            org_id = str(org.get("id") or "").strip()
            if org_id:
                body = {"org_id": org_id}
                projects = org.get("projects") or []
                if projects:
                    project_id = str((projects[0] or {}).get("id") or "").strip()
                    if project_id:
                        body["project_id"] = project_id
                org_response = session.post(
                    ORGANIZATION_SELECT_URL,
                    headers={
                        "content-type": "application/json",
                        "openai-sentinel-token": sentinel,
                    },
                    json=body,
                    timeout=20,
                    verify=True,
                )
                logs.append(response_entry("organization_select", org_response, org_id=org_id))
                if org_response.status_code in {301, 302, 303, 307, 308}:
                    continue_url = urllib.parse.urljoin(continue_url or AUTH_BASE_URL, str(org_response.headers.get("Location") or ""))
                elif org_response.status_code == 200:
                    continue_url = str((safe_json(org_response).get("continue_url") or continue_url)).strip()

        if not continue_url:
            raise RuntimeError("continue_url missing after workspace select")

        callback_url = follow_callback_chain(session, continue_url, proxy_url, logs)
        token_data = exchange_callback(callback_url, start, settings, proxy_url=proxy_url)
        store = TokenStore(settings)
        token_path = store.save_token_response(token_data, metadata={"auth_mode": "protocol_batch"})

        report = {
            "created_at": now_rfc3339(),
            "email": account.email,
            "proxy": proxy_url,
            "callback_url": callback_url,
            "token_path": str(token_path),
            "logs": logs,
            "account": {
                "email": account.email,
                "mailbox_mode": account.mailbox_mode,
                "has_totp": bool(account.totp_secret),
            },
        }
        report_path = report_dir() / f"auth_batch_{re.sub(r'[^a-zA-Z0-9._-]+', '_', account.email)}_{int(time.time())}.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return WorkerResult(
            ok=True,
            email=account.email,
            proxy=proxy_url,
            message="ok",
            token_path=str(token_path),
            report_path=str(report_path),
            callback_url=callback_url,
            logs=logs,
        )
    except Exception as exc:
        report_path = report_dir() / f"auth_batch_fail_{re.sub(r'[^a-zA-Z0-9._-]+', '_', account.email)}_{int(time.time())}.json"
        report_path.write_text(
            json.dumps(
                {
                    "created_at": now_rfc3339(),
                    "email": account.email,
                    "proxy": proxy_url,
                    "error": str(exc),
                    "logs": logs,
                    "account": {
                        "email": account.email,
                        "mailbox_mode": account.mailbox_mode,
                        "has_totp": bool(account.totp_secret),
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return WorkerResult(
            ok=False,
            email=account.email,
            proxy=proxy_url,
            message=str(exc),
            report_path=str(report_path),
            logs=logs,
        )


def run_batch(args: argparse.Namespace) -> int:
    settings = load_app_config()
    if args.tokens_dir:
        settings["tokens_dir"] = args.tokens_dir
    if args.outputs_dir:
        settings["outputs_dir"] = args.outputs_dir
    if args.proxy:
        settings["http_proxy"] = args.proxy
    if args.redirect_uri or args.client_id or args.auth_url or args.token_url or args.scope:
        oauth = dict(settings.get("oauth") or {})
        if args.redirect_uri:
            oauth["redirect_uri"] = args.redirect_uri
        if args.client_id:
            oauth["client_id"] = args.client_id
        if args.auth_url:
            oauth["auth_url"] = args.auth_url
        if args.token_url:
            oauth["token_url"] = args.token_url
        if args.scope:
            oauth["scope"] = args.scope
        settings["oauth"] = oauth

    accounts, errors = load_accounts(Path(args.accounts_file))
    proxies = load_proxies(args.proxies_file or "", args.proxy or "")
    log_line(f"accounts: {len(accounts)}")
    log_line(f"proxies: {len(proxies)}")
    if errors:
        for item in errors[:30]:
            log_line(f"skip: {item}")
    if not accounts:
        return 1
    if args.dry_run:
        return 0

    rotator = ProxyRotator(proxies)
    workers = max(1, int(args.workers))
    otp_timeout = max(30, int(args.otp_timeout))

    ok_count = 0
    fail_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for account in accounts:
            proxy_url = rotator.next()
            futures.append(executor.submit(authorize_one, account, settings, proxy_url, otp_timeout))
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = WorkerResult(ok=False, email="unknown", proxy="", message=str(exc))
            if result.ok:
                ok_count += 1
                log_line(f"ok: {result.email} -> {result.token_path}")
            else:
                fail_count += 1
                log_line(f"fail: {result.email} -> {result.message}")
    log_line(f"done: success={ok_count} fail={fail_count}")
    return 0 if ok_count else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="批量协议授权脚本")
    parser.add_argument("--accounts-file", required=True, help="账号文件")
    parser.add_argument("--proxies-file", default="", help="代理文件")
    parser.add_argument("--proxy", default="", help="单代理")
    parser.add_argument("--workers", type=int, default=3, help="线程数")
    parser.add_argument("--otp-timeout", type=int, default=120, help="验证码等待秒数")
    parser.add_argument("--tokens-dir", default="", help="覆盖 tokens_dir")
    parser.add_argument("--outputs-dir", default="", help="覆盖 outputs_dir")
    parser.add_argument("--auth-url", default="", help="覆盖 auth_url")
    parser.add_argument("--token-url", default="", help="覆盖 token_url")
    parser.add_argument("--client-id", default="", help="覆盖 client_id")
    parser.add_argument("--redirect-uri", default="", help="覆盖 redirect_uri")
    parser.add_argument("--scope", default="", help="覆盖 scope")
    parser.add_argument("--dry-run", action="store_true", help="只校验导入和配置，不发请求")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_batch(args)


if __name__ == "__main__":
    raise SystemExit(main())
