from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests

from .constants import (
    DEFAULT_CALLBACK_FAILURE_HTML,
    DEFAULT_CALLBACK_SUCCESS_HTML,
)
from .utils import (
    build_requests_proxies,
    decode_jwt,
    format_rfc3339_from_ts,
    now_ts,
    parse_callback_url,
)


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(value: str) -> str:
    return _b64url_no_pad(hashlib.sha256(value.encode("ascii")).digest())


@dataclass(slots=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_start(settings: dict[str, Any]) -> OAuthStart:
    oauth = dict(settings.get("oauth") or {})
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    params = {
        "client_id": oauth.get("client_id", ""),
        "response_type": "code",
        "redirect_uri": oauth.get("redirect_uri", ""),
        "scope": oauth.get("scope", ""),
        "state": state,
        "code_challenge": _sha256_b64url_no_pad(code_verifier),
        "code_challenge_method": "S256",
        "prompt": "login",
    }
    auth_url = f"{oauth.get('auth_url', '').rstrip()}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=str(oauth.get("redirect_uri") or ""),
    )


def exchange_callback(
    callback_url: str,
    start: OAuthStart,
    settings: dict[str, Any],
    proxy_url: str = "",
) -> dict[str, Any]:
    code, state = parse_callback_url(callback_url)
    if state != start.state:
        raise ValueError("State 验证失败")

    oauth = dict(settings.get("oauth") or {})
    response = requests.post(
        str(oauth.get("token_url") or ""),
        data={
            "grant_type": "authorization_code",
            "client_id": str(oauth.get("client_id") or ""),
            "code": code,
            "redirect_uri": start.redirect_uri,
            "code_verifier": start.code_verifier,
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
    id_token = str(data.get("id_token") or "")
    access_token = str(data.get("access_token") or "")
    claims = decode_jwt(id_token)
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    expires_in = int(data.get("expires_in") or 3600)
    now = now_ts()
    return {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": str(data.get("refresh_token") or ""),
        "account_id": str(auth_claims.get("chatgpt_account_id") or ""),
        "last_refresh": format_rfc3339_from_ts(now),
        "email": str(claims.get("email") or ""),
        "type": "codex",
        "expired": format_rfc3339_from_ts(now + max(0, expires_in)),
    }


class OAuthCallbackServer:
    def __init__(self, redirect_uri: str) -> None:
        parsed = urllib.parse.urlparse(redirect_uri)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
        self.path = parsed.path or "/"
        self.scheme = parsed.scheme or "http"
        self._callback_url = ""
        self._event = threading.Event()
        self._error = ""
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                host = self.headers.get("Host") or f"{outer.host}:{outer.port}"
                full_url = f"{outer.scheme}://{host}{self.path}"
                if self.path.startswith(outer.path):
                    outer._callback_url = full_url
                    outer._event.set()
                    body = DEFAULT_CALLBACK_SUCCESS_HTML.encode("utf-8")
                    self.send_response(200)
                else:
                    body = DEFAULT_CALLBACK_FAILURE_HTML.encode("utf-8")
                    self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args):  # noqa: A003
                return

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        except OSError as exc:
            raise RuntimeError(f"无法监听 {self.host}:{self.port}，端口可能被占用: {exc}") from exc
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def wait(self, timeout: int) -> str:
        completed = self._event.wait(max(1, int(timeout)))
        if not completed:
            raise TimeoutError("等待浏览器回调超时")
        return self._callback_url

    def close(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def browser_assisted_authorize(
    settings: dict[str, Any],
    *,
    proxy_url: str = "",
    timeout: int = 300,
    open_browser: bool = True,
    log_fn=None,
) -> dict[str, Any]:
    def _log(message: str) -> None:
        if callable(log_fn):
            log_fn(message)

    start = generate_oauth_start(settings)
    _log("已生成授权 URL")
    server = OAuthCallbackServer(start.redirect_uri)
    server.start()
    try:
        if open_browser:
            webbrowser.open(start.auth_url)
            _log("已自动打开浏览器，正在等待回调")
        else:
            _log("已启动本地回调监听，请手动打开授权 URL")
        callback_url = server.wait(timeout)
        _log("已收到浏览器回调，正在换取 Token")
        token_data = exchange_callback(
            callback_url,
            start,
            settings,
            proxy_url=proxy_url,
        )
        _log("授权成功，Token 已获取")
        return {"start": start, "callback_url": callback_url, "token_data": token_data}
    finally:
        server.close()
