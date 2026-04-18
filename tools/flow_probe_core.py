from __future__ import annotations

import json
import queue
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import requests
import websocket

from token_manager.constants import APP_DIR


DEFAULT_FILTER_PATTERN = r".*"
SENSITIVE_HEADER_RE = re.compile(
    r"(authorization|cookie|set-cookie|x-auth|x-api-key|proxy-authorization)",
    re.I,
)
SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|pass(word)?|cookie|session|otp|totp|code|key|authorization)",
    re.I,
)
SENSITIVE_TEXT_RE = re.compile(
    r"(?i)\b(bearer)\s+[A-Za-z0-9._\-=/+]+\b|"
    r"((?:access|refresh|id|auth|session|csrf|otp|totp|password|secret|code|key)[-_a-zA-Z0-9]*=)([^&\s]+)"
)


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure_probe_dir(name: str = "FlowProbeStudio") -> Path:
    path = APP_DIR / "outputs" / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def snippet(value: Any, max_len: int = 1200) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def redact_string(value: str, max_len: int = 1200) -> str:
    def _replace(match: re.Match[str]) -> str:
        if match.group(1):
            return "Bearer <redacted>"
        if match.group(2):
            return f"{match.group(2)}<redacted>"
        return "<redacted>"

    return snippet(SENSITIVE_TEXT_RE.sub(_replace, value or ""), max_len=max_len)


def redact_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    result: dict[str, str] = {}
    for key, value in headers.items():
        key_text = str(key)
        value_text = str(value)
        if SENSITIVE_HEADER_RE.search(key_text):
            result[key_text] = "<redacted>"
        else:
            result[key_text] = redact_string(value_text, max_len=600)
    return result


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if SENSITIVE_KEY_RE.search(key_text):
                result[key_text] = "<redacted>"
            else:
                result[key_text] = redact_value(item)
        return result
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def parse_post_data(request: dict[str, Any]) -> Any:
    post_data = request.get("postData")
    if not isinstance(post_data, str) or not post_data:
        return ""
    headers = request.get("headers") or {}
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
    if "application/json" in content_type.lower():
        try:
            return json.loads(post_data)
        except Exception:
            return post_data
    if "application/x-www-form-urlencoded" in content_type.lower():
        return urllib.parse.parse_qs(post_data, keep_blank_values=True)
    return post_data


def parse_response_body(body: str, mime_type: str) -> Any:
    if not body:
        return ""
    mime_text = str(mime_type or "").lower()
    if "application/json" in mime_text:
        try:
            return json.loads(body)
        except Exception:
            return body
    return body


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass(slots=True)
class TargetInfo:
    id: str
    title: str
    url: str
    web_socket_debugger_url: str


@dataclass(slots=True)
class ProbeOptions:
    debug_port: int = 9222
    target_hint: str = ""
    target_id: str = ""
    filter_pattern: str = DEFAULT_FILTER_PATTERN
    output_dir: Path | None = None
    capture_response_body: bool = True
    output_prefix: str = "flow_probe"


class CDPClient:
    def __init__(self, ws_url: str) -> None:
        self.ws = websocket.create_connection(ws_url, timeout=30)
        self._message_queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._closed = False
        self._next_id = 1
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def _reader_loop(self) -> None:
        while not self._closed:
            try:
                raw = self.ws.recv()
            except Exception:
                break
            try:
                message = json.loads(raw)
            except Exception:
                continue
            if "id" in message:
                target = self._pending.get(int(message["id"]))
                if target is not None:
                    target.put(message)
                continue
            self._message_queue.put(message)

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
        call_id = self._next_id
        self._next_id += 1
        waiter: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=1)
        self._pending[call_id] = waiter
        self.ws.send(json.dumps({"id": call_id, "method": method, "params": params or {}}))
        try:
            response = waiter.get(timeout=timeout)
        finally:
            self._pending.pop(call_id, None)
        if response.get("error"):
            raise RuntimeError(f"{method} failed: {response['error']}")
        return dict(response.get("result") or {})

    def recv_event(self, timeout: float = 0.5) -> dict[str, Any] | None:
        try:
            return self._message_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        self._closed = True
        try:
            self.ws.close()
        except Exception:
            pass


def load_targets(debug_port: int) -> list[TargetInfo]:
    response = requests.get(f"http://127.0.0.1:{debug_port}/json/list", timeout=10)
    response.raise_for_status()
    payload = response.json()
    results: list[TargetInfo] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        ws_url = str(item.get("webSocketDebuggerUrl") or "").strip()
        if not ws_url:
            continue
        results.append(
            TargetInfo(
                id=str(item.get("id") or ""),
                title=str(item.get("title") or ""),
                url=str(item.get("url") or ""),
                web_socket_debugger_url=ws_url,
            )
        )
    return results


def choose_target(targets: list[TargetInfo], target_hint: str = "", target_id: str = "") -> TargetInfo:
    wanted_id = str(target_id or "").strip()
    if wanted_id:
        for item in targets:
            if item.id == wanted_id:
                return item
    hint = str(target_hint or "").strip().lower()
    if hint:
        for item in targets:
            hay = f"{item.title} {item.url}".lower()
            if hint in hay:
                return item
    if not targets:
        raise RuntimeError("no debuggable pages found")
    return targets[0]


def record_event_line(kind: str, entry: dict[str, Any]) -> str:
    method = str(entry.get("method") or "")
    url = str(entry.get("url") or "")
    status = entry.get("status")
    if status is None:
        return f"{kind} {method} {url}"
    return f"{kind} {status} {method} {url}"


class FlowProbe:
    def __init__(
        self,
        options: ProbeOptions,
        *,
        log_fn: Callable[[str], None] | None = None,
        event_fn: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.options = options
        self.log_fn = log_fn
        self.event_fn = event_fn
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._client: CDPClient | None = None
        self.meta_path: Path | None = None
        self.trace_path: Path | None = None
        self.target: TargetInfo | None = None

    def _log(self, message: str) -> None:
        if callable(self.log_fn):
            self.log_fn(message)

    def _emit(self, payload: dict[str, Any]) -> None:
        if self.trace_path is None:
            raise RuntimeError("trace_path not initialized")
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        if callable(self.event_fn):
            self.event_fn(payload)

    def prepare(self) -> dict[str, Any]:
        if self.target is not None and self.trace_path is not None and self.meta_path is not None:
            return {
                "target": self.target,
                "trace_path": self.trace_path,
                "meta_path": self.meta_path,
            }
        targets = load_targets(self.options.debug_port)
        target = choose_target(targets, self.options.target_hint, self.options.target_id)
        out_dir = self.options.output_dir or ensure_probe_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        prefix = self.options.output_prefix or "flow_probe"
        self.trace_path = out_dir / f"{prefix}_trace_{ts}.ndjson"
        self.meta_path = out_dir / f"{prefix}_meta_{ts}.json"
        self.target = target
        write_json(
            self.meta_path,
            {
                "created_at": now_rfc3339(),
                "debug_port": self.options.debug_port,
                "target": {
                    "id": target.id,
                    "title": target.title,
                    "url": target.url,
                },
                "filter": self.options.filter_pattern,
                "capture_response_body": self.options.capture_response_body,
            },
        )
        return {
            "target": target,
            "trace_path": self.trace_path,
            "meta_path": self.meta_path,
        }

    def start_background(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("probe already running")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self.run_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._client is not None:
            self._client.close()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def run_forever(self) -> None:
        prepared = self.prepare()
        target = prepared["target"]
        pattern = re.compile(self.options.filter_pattern, re.I)
        request_map: dict[str, dict[str, Any]] = {}
        response_map: dict[str, dict[str, Any]] = {}
        self._client = CDPClient(target.web_socket_debugger_url)

        try:
            self._client.call("Page.enable")
            self._client.call(
                "Network.enable",
                {"maxResourceBufferSize": 1024 * 1024 * 10, "maxTotalBufferSize": 1024 * 1024 * 50},
            )
            self._client.call("Runtime.enable")
            self._client.call("Network.setCacheDisabled", {"cacheDisabled": True})
            self._log(f"已附着页签 {target.title or '(无标题)'}")
            self._log(f"链路文件 {self.trace_path}")

            while not self._stop_event.is_set():
                event = self._client.recv_event(timeout=0.5)
                if event is None:
                    continue
                method = str(event.get("method") or "")
                params = dict(event.get("params") or {})

                if method == "Network.requestWillBeSent":
                    request_id = str(params.get("requestId") or "")
                    request = dict(params.get("request") or {})
                    url = str(request.get("url") or "")
                    if not pattern.search(url):
                        continue
                    entry = {
                        "kind": "request",
                        "ts": now_rfc3339(),
                        "request_id": request_id,
                        "loader_id": str(params.get("loaderId") or ""),
                        "type": str(params.get("type") or ""),
                        "document_url": redact_string(str(params.get("documentURL") or ""), max_len=600),
                        "method": str(request.get("method") or ""),
                        "url": redact_string(url, max_len=1200),
                        "headers": redact_headers(request.get("headers")),
                        "post_data": redact_value(parse_post_data(request)),
                        "has_post_data": bool(request.get("hasPostData") or request.get("postData")),
                        "initiator": redact_value(params.get("initiator") or {}),
                        "redirect_response": redact_value(params.get("redirectResponse") or {}),
                    }
                    request_map[request_id] = entry
                    self._emit(entry)
                    self._log(record_event_line(">>", entry))
                    continue

                if method == "Network.requestWillBeSentExtraInfo":
                    request_id = str(params.get("requestId") or "")
                    entry = request_map.get(request_id)
                    if not entry:
                        continue
                    extra = {
                        "kind": "request_extra",
                        "ts": now_rfc3339(),
                        "request_id": request_id,
                        "headers": redact_headers(params.get("headers")),
                        "associated_cookies": redact_value(params.get("associatedCookies") or []),
                        "connect_timing": params.get("connectTiming") or {},
                        "client_security_state": params.get("clientSecurityState") or {},
                    }
                    self._emit(extra)
                    continue

                if method == "Network.responseReceived":
                    request_id = str(params.get("requestId") or "")
                    response = dict(params.get("response") or {})
                    url = str(response.get("url") or "")
                    if not pattern.search(url):
                        continue
                    entry = {
                        "kind": "response",
                        "ts": now_rfc3339(),
                        "request_id": request_id,
                        "url": redact_string(url, max_len=1200),
                        "method": str((request_map.get(request_id) or {}).get("method") or ""),
                        "status": int(response.get("status") or 0),
                        "status_text": str(response.get("statusText") or ""),
                        "mime_type": str(response.get("mimeType") or ""),
                        "headers": redact_headers(response.get("headers")),
                        "remote_ip": str(response.get("remoteIPAddress") or ""),
                        "protocol": str(response.get("protocol") or ""),
                        "security_details": redact_value(response.get("securityDetails") or {}),
                    }
                    response_map[request_id] = entry
                    self._emit(entry)
                    self._log(record_event_line("<<", entry))
                    continue

                if method == "Network.responseReceivedExtraInfo":
                    request_id = str(params.get("requestId") or "")
                    if request_id not in response_map and request_id not in request_map:
                        continue
                    extra = {
                        "kind": "response_extra",
                        "ts": now_rfc3339(),
                        "request_id": request_id,
                        "status_code": params.get("statusCode"),
                        "headers": redact_headers(params.get("headers")),
                        "blocked_cookies": redact_value(params.get("blockedCookies") or []),
                        "resource_ip_address_space": str(params.get("resourceIPAddressSpace") or ""),
                    }
                    self._emit(extra)
                    continue

                if method == "Network.loadingFinished":
                    request_id = str(params.get("requestId") or "")
                    request_entry = request_map.get(request_id)
                    if not request_entry or not self.options.capture_response_body:
                        continue
                    body_value: Any = ""
                    body_status = (response_map.get(request_id) or {}).get("status")
                    mime_type = str((response_map.get(request_id) or {}).get("mime_type") or "")
                    try:
                        body_data = self._client.call("Network.getResponseBody", {"requestId": request_id}, timeout=5)
                        body = str(body_data.get("body") or "")
                        if body_data.get("base64Encoded"):
                            body_value = f"[base64:{len(body)}]"
                        else:
                            body_value = redact_value(parse_response_body(body, mime_type))
                    except Exception as exc:
                        body_value = f"[getResponseBody failed] {exc}"
                    entry = {
                        "kind": "body",
                        "ts": now_rfc3339(),
                        "request_id": request_id,
                        "url": str(request_entry.get("url") or ""),
                        "status": body_status,
                        "body": body_value,
                    }
                    self._emit(entry)
                    continue

                if method == "Page.frameNavigated":
                    frame = dict(params.get("frame") or {})
                    url = str(frame.get("url") or "")
                    if not pattern.search(url):
                        continue
                    entry = {
                        "kind": "frame_navigated",
                        "ts": now_rfc3339(),
                        "frame": redact_value(frame),
                    }
                    self._emit(entry)
                    self._log(f"== navigated {redact_string(url, max_len=1200)}")
                    continue
        except Exception as exc:
            self._log(f"监听异常 {exc}")
        finally:
            if self._client is not None:
                self._client.close()
            self._log("监听已停止")
