from __future__ import annotations

import argparse
import json
import queue
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import sys

import requests
import websocket

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from token_manager.constants import APP_DIR


DEFAULT_FILTER_RE = re.compile(
    r"(auth\.openai\.com|sentinel\.openai\.com|chatgpt\.com/backend-api|chatgpt\.com/ces/)",
    re.I,
)


def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def snippet(value: Any, max_len: int = 600) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def ensure_probe_dir() -> Path:
    path = APP_DIR / "outputs" / "LoginFlowProbe"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(slots=True)
class TargetInfo:
    id: str
    title: str
    url: str
    web_socket_debugger_url: str


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


def choose_target(targets: list[TargetInfo], target_hint: str) -> TargetInfo:
    hint = str(target_hint or "").strip().lower()
    if hint:
        for item in targets:
            hay = f"{item.title} {item.url}".lower()
            if hint in hay:
                return item
    for item in targets:
        if "auth.openai.com" in item.url.lower():
            return item
    if not targets:
        raise RuntimeError("no debuggable pages found")
    return targets[0]


def print_target_list(targets: list[TargetInfo]) -> None:
    for idx, item in enumerate(targets, start=1):
        print(f"[{idx}] {item.title} | {item.url}")


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_post_data(request: dict[str, Any]) -> Any:
    post_data = request.get("postData")
    if not isinstance(post_data, str) or not post_data:
        return ""
    content_type = str((request.get("headers") or {}).get("Content-Type") or (request.get("headers") or {}).get("content-type") or "")
    if "application/json" in content_type.lower():
        try:
            return json.loads(post_data)
        except Exception:
            return post_data
    if "application/x-www-form-urlencoded" in content_type.lower():
        return urllib.parse.parse_qs(post_data, keep_blank_values=True)
    return post_data


def normalize_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    return {str(key): str(value) for key, value in headers.items()}


def record_event_line(kind: str, entry: dict[str, Any]) -> str:
    method = str(entry.get("method") or "")
    url = str(entry.get("url") or "")
    status = entry.get("status")
    if status is None:
        return f"{kind} {method} {url}"
    return f"{kind} {status} {method} {url}"


def matches_filter(url: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(str(url or "")))


def run_probe(args: argparse.Namespace) -> int:
    targets = load_targets(args.debug_port)
    if args.list_targets:
        print_target_list(targets)
        return 0

    target = choose_target(targets, args.target)
    out_dir = ensure_probe_dir()
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    trace_path = out_dir / f"probe_trace_{ts}.ndjson"
    meta_path = out_dir / f"probe_meta_{ts}.json"

    write_json(
        meta_path,
        {
            "created_at": now_rfc3339(),
            "debug_port": args.debug_port,
            "target": {
                "id": target.id,
                "title": target.title,
                "url": target.url,
            },
            "filter": args.filter,
        },
    )

    pattern = re.compile(args.filter, re.I)
    client = CDPClient(target.web_socket_debugger_url)
    request_map: dict[str, dict[str, Any]] = {}
    response_map: dict[str, dict[str, Any]] = {}
    closed = False

    def append_event(payload: dict[str, Any]) -> None:
        with trace_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    try:
        client.call("Page.enable")
        client.call("Network.enable", {"maxResourceBufferSize": 1024 * 1024 * 10, "maxTotalBufferSize": 1024 * 1024 * 50})
        client.call("Runtime.enable")
        client.call("Network.setCacheDisabled", {"cacheDisabled": True})
        print(f"attached: {target.title} | {target.url}")
        print(f"trace: {trace_path}")
        print("开始监听，手工登录就行，按 Ctrl+C 停止。")

        while True:
            event = client.recv_event(timeout=0.5)
            if event is None:
                continue
            method = str(event.get("method") or "")
            params = dict(event.get("params") or {})

            if method == "Network.requestWillBeSent":
                request_id = str(params.get("requestId") or "")
                request = dict(params.get("request") or {})
                url = str(request.get("url") or "")
                if not matches_filter(url, pattern):
                    continue
                entry = {
                    "kind": "request",
                    "ts": now_rfc3339(),
                    "request_id": request_id,
                    "loader_id": str(params.get("loaderId") or ""),
                    "type": str(params.get("type") or ""),
                    "document_url": str(params.get("documentURL") or ""),
                    "method": str(request.get("method") or ""),
                    "url": url,
                    "headers": normalize_headers(request.get("headers")),
                    "post_data": parse_post_data(request),
                    "has_post_data": bool(request.get("hasPostData") or request.get("postData")),
                    "initiator": params.get("initiator") or {},
                    "redirect_response": params.get("redirectResponse") or {},
                }
                request_map[request_id] = entry
                append_event(entry)
                print(record_event_line(">>", entry))
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
                    "headers": normalize_headers(params.get("headers")),
                    "associated_cookies": params.get("associatedCookies") or [],
                    "connect_timing": params.get("connectTiming") or {},
                    "client_security_state": params.get("clientSecurityState") or {},
                }
                append_event(extra)
                continue

            if method == "Network.responseReceived":
                request_id = str(params.get("requestId") or "")
                response = dict(params.get("response") or {})
                url = str(response.get("url") or "")
                if not matches_filter(url, pattern):
                    continue
                entry = {
                    "kind": "response",
                    "ts": now_rfc3339(),
                    "request_id": request_id,
                    "url": url,
                    "method": str((request_map.get(request_id) or {}).get("method") or ""),
                    "status": int(response.get("status") or 0),
                    "status_text": str(response.get("statusText") or ""),
                    "mime_type": str(response.get("mimeType") or ""),
                    "headers": normalize_headers(response.get("headers")),
                    "remote_ip": str(response.get("remoteIPAddress") or ""),
                    "protocol": str(response.get("protocol") or ""),
                    "security_details": response.get("securityDetails") or {},
                }
                response_map[request_id] = entry
                append_event(entry)
                print(record_event_line("<<", entry))
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
                    "headers": normalize_headers(params.get("headers")),
                    "blocked_cookies": params.get("blockedCookies") or [],
                    "resource_ip_address_space": str(params.get("resourceIPAddressSpace") or ""),
                }
                append_event(extra)
                continue

            if method == "Network.loadingFinished":
                request_id = str(params.get("requestId") or "")
                request_entry = request_map.get(request_id)
                if not request_entry:
                    continue
                try:
                    body_data = client.call("Network.getResponseBody", {"requestId": request_id}, timeout=5)
                    body = body_data.get("body")
                    if body_data.get("base64Encoded"):
                        body = f"[base64:{len(str(body or ''))}]"
                except Exception as exc:
                    body = f"[getResponseBody failed] {exc}"
                entry = {
                    "kind": "body",
                    "ts": now_rfc3339(),
                    "request_id": request_id,
                    "url": str(request_entry.get("url") or ""),
                    "status": (response_map.get(request_id) or {}).get("status"),
                    "body": body,
                }
                append_event(entry)
                continue

            if method == "Page.frameNavigated":
                frame = dict(params.get("frame") or {})
                url = str(frame.get("url") or "")
                if not matches_filter(url, pattern):
                    continue
                append_event(
                    {
                        "kind": "frame_navigated",
                        "ts": now_rfc3339(),
                        "frame": frame,
                    }
                )
                print(f"== navigated {url}")
                continue
    except KeyboardInterrupt:
        closed = True
        print("\n停止监听。")
    finally:
        client.close()
    return 0 if closed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="实时登录链路采集脚本")
    parser.add_argument("--debug-port", type=int, default=9222, help="Chrome remote debugging 端口")
    parser.add_argument("--target", default="", help="页签匹配关键字，默认优先 auth.openai.com")
    parser.add_argument("--filter", default=DEFAULT_FILTER_RE.pattern, help="URL 过滤正则")
    parser.add_argument("--list-targets", action="store_true", help="只列出可附着页签")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_probe(args)


if __name__ == "__main__":
    raise SystemExit(main())
