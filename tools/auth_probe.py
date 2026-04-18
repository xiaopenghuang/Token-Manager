from __future__ import annotations

import argparse
import json
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from token_manager.config import load_app_config
from token_manager.constants import APP_DIR
from token_manager.oauth import OAuthCallbackServer, OAuthStart, exchange_callback, generate_oauth_start
from token_manager.utils import decode_jwt, now_rfc3339


def _timestamp_slug() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def _default_save_dir() -> Path:
    return APP_DIR / "outputs" / "auth_probe"


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


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
    return settings


def _start_to_dict(start: OAuthStart) -> dict[str, Any]:
    return {
        "auth_url": start.auth_url,
        "state": start.state,
        "code_verifier": start.code_verifier,
        "redirect_uri": start.redirect_uri,
    }


def _dict_to_start(data: dict[str, Any]) -> OAuthStart:
    return OAuthStart(
        auth_url=str(data.get("auth_url") or "").strip(),
        state=str(data.get("state") or "").strip(),
        code_verifier=str(data.get("code_verifier") or "").strip(),
        redirect_uri=str(data.get("redirect_uri") or "").strip(),
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


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
        "plan": str(
            access_auth.get("chatgpt_plan_type")
            or id_auth.get("chatgpt_plan_type")
            or ""
        ),
    }


def _build_session_payload(settings: dict[str, Any], start: OAuthStart) -> dict[str, Any]:
    return {
        "created_at": now_rfc3339(),
        "proxy": str(settings.get("http_proxy") or ""),
        "oauth": dict(settings.get("oauth") or {}),
        "start": _start_to_dict(start),
    }


def _save_session(payload: dict[str, Any], save_dir: Path) -> Path:
    session_path = save_dir / f"oauth_session_{_timestamp_slug()}.json"
    _write_json(session_path, payload)
    return session_path


def _save_report(
    *,
    settings: dict[str, Any],
    start: OAuthStart,
    callback_url: str,
    token_data: dict[str, Any],
    save_dir: Path,
    session_path: Path | None,
) -> Path:
    report_path = save_dir / f"auth_probe_{_timestamp_slug()}.json"
    payload = {
        "created_at": now_rfc3339(),
        "proxy": str(settings.get("http_proxy") or ""),
        "oauth": dict(settings.get("oauth") or {}),
        "start": _start_to_dict(start),
        "callback_url": callback_url,
        "token_summary": _token_summary(token_data),
        "token_data": token_data,
        "session_path": str(session_path) if session_path else "",
    }
    _write_json(report_path, payload)
    return report_path


def _print_start(start: OAuthStart, session_path: Path | None = None) -> None:
    if session_path:
        print(f"session: {session_path}")
    print(f"redirect_uri: {start.redirect_uri}")
    print(f"state: {start.state}")
    print(f"auth_url: {start.auth_url}")


def command_start(args: argparse.Namespace) -> int:
    settings = _load_settings(args)
    save_dir = _ensure_dir(Path(args.save_dir).resolve() if args.save_dir else _default_save_dir())
    start = generate_oauth_start(settings)
    session_path = _save_session(_build_session_payload(settings, start), save_dir)
    _print_start(start, session_path)
    return 0


def command_browser(args: argparse.Namespace) -> int:
    settings = _load_settings(args)
    save_dir = _ensure_dir(Path(args.save_dir).resolve() if args.save_dir else _default_save_dir())
    start = generate_oauth_start(settings)
    session_path = _save_session(_build_session_payload(settings, start), save_dir)
    _print_start(start, session_path)

    server = OAuthCallbackServer(start.redirect_uri)
    server.start()
    try:
        if args.open_browser:
            webbrowser.open(start.auth_url)
            print("browser: opened")
        else:
            print("browser: not opened")
        callback_url = server.wait(args.timeout)
        print(f"callback_url: {callback_url}")
        token_data = exchange_callback(
            callback_url,
            start,
            settings,
            proxy_url=str(settings.get("http_proxy") or ""),
        )
    finally:
        server.close()

    report_path = _save_report(
        settings=settings,
        start=start,
        callback_url=callback_url,
        token_data=token_data,
        save_dir=save_dir,
        session_path=session_path,
    )
    print(f"email: {token_data.get('email', '')}")
    print(f"account_id: {token_data.get('account_id', '')}")
    print(f"report: {report_path}")
    return 0


def command_exchange(args: argparse.Namespace) -> int:
    session_path = Path(args.session).resolve()
    if not session_path.exists():
        raise FileNotFoundError(f"session file not found: {session_path}")

    payload = json.loads(session_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("session file format invalid")

    settings = {
        "http_proxy": str(payload.get("proxy") or ""),
        "oauth": dict(payload.get("oauth") or {}),
    }
    if args.proxy is not None:
        settings["http_proxy"] = args.proxy.strip()

    start = _dict_to_start(dict(payload.get("start") or {}))
    if not start.state or not start.code_verifier or not start.redirect_uri:
        raise ValueError("session file missing oauth start data")

    callback_url = str(args.callback_url or "").strip()
    if not callback_url:
        raise ValueError("callback_url required")

    save_dir = _ensure_dir(Path(args.save_dir).resolve() if args.save_dir else _default_save_dir())
    token_data = exchange_callback(
        callback_url,
        start,
        settings,
        proxy_url=str(settings.get("http_proxy") or ""),
    )
    report_path = _save_report(
        settings=settings,
        start=start,
        callback_url=callback_url,
        token_data=token_data,
        save_dir=save_dir,
        session_path=session_path,
    )
    print(f"email: {token_data.get('email', '')}")
    print(f"account_id: {token_data.get('account_id', '')}")
    print(f"report: {report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OAuth 授权测试脚本")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_options(target: argparse.ArgumentParser) -> None:
        target.add_argument("--auth-url", help="覆盖 auth_url")
        target.add_argument("--token-url", help="覆盖 token_url")
        target.add_argument("--client-id", help="覆盖 client_id")
        target.add_argument("--redirect-uri", help="覆盖 redirect_uri")
        target.add_argument("--scope", help="覆盖 scope")
        target.add_argument("--proxy", help="覆盖 http_proxy，传空字符串可禁用")
        target.add_argument("--save-dir", help="输出目录，默认 outputs/auth_probe")

    start_parser = subparsers.add_parser("start", help="生成授权链接并保存 session")
    add_common_options(start_parser)
    start_parser.set_defaults(func=command_start)

    browser_parser = subparsers.add_parser("browser", help="启动本地回调并直接测试换 token")
    add_common_options(browser_parser)
    browser_parser.add_argument("--timeout", type=int, default=300, help="等待回调秒数")
    browser_parser.add_argument(
        "--open-browser",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="是否自动打开浏览器",
    )
    browser_parser.set_defaults(func=command_browser)

    exchange_parser = subparsers.add_parser("exchange", help="用现成 callback_url 测试换 token")
    exchange_parser.add_argument("--session", required=True, help="start/browser 生成的 session 文件")
    exchange_parser.add_argument("--callback-url", required=True, help="浏览器拿到的 callback_url")
    exchange_parser.add_argument("--proxy", help="覆盖 session 里的 http_proxy，传空字符串可禁用")
    exchange_parser.add_argument("--save-dir", help="输出目录，默认 outputs/auth_probe")
    exchange_parser.set_defaults(func=command_exchange)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
