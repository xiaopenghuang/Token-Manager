from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .constants import (
    APP_CONFIG_FILE,
    DEFAULT_AUTO_REFRESH_INTERVAL,
    DEFAULT_AUTO_REFRESH_THRESHOLD,
    DEFAULT_OAUTH_AUTH_URL,
    DEFAULT_OAUTH_CLIENT_ID,
    DEFAULT_OAUTH_REDIRECT_URI,
    DEFAULT_OAUTH_SCOPE,
    DEFAULT_OAUTH_TOKEN_URL,
    DEFAULT_OUTPUTS_DIR,
    DEFAULT_REFRESH_WORKERS,
    DEFAULT_SUB2API_GROUP_IDS,
    DEFAULT_TOKENS_DIR,
    DEFAULT_UPLOAD_WORKERS,
)


from .utils import atomic_write_json


def default_config() -> dict[str, Any]:
    return {
        "tokens_dir": str(DEFAULT_TOKENS_DIR),
        "outputs_dir": str(DEFAULT_OUTPUTS_DIR),
        "refresh_workers": DEFAULT_REFRESH_WORKERS,
        "upload_workers": DEFAULT_UPLOAD_WORKERS,
        "auth_2fa_live_workers": 3,
        "auth_2fa_live_save_token": False,
        "auto_refresh_interval_seconds": DEFAULT_AUTO_REFRESH_INTERVAL,
        "auto_refresh_threshold_seconds": DEFAULT_AUTO_REFRESH_THRESHOLD,
        "organize_tokens_by_plan": True,
        "http_proxy": "",
        "open_browser_on_auto_auth": True,
        "auto_auth_timeout_seconds": 300,
        "oauth": {
            "auth_url": DEFAULT_OAUTH_AUTH_URL,
            "token_url": DEFAULT_OAUTH_TOKEN_URL,
            "client_id": DEFAULT_OAUTH_CLIENT_ID,
            "redirect_uri": DEFAULT_OAUTH_REDIRECT_URI,
            "scope": DEFAULT_OAUTH_SCOPE,
        },
        "integrations": {
            "cpa": {
                "api_url": "",
                "api_key": "",
                "container_name": "cli-proxy-api",
            },
            "sub2api": {
                "api_url": "",
                "api_key": "",
                "group_ids": DEFAULT_SUB2API_GROUP_IDS,
                "admin_email": "",
                "admin_password": "",
                "access_token": "",
                "refresh_token": "",
                "token_expires_at": 0,
            },
        },
    }


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _migrate_legacy_config(raw: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(raw or {})
    if migrated.get("custom_scan_root") and not migrated.get("tokens_dir"):
        root = Path(str(migrated["custom_scan_root"])).expanduser()
        migrated["tokens_dir"] = str(root if root.name.lower() == "tokens" else root / "tokens")
    return migrated


def load_app_config() -> dict[str, Any]:
    config = default_config()
    if not APP_CONFIG_FILE.exists():
        return config

    try:
        raw = json.loads(APP_CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except Exception:
        return config

    if not isinstance(raw, dict):
        return config
    return _deep_merge(config, _migrate_legacy_config(raw))


def save_app_config(config: dict[str, Any]) -> None:
    atomic_write_json(APP_CONFIG_FILE, config)
