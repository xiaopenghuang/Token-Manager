from __future__ import annotations

import sys
from pathlib import Path


APP_NAME = "OpenAI Token Manager"
APP_VERSION = "2.1.0"

DEFAULT_OAUTH_AUTH_URL = "https://auth.openai.com/oauth/authorize"
DEFAULT_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_OAUTH_SCOPE = "openid email profile offline_access"

DEFAULT_CALLBACK_SUCCESS_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>OAuth Success</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;padding:24px;">
<h2>授权完成</h2>
<p>可以回到 OpenAI Token Manager 了。</p>
</body>
</html>
"""

DEFAULT_CALLBACK_FAILURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>OAuth Failed</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;padding:24px;">
<h2>授权失败</h2>
<p>回到 OpenAI Token Manager 查看错误信息。</p>
</body>
</html>
"""

DEFAULT_REFRESH_WORKERS = 6
DEFAULT_UPLOAD_WORKERS = 4
MAX_REFRESH_WORKERS = 32
MAX_UPLOAD_WORKERS = 32
DEFAULT_AUTO_REFRESH_INTERVAL = 60
DEFAULT_AUTO_REFRESH_THRESHOLD = 300
DEFAULT_LOG_POLL_MS = 200
DEFAULT_UI_REFRESH_MS = 30000
DEFAULT_AUTH_TIMEOUT_SECONDS = 300

DEFAULT_SUB2API_GROUP_IDS = "2"


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


APP_DIR = app_dir()
APP_CONFIG_FILE = APP_DIR / "token_manager_config.json"
DEFAULT_TOKENS_DIR = APP_DIR / "tokens"
DEFAULT_OUTPUTS_DIR = APP_DIR / "outputs"
