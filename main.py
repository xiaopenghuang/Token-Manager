#!/usr/bin/env python3
from __future__ import annotations

import argparse

from token_manager.constants import APP_VERSION
from token_manager.gui import run_app


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI Token Manager")
    parser.add_argument("--version", action="version", version=f"v{APP_VERSION}")
    parser.add_argument("command", nargs="?", default="gui", choices=["gui"])
    parser.parse_args()
    run_app()


if __name__ == "__main__":
    main()
