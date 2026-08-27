# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_PATH: Path | None = None


def setup_logging() -> Path | None:
    global LOG_PATH
    logger = logging.getLogger("isopropyl")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return LOG_PATH
    try:
        state_root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        directory = state_root / "isopropyl"
        directory.mkdir(parents=True, exist_ok=True)
        LOG_PATH = directory / "isopropyl.log"
        handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=2)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())
        LOG_PATH = None
    logger.info("ISOpropyl started")
    return LOG_PATH


def read_log() -> str:
    if not LOG_PATH:
        return "File logging is unavailable in this session."
    try:
        return LOG_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return f"Could not read {LOG_PATH}: {error}"
