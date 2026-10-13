"""Platform conventions for app data; Linux XDG overrides remain honored."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import sys
from pathlib import Path

def cache_root():
    if sys.platform=='darwin':return Path.home()/'Library/Caches'
    if sys.platform=='win32':return Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData/Local'))/'Cache'
    return Path(os.environ.get('XDG_CACHE_HOME',Path.home()/'.cache'))

def state_root():
    if sys.platform=='darwin':return Path.home()/'Library/Logs'
    if sys.platform=='win32':return Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData/Local'))
    return Path(os.environ.get('XDG_STATE_HOME',Path.home()/'.local/state'))
