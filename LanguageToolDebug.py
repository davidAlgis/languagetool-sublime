# -*- coding: utf-8 -*-
"""
Small helper used by LanguageTool.py to log internal information
to the Sublime Text console.  Compatible with ST2 (Python 2.6)
and ST3 ≤ 4103 (Python 3.3, no f-strings).

Add `"debug": true` to *LanguageTool.sublime-settings*
to see the messages.
"""
import time

import sublime


def _get_settings():
    # Late import to avoid circular reference if the main file
    # has not finished loading yet.
    from .settings import languageToolSettings

    return languageToolSettings()


def log(msg, view=None, truncate_at=200):
    """Print a time-stamped message in the ST console."""
    settings = _get_settings()
    if not settings.get("debug", False):
        return

    if view is not None:
        buf_name = view.file_name() or "untitled"
        header = "[LanguageTool][{}] {} | ".format(
            time.strftime("%H:%M:%S"), buf_name
        )
    else:
        header = "[LanguageTool][{}] ".format(time.strftime("%H:%M:%S"))

    # Hard truncate extremely long payloads
    if isinstance(msg, str):  # ST2
        u_msg = msg[:truncate_at] + (" …" if len(msg) > truncate_at else "")
    else:  # ST3
        u_msg = msg[:truncate_at] + (" …" if len(msg) > truncate_at else "")

    print(header + u_msg)
