"""Path handling that depends on the PATH, not on the host running the monitor.

Policy rules and events carry paths written for the platform the agent runs
on. `os.path` answers for the host instead, and on POSIX it does not treat a
backslash as a separator at all -- so `C:\\Windows\\System32\\cmd.exe` had no
basename, and a Windows workspace rule evaluated on a Linux host reported every
write inside the workspace as "outside".

The rule here: a path that is unmistakably Windows-shaped (a drive letter, a
UNC prefix, or any backslash) is handled with `ntpath` wherever the monitor
runs. Anything else uses the host's `os.path`, which keeps behaviour on each
platform exactly what it was for its own native paths.
"""

from __future__ import annotations

import ntpath
import os
import re

_WINDOWS_SHAPED = re.compile(r"^(?:[A-Za-z]:|\\\\)|\\")


def flavor(p: str):
    """The path module that understands `p`."""
    return ntpath if _WINDOWS_SHAPED.search(p or "") else os.path


def norm(p: str) -> str:
    """normpath + normcase in the path's own flavor.

    normcase lowercases and unifies separators for Windows paths, so
    containment is not one capital letter from being bypassed on NTFS. It is
    identity for POSIX paths.
    """
    f = flavor(p)
    return f.normcase(f.normpath(p))


def normpath(p: str) -> str:
    """normpath only -- for comparisons that must stay case-sensitive."""
    return flavor(p).normpath(p)


def basename(p: str) -> str:
    return flavor(p).basename(p)


def sep_for(p: str) -> str:
    return flavor(p).sep
