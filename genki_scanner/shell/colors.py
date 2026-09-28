"""
ANSI color codes for terminal output.
Auto-disables on non-TTY (piped output / CI).
"""
import sys
import os

_NO_COLOR = os.environ.get("NO_COLOR") or not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty()


def _c(code):
    if _NO_COLOR:
        return ""
    return f"\033[{code}m"


# Reset
RST = _c(0)

# Regular
BLK = _c(30)
RED = _c(31)
GRN = _c(32)
YLW = _c(33)
BLU = _c(34)
MAG = _c(35)
CYN = _c(36)
WHT = _c(37)

# Bright
BRED = _c(91)
BGRN = _c(92)
BYLW = _c(93)
BBLU = _c(94)
BMAG = _c(95)
BCYN = _c(96)
BWHT = _c(97)

# Styles
BOLD = _c(1)
DIM = _c(2)
UND = _c(4)

# Background
BG_RED = _c(41)
BG_GRN = _c(42)
BG_YLW = _c(43)


def sev_color(sev_str):
    """Return color code for a severity label."""
    s = sev_str.upper() if isinstance(sev_str, str) else ""
    if s in ("CRITICAL", "CRIT"):
        return BRED
    if s == "HIGH":
        return RED
    if s in ("MEDIUM", "MED"):
        return YLW
    if s == "LOW":
        return CYN
    return DIM  # INFO


def ok(text):
    return f"{BGRN}{text}{RST}"


def err(text):
    return f"{BRED}{text}{RST}"


def warn(text):
    return f"{YLW}{text}{RST}"


def info(text):
    return f"{CYN}{text}{RST}"


def dim(text):
    return f"{DIM}{text}{RST}"


def bold(text):
    return f"{BOLD}{text}{RST}"


def sev(label):
    """Colorize a severity label."""
    return f"{sev_color(label)}{label}{RST}"
