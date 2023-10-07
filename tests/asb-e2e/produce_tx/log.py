from functools import partial

from datetime import datetime
import os
import sys

log_level = 9

def set_level(level):
    global log_level
    log_level = level

GRAY = "\033[90m"
GREEN = "\033[32m"
RED = "\033[91m"
WHITE = "\033[37m"
ORANGE = "\033[93m"
PURPLE = "\033[95m"
RESET = "\033[0m"

def supports_color():
    """
    Returns True if the running system's terminal supports color, and False otherwise.
    """
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    # Check for Windows.
    if os.name == "nt":
        return False
    # Check for MacOS and Linux.
    if sys.platform == "darwin" or sys.platform == "linux":
        return True
    return False

def _log(color, tag, *args, **kwargs):
    if supports_color():
        print(f"{color}{datetime.now().time()} [{tag}]", *args, RESET, **kwargs)
    else:
        print(f"{datetime.now().time()} [{tag}]", *args, **kwargs)

def log(level, *args, **kwargs):
    if level < log_level:
        return
    
    if level == 0:
        _log(GRAY, "DEBUG", *args, **kwargs)
    if level == 1:
        _log(WHITE, "INFO ", *args, **kwargs)
    if level == 2:
        _log(GREEN, "NOTIC", *args, **kwargs)
    if level == 3:
        _log(ORANGE, "WARN ", *args, **kwargs)
    if level == 4:
        _log(RED, "ERROR", *args, **kwargs)
    if level == 5:
        _log(PURPLE, "CRITI", *args, **kwargs)


def debug(*args, **kwargs):
    log(0, *args, **kwargs)

def info(*args, **kwargs):
    log(1, *args, **kwargs)

def notice(*args, **kwargs):
    log(2, *args, **kwargs)

def warn(*args, **kwargs):
    log(3, *args, **kwargs)

def error(*args, **kwargs):
    log(4, *args, **kwargs)

def critical(*args, **kwargs):
    log(5, *args, **kwargs)
