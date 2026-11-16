"""Short pauses between sections of terminal output so it can be read as it appears."""
import time

_enabled = True


def set_enabled(enabled):
    """Turns pauses on or off (main.py turns them off for --no-delay)."""
    global _enabled
    _enabled = enabled


def pause(seconds):
    if _enabled:
        time.sleep(seconds)
