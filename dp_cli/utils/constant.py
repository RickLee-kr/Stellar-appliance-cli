from __future__ import annotations

try:
    from zoneinfo import available_timezones
    ALL_TIMEZONES = frozenset(available_timezones())
except Exception:
    ALL_TIMEZONES = frozenset()
