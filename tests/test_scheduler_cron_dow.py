"""Regression test for B1: POSIX cron day_of_week 0 must mean Sunday.

Before the fix, scheduler.py parsed the dow field as 0-6 and compared
to datetime.weekday() (0=Mon … 6=Sun), so `0 3 * * 0` would never fire
on a Sunday — it fired on Monday. POSIX cron specifies 0=Sunday with
7 also accepted as Sunday.
"""
from datetime import datetime

from wpsecscan import scheduler


# 2026-05-31 is a Sunday; 2026-05-25 is Monday.
SUNDAY    = datetime(2026, 5, 31, 3, 0)
MONDAY    = datetime(2026, 5, 25, 3, 0)
TUESDAY   = datetime(2026, 5, 26, 3, 0)
SATURDAY  = datetime(2026, 5, 30, 3, 0)


def test_dow_0_fires_on_sunday():
    """`0 3 * * 0` must fire Sunday — not Monday."""
    assert scheduler.matches("0 3 * * 0", SUNDAY) is True
    assert scheduler.matches("0 3 * * 0", MONDAY) is False


def test_dow_7_also_fires_on_sunday():
    """POSIX cron allows 7 as Sunday too."""
    assert scheduler.matches("0 3 * * 7", SUNDAY) is True
    assert scheduler.matches("0 3 * * 7", MONDAY) is False


def test_dow_1_fires_on_monday():
    """Monday is 1 in POSIX cron."""
    assert scheduler.matches("0 3 * * 1", MONDAY) is True
    assert scheduler.matches("0 3 * * 1", TUESDAY) is False


def test_dow_6_fires_on_saturday():
    """Saturday is 6 in POSIX cron."""
    assert scheduler.matches("0 3 * * 6", SATURDAY) is True
    assert scheduler.matches("0 3 * * 6", SUNDAY) is False


def test_dow_range_includes_endpoints():
    """`0-5` should be Sun–Fri inclusive."""
    assert scheduler.matches("0 3 * * 0-5", SUNDAY) is True   # Sunday
    assert scheduler.matches("0 3 * * 0-5", MONDAY) is True   # Monday
    assert scheduler.matches("0 3 * * 0-5", SATURDAY) is False  # Saturday excluded


def test_dow_star_fires_every_day():
    """`* * * * *` (with matching minute/hour) fires regardless of dow."""
    for d in (SUNDAY, MONDAY, TUESDAY, SATURDAY):
        assert scheduler.matches("0 3 * * *", d) is True


def test_dow_list_fires_on_listed_days():
    """`0,3` should fire on Sunday and Wednesday only."""
    WEDNESDAY = datetime(2026, 5, 27, 3, 0)
    assert scheduler.matches("0 3 * * 0,3", SUNDAY) is True
    assert scheduler.matches("0 3 * * 0,3", WEDNESDAY) is True
    assert scheduler.matches("0 3 * * 0,3", MONDAY) is False
