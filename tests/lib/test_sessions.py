import datetime

import freezegun


def fromtimestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, tz=datetime.UTC)


def test_extend(session_factory):
    now = 1719057600
    with freezegun.freeze_time(fromtimestamp(now)):
        session = session_factory(duration_in_mins=3)
        assert session.expires_at == (now + 3 * 60)

    now += 60
    with freezegun.freeze_time(fromtimestamp(now)):
        session.extend(by_mins=1, up_to_mins=3)
        assert session.expires_at == (now + 60)

    now += 61
    with freezegun.freeze_time(fromtimestamp(now)):
        session.extend(by_mins=1, up_to_mins=3)
        # limit is 3 minutes, but we're now 2 mins and 1 sec in to the
        # session, so we only extend by 59 secs.
        assert session.expires_at == (now + 59)
