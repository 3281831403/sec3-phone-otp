"""SMS one-time-password issuance, rate checks, and verification.

Server-side security contract:

* every accepted send generates a fresh, unpredictable code;
* sends for one phone are bounded by a sliding time window / count;
* verification failures for one phone are bounded by a sliding window;
* a code is consumed successfully exactly once, and only before expiry;
* expired, used, missing and incorrect codes are all rejected;
* the send reply is identical for registered and unregistered phones;
* batch entries are verified independently with their own phone/code.
"""

import hmac
import random as _random
import secrets
import time

MAX_TTL_SECONDS = 600
DEFAULT_TTL_SECONDS = 300
DEFAULT_CODE_LENGTH = 6


def _current_time(now):
    """Use the caller's clock reading, falling back to server time."""
    return time.time() if now is None else now


def _int_setting(policy, key, default):
    """Read an int setting, returning default when the value is unusable."""
    try:
        value = policy.get(key, default)
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError, AttributeError):
        return default


def _randbelow(entropy, bound):
    """Draw an integer in ``[0, bound)`` from the supplied entropy source.

    Tests inject a seeded :class:`random.Random`; production callers that pass
    ``None`` get a cryptographically unpredictable draw from :mod:`secrets`.
    """
    if bound <= 0:
        return 0
    if entropy is None:
        return secrets.randbelow(bound)
    if isinstance(entropy, int) and not isinstance(entropy, bool):
        entropy = _random.Random(entropy)

    randrange = getattr(entropy, "randrange", None)
    if callable(randrange):
        return randrange(bound)

    randbelow = getattr(entropy, "randbelow", None)
    if callable(randbelow):
        return randbelow(bound)

    randint = getattr(entropy, "randint", None)
    if callable(randint):
        return randint(0, bound - 1)

    getrandbits = getattr(entropy, "getrandbits", None)
    if callable(getrandbits):
        return getrandbits(bound.bit_length()) % bound

    return secrets.randbelow(bound)


def _new_code(entropy, length):
    """Return a zero-padded ``length``-digit numeric code."""
    length = max(1, int(length))
    return str(_randbelow(entropy, 10 ** length)).zfill(length)


def _count_in_window(timestamps, now, window):
    """Count timestamps inside the sliding window of ``window`` seconds."""
    if window <= 0:
        return 0
    return sum(1 for stamp in timestamps if now - stamp < window)


def issue(store, phone, entropy, now, policy):
    """Generate and record a fresh code for ``phone``.

    Every accepted send replaces the previous record, so a code is never
    handed out twice and an old code cannot survive a re-send.
    """
    now = _current_time(now)
    policy = dict(policy or {})

    if not check_rate(store, phone, now, policy):
        return {"ok": False, "reason": "rate_limited"}

    length = max(1, _int_setting(policy, "code_length", DEFAULT_CODE_LENGTH))
    code = _new_code(entropy, length)
    ttl = _int_setting(policy, "ttl_seconds", DEFAULT_TTL_SECONDS)

    record = {
        "phone": phone,
        "code": code,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
        "used_at": None,
        "policy": policy,
    }
    store.setdefault("records", {})[phone] = record
    store.setdefault("sends", {}).setdefault(phone, []).append(now)
    # Keep the cumulative failure history; the sliding window in
    # check_attempts decides whether the budget is exhausted.
    store.setdefault("failures", {}).setdefault(phone, [])
    return {
        "ok": True,
        "phone": phone,
        "code": code,
        "issued_at": now,
        "expires_at": now + ttl,
    }


def check_rate(store, phone, now, policy):
    """Return True when another send is allowed for phone at now.

    A missing or non-positive rate configuration fails closed: it never grants
    an unlimited sending allowance.
    """
    now = _current_time(now)
    policy = policy or {}
    window = _int_setting(policy, "send_window_seconds", 0)
    limit = _int_setting(policy, "max_sends_per_window", 0)
    if window <= 0 or limit <= 0:
        return False

    sends = store.get("sends", {}).get(phone, [])
    return _count_in_window(sends, now, window) < limit


def check_attempts(store, phone, now, policy):
    """Return True when another verification attempt is allowed for phone."""
    now = _current_time(now)
    policy = policy or {}
    window = _int_setting(policy, "attempt_window_seconds", 0)
    limit = _int_setting(policy, "max_attempts", 0)
    if window <= 0 or limit <= 0:
        return False

    failures = store.get("failures", {}).get(phone, [])
    return _count_in_window(failures, now, window) < limit


def _codes_match(expected, candidate):
    """Constant-time, exact code comparison (prefixes never match)."""
    expected_bytes = str(expected).encode("utf-8")
    candidate_bytes = str(candidate).encode("utf-8")
    return hmac.compare_digest(expected_bytes, candidate_bytes)


def verify(store, phone, code, now):
    """Verify a submitted code and consume it on the first success.

    The decision order is fixed so callers always get a precise reason and a
    correct code can never bypass expiry or the attempt lockout.
    """
    now = _current_time(now)
    record = store.get("records", {}).get(phone)
    if not isinstance(record, dict):
        return {"ok": False, "reason": "missing"}

    if record.get("used"):
        return {"ok": False, "reason": "used"}

    policy = record.get("policy") or {}

    expires_at = record.get("expires_at")
    if expires_at is None:
        ttl = _int_setting(policy, "ttl_seconds", DEFAULT_TTL_SECONDS)
        expires_at = record.get("issued_at", 0) + ttl
    if now >= expires_at:
        return {"ok": False, "reason": "expired"}

    if not check_attempts(store, phone, now, policy):
        return {"ok": False, "reason": "too_many_attempts"}

    expected = record.get("code", "")
    candidate = "" if code is None else code
    if not _codes_match(expected, candidate):
        failures = store.setdefault("failures", {}).setdefault(phone, [])
        failures.append(now)
        return {"ok": False, "reason": "invalid", "failures": len(failures)}

    consumed = consume(record, now)
    if not consumed.get("ok"):
        return {"ok": False, "reason": consumed.get("reason", "used")}
    return {"ok": True, "phone": phone, "consumed": True}


def consume(record, now):
    """Mark a verification record as used, at most once."""
    if not isinstance(record, dict):
        return {"ok": False, "reason": "missing"}
    if record.get("used"):
        return {"ok": False, "reason": "used"}
    record["used"] = True
    record["used_at"] = _current_time(now)
    return {
        "ok": True,
        "phone": record.get("phone"),
        "used_at": record["used_at"],
    }


def uniform_reply(exists):
    """Build the reply returned by a send request.

    The payload is deliberately independent of ``exists`` so an enumerator
    cannot distinguish registered from unregistered phone numbers.
    """
    del exists
    return {"ok": True, "message": "验证码已发送"}


def validate_policy(policy):
    """Return configuration problems for a send and verification policy."""
    policy = policy or {}
    problems = []

    send_window = _int_setting(policy, "send_window_seconds", 0)
    send_limit = _int_setting(policy, "max_sends_per_window", 0)
    if send_window <= 0 or send_limit <= 0:
        problems.append("send_rate_limit_missing")

    attempt_window = _int_setting(policy, "attempt_window_seconds", 0)
    attempt_limit = _int_setting(policy, "max_attempts", 0)
    if attempt_window <= 0 or attempt_limit <= 0:
        problems.append("attempt_limit_missing")

    ttl = _int_setting(policy, "ttl_seconds", 0)
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        problems.append("ttl_too_long")

    return problems


def otp_batch(requests, store, now):
    """Verify a batch, each item against its own phone and code.

    Entries are processed independently and sequentially: a successful entry
    consumes its own code, so repeating the same phone/code later in the same
    batch is correctly rejected as re-use rather than shared.
    """
    requests = list(requests or [])
    results = []
    for request in requests:
        if not isinstance(request, dict):
            request = {}
        results.append(
            verify(store, request.get("phone"), request.get("code"), now)
        )
    return {
        "ok": all(result.get("ok", False) for result in results),
        "results": results,
    }
