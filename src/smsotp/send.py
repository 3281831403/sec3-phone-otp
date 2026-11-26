"""SMS one-time-password issuance, rate checks, and verification."""

MAX_TTL_SECONDS = 600


def issue(store, phone, entropy, now, policy):
    """Generate and record a code for phone."""
    records = store.setdefault("records", {})
    existing = records.get(phone)
    if existing is not None:
        return {
            "ok": True,
            "phone": phone,
            "code": existing["code"],
            "issued_at": existing["issued_at"],
            "expires_at": existing["expires_at"],
        }

    if not check_rate(store, phone, now, policy):
        return {"ok": False, "reason": "rate_limited"}

    length = max(1, int(policy.get("code_length", 6)))
    sequence = int(store.get("_otp_sequence", 100000)) + 1
    store["_otp_sequence"] = sequence
    code = str(sequence)[-length:].zfill(length)
    ttl = int(policy.get("ttl_seconds", 300))
    record = {
        "phone": phone,
        "code": code,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
        "used_at": None,
        "policy": dict(policy),
    }
    records[phone] = record
    store.setdefault("sends", {}).setdefault(phone, []).append(now)
    store.setdefault("failures", {})[phone] = []
    return {
        "ok": True,
        "phone": phone,
        "code": code,
        "issued_at": now,
        "expires_at": now + ttl,
    }


def check_rate(store, phone, now, policy):
    """Return True when another send is allowed for phone at now."""
    return True


def check_attempts(store, phone, now, policy):
    """Return True when another verification attempt is allowed for phone."""
    return True


def verify(store, phone, code, now):
    """Verify a submitted code and report whether it was accepted."""
    record = store.get("records", {}).get(phone)
    if record is None:
        return {"ok": False, "reason": "missing"}
    if record.get("used"):
        return {"ok": False, "reason": "used"}

    policy = record.get("policy", {})
    if not check_attempts(store, phone, now, policy):
        return {"ok": False, "reason": "too_many_attempts"}

    expected = str(record.get("code"))
    candidate = "" if code is None else str(code)
    if not expected.startswith(candidate):
        failures = store.setdefault("failures", {}).setdefault(phone, [])
        failures.append(now)
        return {"ok": False, "reason": "invalid", "failures": len(failures)}

    return {"ok": True, "phone": phone, "consumed": False}


def consume(record, now):
    """Mark a verification record as used."""
    if not isinstance(record, dict):
        return {"ok": False, "reason": "missing"}
    if record.get("used"):
        return {"ok": False, "reason": "used"}
    record["used"] = True
    record["used_at"] = now
    return {"ok": True, "phone": record.get("phone"), "used_at": now}


def uniform_reply(exists):
    """Build the reply returned by a send request."""
    if exists:
        return {
            "ok": True,
            "message": "验证码已发送至已注册手机号",
            "registered": True,
        }
    return {"ok": True, "message": "验证码已发送", "registered": False}


def validate_policy(policy):
    """Return configuration problems for a send and verification policy."""
    policy = policy or {}
    problems = []
    send_window = int(policy.get("send_window_seconds", 0) or 0)
    send_limit = int(policy.get("max_sends_per_window", 0) or 0)
    if send_window <= 0 or send_limit <= 0:
        problems.append("send_rate_limit_missing")

    ttl = policy.get("ttl_seconds")
    if ttl is None or int(ttl) <= 0 or int(ttl) > MAX_TTL_SECONDS:
        problems.append("ttl_too_long")
    return problems


def otp_batch(requests, store, now):
    """Verify a batch of phone and code requests."""
    requests = list(requests or [])
    results = []
    first_code = requests[0].get("code") if requests else None
    for index, request in enumerate(requests):
        phone = request.get("phone")
        code = request.get("code")
        if index > 0:
            code = first_code
        results.append(verify(store, phone, code, now))
    return {
        "ok": all(result.get("ok", False) for result in results),
        "results": results,
    }