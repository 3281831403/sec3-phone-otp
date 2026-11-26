"""Public tests for the SMS OTP exercise."""

import random

from smsotp import check_rate, issue, otp_batch, verify


def _policy(**overrides):
    values = {
        "send_window_seconds": 60,
        "max_sends_per_window": 10,
        "attempt_window_seconds": 300,
        "max_attempts": 3,
        "ttl_seconds": 300,
        "code_length": 6,
    }
    values.update(overrides)
    return values


def test_issue_generates_fresh_six_digit_code():
    store = {}
    policy = _policy(max_sends_per_window=10)
    phone = "13800000001"

    first = issue(store, phone, random.Random(11), 100, policy)
    second = issue(store, phone, random.Random(12), 101, policy)

    assert first["ok"] is True
    assert second["ok"] is True
    assert first["code"].isdigit() and len(first["code"]) == 6
    assert second["code"].isdigit() and len(second["code"]) == 6
    assert first["code"] != second["code"]


def test_send_rate_limit_rejects_immediate_resend():
    store = {}
    policy = _policy(max_sends_per_window=1, send_window_seconds=60)
    phone = "13800000002"

    first = issue(store, phone, random.Random(21), 0, policy)
    second = issue(store, phone, random.Random(22), 1, policy)

    assert first["ok"] is True
    assert second["ok"] is False
    assert second.get("reason") == "rate_limited"
    assert check_rate(store, phone, 1, policy) is False


def test_verify_accepts_correct_code_and_consumes_it():
    store = {}
    policy = _policy()
    phone = "13800000003"

    issued = issue(store, phone, random.Random(31), 0, policy)
    result = verify(store, phone, issued["code"], 10)

    assert result["ok"] is True
    assert result["consumed"] is True
    assert store["records"][phone]["used"] is True


def test_verified_code_cannot_be_reused():
    store = {}
    policy = _policy()
    phone = "13800000004"

    issued = issue(store, phone, random.Random(41), 0, policy)
    first = verify(store, phone, issued["code"], 1)
    second = verify(store, phone, issued["code"], 2)

    assert first["ok"] is True
    assert second["ok"] is False
    assert second.get("reason") == "used"


def test_batch_requests_are_independent():
    store = {}
    policy = _policy(max_sends_per_window=10)
    first_phone = "13800000005"
    second_phone = "13800000006"

    first = issue(store, first_phone, random.Random(51), 0, policy)
    second = issue(store, second_phone, random.Random(52), 0, policy)
    result = otp_batch(
        [
            {"phone": first_phone, "code": first["code"]},
            {"phone": second_phone, "code": second["code"]},
        ],
        store,
        1,
    )

    assert result["ok"] is True
    assert [item["ok"] for item in result["results"]] == [True, True]