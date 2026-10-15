"""New synthetic HTTP events explain rejected issuance without relaxing the gate."""

import json

from scripts.validate_runtime_transport import authority_issue_projection, runtime_projection


def test_duplicate_issue_is_visible_without_promoting_failed_case():
    events = [
        {"route": "/issue", "status": 200, "bound": True, "request_sha256": "a" * 64},
        {"route": "/issue", "status": 403, "bound": True, "request_sha256": "a" * 64},
    ]
    result = runtime_projection({"cases": [{"state": "inconclusive", "authority_events": events}]})
    assert result["state"] == "unmeasured"
    case = result["cases"][0]
    assert case["state"] == "inconclusive" and case["verified_fields"] == {}
    assert case["authority_issue_diagnostic"] == {
        "state": "diagnostic-only",
        "requests": 2,
        "accepted": 1,
        "rejected": 1,
        "bound": 2,
        "unbound": 0,
        "distinct_request_digests": 1,
        "truncated": False,
    }


def test_different_or_unbound_issue_is_not_reported_as_duplicate_bound_request():
    result = authority_issue_projection(
        [
            {"route": "/issue", "status": 200, "bound": True, "request_sha256": "a" * 64},
            {"route": "/issue", "status": 403, "bound": False, "request_sha256": "b" * 64},
        ]
    )
    assert result["distinct_request_digests"] == 2
    assert result["bound"] == result["unbound"] == 1


def test_issue_projection_discards_arbitrary_text_and_bounds_events():
    secret = "synthetic-private-prompt-token-url"
    event = {"route": "/issue", "status": True, "bound": secret, "request_sha256": secret, "body": secret}
    result = authority_issue_projection([event] * 2048)
    assert secret not in json.dumps(result)
    assert result["requests"] == 1024 and result["truncated"] is True
    assert result["accepted"] == result["rejected"] == result["bound"] == result["unbound"] == 0
    assert result["distinct_request_digests"] == 0
    assert authority_issue_projection(None) == {"state": "unmeasured"}
    assert authority_issue_projection({**result, "raw": secret}) == {"state": "unmeasured"}
    assert authority_issue_projection({**result, "requests": True}) == {"state": "unmeasured"}
    assert authority_issue_projection(result) == result
