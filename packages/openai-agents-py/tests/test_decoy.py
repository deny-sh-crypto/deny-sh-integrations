import asyncio
import http.server
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import BaseModel

from deny_sh_openai_agents import (
    DenyDecoyLeakError,
    DenyToolError,
    create_decoy_watch,
)


DECOY = "decoy-value-1234"


def test_published_typescript_vectors():
    vectors = json.loads((Path(__file__).parent / "decoy_vectors.json").read_text())
    watch = create_decoy_watch(vectors["decoys"], report=False, block=False)
    assert watch.fingerprints() == vectors["fingerprints"]
    for case in vectors["cases"]:
        actual = [
            (hit.encoding, hit.surface, hit.fingerprint, hit.label)
            for hit in watch.scan(case["value"], case["surface"])
        ]
        expected = [
            (
                hit["encoding"],
                hit["surface"],
                hit["fingerprint"],
                hit.get("label"),
            )
            for hit in case["expected"]
        ]
        assert actual == expected, case["name"]


def test_short_decoy_and_leaking_label_rejected():
    with pytest.raises(DenyToolError) as error:
        create_decoy_watch(["short"])
    assert error.value.code == "deny_config_error"
    with pytest.raises(DenyToolError) as error:
        create_decoy_watch([{"value": DECOY, "label": "x " + DECOY}])
    assert error.value.code == "deny_config_error"
    assert DECOY not in str(error.value)


def test_nested_python_containers_dataclass_pydantic_and_bytes():
    @dataclass
    class Carrier:
        value: str

    class Model(BaseModel):
        value: str

    values = {
        "dict": {"value": DECOY},
        "list": [DECOY],
        "tuple": (DECOY,),
        "set": {DECOY},
        "dataclass": Carrier(DECOY),
        "pydantic": Model(value=DECOY),
        "bytes": DECOY.encode(),
    }
    watch = create_decoy_watch([DECOY], report=False, block=False)
    for name, value in values.items():
        assert len(watch.scan(value)) == 1, name


def test_scanner_skips_raising_property_and_finds_other_fields():
    class Carrier:
        def __init__(self):
            self.safe = DECOY

        @property
        def hostile(self):
            raise RuntimeError(DECOY)

    watch = create_decoy_watch([DECOY], report=False)
    assert len(watch.scan(Carrier())) == 1
    with pytest.raises(DenyDecoyLeakError) as error:
        watch.check(Carrier())
    assert DECOY not in str(error.value)


def test_scanner_skips_mapping_with_raising_items():
    class HostileMapping(Mapping):
        def __getitem__(self, key):
            raise KeyError(key)

        def __iter__(self):
            return iter(())

        def __len__(self):
            return 0

        def items(self):
            raise RuntimeError(DECOY)

    watch = create_decoy_watch([DECOY], report=False, block=False)
    assert watch.scan(HostileMapping()) == []


def test_scanner_depth_limit_prevents_recursion_error():
    value = []
    for _ in range(10_000):
        value = [value]
    watch = create_decoy_watch([DECOY], report=False, block=False)
    assert watch.scan(value) == []


def test_scanner_cyclic_structure_terminates():
    value = []
    value.append(value)
    value.append(DECOY)
    watch = create_decoy_watch([DECOY], report=False, block=False)
    assert len(watch.scan(value)) == 1


def test_report_body_and_base_url_contain_no_decoy():
    calls = []

    def transport(url, headers, body, timeout):
        calls.append((url, headers, body, timeout))
        return 200

    watch = create_decoy_watch(
        [{"label": "demo", "value": DECOY}],
        api_key="test-key",
        base_url="https://example.invalid/api/",
        block=False,
        transport=transport,
    )
    hits = watch.check("out: " + DECOY, "model_output")
    assert len(hits) == 1
    url, headers, body_bytes, timeout = calls[0]
    assert url == "https://example.invalid/v1/decoy-tripwires/observe"
    body = json.loads(body_bytes)
    assert body == {
        "tripwire_hash": watch.fingerprints()[0],
        "surface": "model_output",
        "source": "deny-sh-openai-agents-py/0.2.0",
    }
    assert DECOY not in body_bytes.decode()
    assert headers["Authorization"] == "Bearer test-key"
    assert timeout == 3.0


def test_non_https_base_url_rejected_except_loopback():
    with pytest.raises(DenyToolError) as error:
        create_decoy_watch([DECOY], base_url="http://example.com", report=False)
    assert error.value.code == "deny_config_error"
    create_decoy_watch(
        [DECOY], base_url="http://127.0.0.1:12345", report=False
    )


def test_default_transport_does_not_follow_redirects():
    requests_seen = {"first": 0, "second": 0}
    failures = []

    class SecondHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests_seen["second"] += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    second = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SecondHandler)

    class FirstHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests_seen["first"] += 1
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{second.server_port}/redirected"
            )
            self.end_headers()

        def log_message(self, *_args):
            pass

    first = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FirstHandler)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (first, second)
    ]
    for thread in threads:
        thread.start()
    try:
        watch = create_decoy_watch(
            [DECOY],
            api_key="test-key",
            base_url=f"http://127.0.0.1:{first.server_port}/api",
            block=False,
            on_report_error=failures.append,
        )
        hit = watch.check(DECOY)[0]
    finally:
        first.shutdown()
        second.shutdown()
        first.server_close()
        second.server_close()
    assert requests_seen == {"first": 1, "second": 0}
    assert failures == [
        {"fingerprint": hit.fingerprint, "surface": "other", "status": 302}
    ]


def test_report_failure_is_swallowed_scrubbed_and_observed():
    failures = []

    def transport(_url, _headers, _body, _timeout):
        raise RuntimeError("offline for " + DECOY)

    watch = create_decoy_watch(
        [DECOY],
        api_key="test-key",
        block=False,
        transport=transport,
        on_report_error=failures.append,
    )
    hits = watch.check(DECOY, "model_output")
    assert len(hits) == 1
    assert failures == [
        {
            "fingerprint": hits[0].fingerprint,
            "surface": "model_output",
            "error": "offline for [deny:redacted]",
        }
    ]
    assert DECOY not in json.dumps(failures)


def test_non_2xx_report_reaches_error_observer():
    failures = []
    watch = create_decoy_watch(
        [DECOY],
        api_key="test-key",
        block=False,
        transport=lambda *_args: 503,
        on_report_error=failures.append,
    )
    hit = watch.check(DECOY, "tool_args")[0]
    assert failures == [
        {"fingerprint": hit.fingerprint, "surface": "tool_args", "status": 503}
    ]


def test_block_true_raises_scrubbed_error_after_on_leak():
    seen = []
    watch = create_decoy_watch([DECOY], report=False, on_leak=seen.append)
    with pytest.raises(DenyDecoyLeakError) as error:
        watch.check(DECOY, "tool_result")
    assert error.value.code == "deny_decoy_leak"
    assert DECOY not in str(error.value)
    assert len(seen) == 1


def test_block_false_returns_all_hits_and_calls_on_leak_once_each():
    seen = []
    watch = create_decoy_watch(
        [DECOY, "second-decoy-5678"],
        report=False,
        block=False,
        on_leak=seen.append,
    )
    hits = watch.check(DECOY + " second-decoy-5678", "tool_args")
    assert len(hits) == 2
    assert seen == hits


def test_arm_posts_plaintext_tripwire_per_fingerprint():
    calls = []

    def transport(url, _headers, body, _timeout):
        calls.append((url, json.loads(body)))
        return 200

    watch = create_decoy_watch(
        [{"value": DECOY, "label": "first"}, "second-decoy-5678"],
        api_key="test-key",
        base_url="https://example.invalid/api",
        report=False,
        transport=transport,
    )
    assert watch.arm() == {"armed": 2}
    assert [call[0] for call in calls] == [
        "https://example.invalid/v1/decoy-tripwires",
        "https://example.invalid/v1/decoy-tripwires",
    ]
    assert [call[1]["tripwire_kind"] for call in calls] == [
        "plaintext",
        "plaintext",
    ]
    assert [call[1]["tripwire_hash"] for call in calls] == watch.fingerprints()
    assert calls[0][1]["label"] == "first"


def test_no_report_when_disabled_or_key_unresolved(monkeypatch):
    monkeypatch.delenv("DENY_API_KEY", raising=False)
    calls = []
    transport = lambda *_args: calls.append(True) or 200
    create_decoy_watch(
        [DECOY], api_key="test-key", report=False, block=False, transport=transport
    ).check(DECOY)
    create_decoy_watch([DECOY], block=False, transport=transport).check(DECOY)
    assert calls == []


def test_acheck_runs_under_asyncio():
    watch = create_decoy_watch([DECOY], report=False, block=False)
    hits = asyncio.run(watch.acheck(DECOY, "model_output"))
    assert len(hits) == 1
    assert hits[0].surface == "model_output"
