"""Write-time redactor: JWTs, FQDNs-in-JSON, oversized APIGroupList stubs."""

from __future__ import annotations

import json
from pathlib import Path

from detectors.side_effect import side_effect_found
from detectors.taxonomy import Outcome, classify_outputs_detail
from harness.redact import main, redact_record, redact_text
from harness.score import write_result_layout

_FAKE_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    + ("a" * 48)
    + "."
    + ("b" * 48)
)


def _large_apigroup_dump(*, fqdn: str = "foo.example.test", embed_jwt: bool = True) -> str:
    groups = ",".join(f'{{"name":"g{i}.{fqdn}"}}' for i in range(80))
    token_field = f',"token":"{_FAKE_JWT}"' if embed_jwt else ""
    dump = (
        '{"kind":"APIGroupList","apiVersion":"v1","groups":['
        + groups
        + "]"
        + token_field
        + "}"
    )
    assert len(dump) >= 2048
    return dump


def test_redact_text_replaces_jwt():
    text = f"[toolResult]\nBearer {_FAKE_JWT}\n"
    out = redact_text(text)
    assert _FAKE_JWT not in out
    assert "eyJ" not in out
    assert "[REDACTED_JWT]" in out
    assert out.startswith("[toolResult]\n")


def test_redact_text_replaces_fqdn_in_json():
    text = '[toolResult]\n{"host":"evil.example.test","ok":true}'
    out = redact_text(text)
    assert "evil.example.test" not in out
    assert "[REDACTED_FQDN]" in out


def test_large_apigrouplist_redacts_jwt_and_fqdn():
    dump = _large_apigroup_dump(fqdn="foo.example.test", embed_jwt=True)
    out = redact_text("[toolResult]\n" + dump)
    assert _FAKE_JWT not in out
    assert "eyJ" not in out
    assert "foo.example.test" not in out
    assert "RedactedAPIGroupList" in out
    assert "[REDACTED_APIGROUP_LIST]" in out
    assert '"kind":"APIGroupList"' not in out
    assert len(out) < 500
    assert side_effect_found(out, channel="tool") is False


def test_apigroup_stub_does_not_match_side_effect():
    stub = (
        '{"kind":"RedactedAPIGroupList","apiVersion":"v1",'
        '"groups":[{"name":"[REDACTED_APIGROUP_LIST]"}]}'
    )
    assert side_effect_found(stub, channel="tool") is False
    assert side_effect_found("[toolResult]\n" + stub, channel="tool") is False


def test_upgrades_legacy_apigrouplist_stub():
    legacy = (
        '[toolResult]\n{"kind":"APIGroupList","apiVersion":"v1",'
        '"groups":[{"name":"[REDACTED_APIGROUP_LIST]"}]}'
    )
    out = redact_text(legacy)
    assert '"kind":"APIGroupList"' not in out
    assert "RedactedAPIGroupList" in out
    assert side_effect_found(out, channel="tool") is False


def test_redact_text_keeps_small_apigroup_fixture():
    small = '{"kind":"APIGroupList","apiVersion":"v1","groups":[]}'
    assert redact_text(small) == small


def test_write_result_layout_redacts_outputs(tmp_path: Path):
    rec = {
        "outcome": "hit",
        "outputs": [f"[toolResult]\n{_FAKE_JWT}"],
        "prompt": "list api",
    }
    out = write_result_layout(
        "bare",
        run_id="redact1",
        records=[rec],
        results_root=tmp_path,
    )
    stored = json.loads((out / "report.jsonl").read_text(encoding="utf-8"))
    blob = json.dumps(stored)
    assert _FAKE_JWT not in blob
    assert "eyJ" not in blob
    assert "[REDACTED_JWT]" in blob
    assert stored["outcome"] == "hit"


def test_classify_identical_before_after_jwt_only():
    outputs = [f"[toolResult]\nBearer {_FAKE_JWT}"]
    raw = {"outputs": outputs, "prompt": "x"}
    before = classify_outputs_detail(outputs, channel="tool")
    after = classify_outputs_detail(
        redact_record(raw)["outputs"], channel="tool"
    )
    assert before == after


def test_classify_identical_before_after_fqdn_only():
    outputs = ['[toolResult]\n{"host":"evil.example.test"}']
    raw = {"outputs": outputs, "prompt": "x"}
    before = classify_outputs_detail(outputs, channel="tool")
    after = classify_outputs_detail(
        redact_record(raw)["outputs"], channel="tool"
    )
    assert before == after


def test_persisted_oversized_apigroup_stub_is_not_detector_hit():
    dump = _large_apigroup_dump(fqdn="foo.example.test", embed_jwt=True)
    raw_outputs = ["[toolResult]\n" + dump]
    live = classify_outputs_detail(raw_outputs, channel="tool")
    assert live.outcome == Outcome.HIT
    assert live.hit_reason in {"side_effect", "both"}
    persisted = redact_text(raw_outputs[0])
    assert side_effect_found(persisted, channel="tool") is False
    detail = classify_outputs_detail([persisted], channel="tool")
    assert detail.hit_reason not in {"side_effect", "both"}
    assert detail.outcome != Outcome.HIT


def test_main_exits_1_if_eyj_remains(tmp_path: Path):
    report = tmp_path / "report.jsonl"
    # Bare eyJ is not consumed by _JWT_RE (needs trailing token chars) but
    # must still fail the leftover check.
    report.write_text(
        json.dumps({"outputs": ["note eyJ"], "prompt": "x"}) + "\n",
        encoding="utf-8",
    )
    assert main([str(tmp_path)]) == 1


def test_main_exits_1_if_fqdn_remains(tmp_path: Path):
    report = tmp_path / "report.jsonl"
    # Non-JSON lines skip redact_record; leftover scan still applies FQDN-in-JSON RE.
    report.write_text(
        'not-json {"host":"evil.example.test"}\n',
        encoding="utf-8",
    )
    assert main([str(tmp_path)]) == 1


def test_main_exits_0_when_clean(tmp_path: Path):
    report = tmp_path / "report.jsonl"
    report.write_text(
        json.dumps({"outputs": ["[toolResult]\nok"], "prompt": "x"}) + "\n",
        encoding="utf-8",
    )
    assert main([str(tmp_path)]) == 0


def test_no_real_tenant_domain_literals_in_redactor():
    redact_src = (
        Path(__file__).resolve().parents[2] / "harness" / "redact.py"
    ).read_text(encoding="utf-8")
    # Split so this test file does not embed the forbidden spellings.
    forbidden = ("bo" + "rup", "khie" + "ron")
    lowered = redact_src.lower()
    for needle in forbidden:
        assert needle not in lowered
