"""The eval harness refuses to report numbers from a run with failed calls.

On 2026-10-08 the API credit ran out partway through a 3+3 eval. Every
call after that failed, the verdict agents fell back to the raw findings,
and the harness printed precision/recall/cost as if nothing had happened:
recall looked fine (a raw finding still "confirms" a planted issue), cost
looked low, dismissals quietly vanished. Numbers like that are worse than
none.

Now:
  * the first auth or credit error (401/402/403, or a credit-balance
    message) aborts the whole harness with exit code 2;
  * any other failed call (timeout, 5xx) withholds that run's metrics and
    exits 1.

Mocked client throughout. No live calls.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from codeguard.pipeline import nodes
from codeguard.pipeline.llm_call import AgentCallResult

_PATH = Path(__file__).resolve().parents[2] / "evals" / "run_full_harness.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_full_harness", _PATH)
    mod = importlib.util.module_from_spec(spec)
    # Registered before it runs: @dataclass resolves its module through
    # sys.modules, and a fresh copy per test keeps the globals clean.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


CREDIT = ("Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
          "'message': 'Your credit balance is too low to access the Anthropic API.'}}")


def _agent_result(r=1.0):
    return {"precision": r, "recall": r, "f1": r, "dismissal_accuracy": None, "tp": 1, "fp": 0, "fn": 0,
            "tokens_in": 10, "tokens_out": 5, "cost_usd": 0.01, "latency_s": 0.1, "agent": "x", "n_fixtures": 1}


def _fake_run_once(calls_per_run=3):
    """Stands in for run_once: makes calls through nodes.call_agent (which
    the harness has wrapped) and returns a well-formed run."""
    def run_once():
        for _ in range(calls_per_run):
            nodes.call_agent(agent="security", api_key="", system_prompt="", repo_context="",
                             user_content="", model="m", max_tokens=1, timeout=1)
        return {a: _agent_result() for a in ("ai_aware", "security", "quality", "test")} | {
            "per_pr_tokens": 60, "per_pr_cost_usd": 0.04, "per_pr_latency_s": 0.4}
    return run_once


def _client(errors):
    """A call_agent whose Nth call returns errors[N] (None = success)."""
    calls = []

    def call_agent(**kwargs):
        calls.append(kwargs["agent"])
        err = errors[len(calls) - 1] if len(calls) - 1 < len(errors) else None
        return AgentCallResult(raw_text=None if err else "[]", error=err, tokens_in=1, tokens_out=1)
    call_agent.calls = calls
    return call_agent


@pytest.mark.parametrize("error", [
    CREDIT,
    "Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'invalid x-api-key'}}",
    "Error code: 402 - payment required",
    "Error code: 403 - {'type': 'error', 'error': {'type': 'permission_error'}}",
])
def test_an_auth_or_credit_error_aborts_on_the_first_call(monkeypatch, capsys, error):
    harness = _load()
    client = _client([error])
    monkeypatch.setattr(nodes, "call_agent", client)
    monkeypatch.setattr(harness, "run_once", _fake_run_once())

    with pytest.raises(SystemExit) as exc:
        harness.main(["--runs", "3"])

    assert exc.value.code == 2
    assert len(client.calls) == 1, "nothing after the first fatal error"
    out = capsys.readouterr().out
    assert "precision=" not in out
    assert "aborting" in out.lower()


def test_a_run_with_any_failed_call_reports_no_metrics(monkeypatch, capsys):
    harness = _load()
    monkeypatch.setattr(nodes, "call_agent", _client([None, "APITimeoutError: request timed out"]))
    monkeypatch.setattr(harness, "run_once", _fake_run_once())

    with pytest.raises(SystemExit) as exc:
        harness.main(["--runs", "3"])

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "precision=" not in out
    assert "per_pr_cost_usd" not in out
    assert "1 failed call" in out


def test_a_clean_run_reports_as_before(monkeypatch, capsys):
    harness = _load()
    monkeypatch.setattr(nodes, "call_agent", _client([]))
    monkeypatch.setattr(harness, "run_once", _fake_run_once())

    harness.main(["--runs", "2"])

    out = capsys.readouterr().out
    assert out.count("precision=") == 8
    assert "per_pr_cost_usd" in out
