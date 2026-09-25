"""A credential in the audit target must not reach any sink.

`run_audit` is reached from three callers — the CLI, the MCP server's
audit_repo tool, and the dashboard's repo_audit job — and only the last
builds the URL itself. The other two pass through whatever the user
typed, and `https://<token>@github.com/owner/repo` is the ordinary way
to hand git a PAT.

Seven places the target reaches, two of which fire on SUCCESS rather
than failure:

  1. the "Cloning ..." stderr line           every remote audit
  2. "git clone failed: <git's stderr>"       clone failure
  3. "<target> is not a directory ..."        non-URL target
  4. the report's "# CodeGuard audit: ..."    every successful audit
  5. audits.report_markdown / audits.error    dashboard audit
  6. the worker's log line                    dashboard audit
  7. a GitHub Issue body via --post-issue     PUBLIC and PERMANENT

Sink 7 is why this is fixed at the source instead of in the one caller
that was already safe. git's own masking does not save us: it hides a
password-position credential in its errors and echoes a username-position
one verbatim.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from codeguard.cli import post_issue, render_report, run_audit
from codeguard.redact import redact

# Shaped like a real PAT (ghp_ + 36) so the vendor pattern applies, and
# long enough that the opaque-token net would catch it too. Not a real
# credential, and assembled rather than written out so secret scanning
# has nothing to match on.
TOKEN = "ghp_" + "b" * 36
CREDENTIALED = f"https://{TOKEN}@github.com/owner/repo.git"

# The password-position form, which git masks itself but we do not rely on.
CREDENTIALED_PASSWORD = f"https://x-access-token:{TOKEN}@github.com/owner/repo.git"


def _clone_fails(stderr: str = "nope"):
    return patch(
        "codeguard.cli._clone_shallow",
        side_effect=subprocess.CalledProcessError(128, "git", stderr=stderr),
    )


def test_the_cloning_line_does_not_echo_the_credential(capsys, tmp_path):
    """Sink 1, and the one that needed no failure at all: this printed on
    every remote audit, before anything could go wrong."""
    with _clone_fails():
        run_audit(CREDENTIALED, str(tmp_path / "out.md"), False)

    err = capsys.readouterr().err
    assert TOKEN not in err
    assert "Cloning" in err
    assert "[redacted]" in err


def test_a_clone_failure_does_not_return_the_credential(tmp_path):
    """Sink 2. git echoes a username-position credential in its own
    stderr — measured against git, not assumed — so the embedded stderr
    is redacted rather than trusted to have masked itself."""
    leaky = (
        f"fatal: could not read Password for 'https://{TOKEN}@github.com': "
        "terminal prompts disabled"
    )
    with _clone_fails(leaky):
        exit_code, error = run_audit(CREDENTIALED, str(tmp_path / "out.md"), False)

    assert exit_code == 1
    assert TOKEN not in error
    assert "[redacted]" in error


def test_the_password_form_is_also_redacted(tmp_path, capsys):
    """git masks this shape itself. Redacted anyway — relying on another
    tool's error formatting is not a security boundary."""
    with _clone_fails():
        _, error = run_audit(CREDENTIALED_PASSWORD, str(tmp_path / "out.md"), False)

    assert TOKEN not in error
    assert TOKEN not in capsys.readouterr().err


def test_a_non_directory_target_does_not_echo_the_credential(tmp_path):
    """Sink 3. Reached when the target is neither a URL nor a directory —
    a typo'd path that still carried a credential."""
    exit_code, error = run_audit(
        f"{TOKEN}@not-a-url-or-a-directory", str(tmp_path / "out.md"), False,
    )

    assert exit_code == 1
    assert TOKEN not in error


def test_the_report_title_does_not_carry_the_credential():
    """Sink 4, the other one that fired on success.

    render_report deliberately does NOT redact — it is a pure renderer,
    and run_audit hands it safe_target. This pins that split: the
    renderer passes its input through, and redact() is what makes the
    output safe. If redaction ever moves into render_report, the first
    assertion fails and says so.
    """
    report = render_report(
        target=CREDENTIALED, files_scanned=0, files_ai_aware=0,
        ai_reviewed_findings=[], passthrough_findings=[], dismissed=[],
        eval_hygiene_findings=[], osv_findings=[], skipped_files=[],
        verdict_call_failures=[], tokens_in=0, tokens_out=0,
        estimated_cost_usd=0.0, elapsed_s=0.0,
    )

    assert TOKEN in report, "render_report is a pure renderer; run_audit passes it safe_target"
    assert TOKEN not in redact(report)


def test_post_issue_redacts_the_body_it_publishes():
    """Sink 7. Public and permanent, so it does not trust its caller.

    An issue body is world-readable the instant it is created, is
    indexed, and survives deletion in GitHub's event stream. Every other
    sink is revocable in a way this one is not, which is the whole reason
    this redacts independently of run_audit.
    """
    captured = {}

    class _Resp:
        status_code = 201

        def raise_for_status(self):
            return None

        def json(self):
            return {"html_url": "https://github.com/o/r/issues/1"}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["body"] = json["body"]
        return _Resp()

    with patch("codeguard.cli.requests.post", side_effect=fake_post):
        post_issue("tok", "o", "r", f"# CodeGuard audit: {CREDENTIALED}\n\nnothing found")

    assert TOKEN not in captured["body"]
    assert "[redacted]" in captured["body"]


def test_the_real_target_still_reaches_git(tmp_path):
    """The redaction must not break the feature it protects: git needs
    the actual credential to clone a private repository."""
    seen = {}

    def fake_clone(url, dest):
        seen["url"] = url
        raise subprocess.CalledProcessError(128, "git", stderr="stop here")

    with patch("codeguard.cli._clone_shallow", side_effect=fake_clone):
        run_audit(CREDENTIALED, str(tmp_path / "out.md"), False)

    assert seen["url"] == CREDENTIALED, "git must receive the unredacted URL"


def test_a_plain_public_url_is_unchanged(capsys, tmp_path):
    """The common case must not acquire a [redacted] where there is no
    credential. An ordinary https://github.com/owner/repo has no `@`, so
    the userinfo pattern cannot match it."""
    plain = "https://github.com/ashrithaumd/codeguard-playground"
    with _clone_fails():
        run_audit(plain, str(tmp_path / "out.md"), False)

    err = capsys.readouterr().err
    assert plain in err
    assert "[redacted]" not in err
