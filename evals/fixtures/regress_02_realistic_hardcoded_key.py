"""Regression fixture (2026-10-08): a realistic-looking hardcoded key with
no comment about it at all.

The value is a RANDOM DUMMY generated for this file: key-shaped, high
entropy, and not a real credential. It is deliberately not in Anthropic's
exact issued format (no trailing checksum), so secret scanners do not
mistake it for a live key. The verdict agent sees it as
`[redacted: N-char sk-ant-style token, high-entropy]` and must confirm.
"""

import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-yGpx381593i8sWdR6RLpdKvDAiTjQCALr2yU61LxkdCNDVcAI370KgTNOLs2XAN3ZdgLangEKdLpcVEF")


def ask(question):
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="Answer in one sentence.",
        messages=[{"role": "user", "content": question}],
    )
