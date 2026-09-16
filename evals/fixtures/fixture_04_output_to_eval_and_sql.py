"""Eval fixture: LLM response text flowing into eval() and into a raw
SQL execute() call — both taint-mode sinks. The two calls that produce
the tainted responses are themselves fully safe (all fields present),
so only the sink lines should be flagged.
"""

import sqlite3

import anthropic

client = anthropic.Anthropic()
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()


def run_model_command(instruction):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Respond with a Python expression.", timeout=5)
    return eval(resp.content[0].text)


def run_model_query(instruction):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Respond with a SQL query.", timeout=5)
    cursor.execute(resp.content[0].text)
    return cursor.fetchall()
