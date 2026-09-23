import asyncio
import os
import subprocess

import anthropic
import openai

client = anthropic.Anthropic()
cursor = None
user_input = "x"
SYSTEM = "You are a helpful assistant."
oai_stream = []


# --- llm-prompt-injection-concatenation ---------------------------------

# ruleid: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": "prefix" + user_input}], max_tokens=100, system=SYSTEM, timeout=5)

# ruleid: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": f"Question: {user_input}"}], max_tokens=100, system=SYSTEM, timeout=5)

# ok: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": "static text only"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-missing-system-user-separation ---------------------------------
# (max_tokens/timeout included in both cases so this block doesn't also
# trip llm-call-missing-max-tokens/timeout — each block isolates the one
# thing it tests)

# ruleid: llm-missing-system-user-separation
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ok: llm-missing-system-user-separation
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-output-to-dangerous-sink (taint) -------------------------------
# Annotation sits directly above the SINK line, not the source line —
# taint-mode matches are reported where the tainted value is used.

resp_a = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-dangerous-sink
eval(resp_a.content[0].text)

resp_b = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-dangerous-sink
subprocess.run(resp_b.content[0].text)

resp_c = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-output-to-dangerous-sink
safe_text = resp_c.content[0].text


# --- llm-output-to-sql (taint) ------------------------------------------

resp_d = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-sql
cursor.execute(resp_d.content[0].text)

resp_e = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-output-to-sql
cursor.execute("SELECT 1")


# --- llm-call-missing-max-tokens -----------------------------------------
# (system/timeout included in both cases so this block doesn't also trip
# llm-missing-system-user-separation / llm-call-missing-timeout)

# ruleid: llm-call-missing-max-tokens
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], system=SYSTEM, timeout=5)

# ok: llm-call-missing-max-tokens
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-call-missing-timeout ---------------------------------------------
# (max_tokens/system included in both cases so this block doesn't also
# trip llm-call-missing-max-tokens / llm-missing-system-user-separation)

# ruleid: llm-call-missing-timeout
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM)

# ok: llm-call-missing-timeout
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-sync-call-in-async-handler ----------------------------------------
# The pattern matches the whole `async def` block, so semgrep reports the
# match at the function's own def line, not the inner call line —
# annotations go above `async def`, not above the call.

# ruleid: llm-sync-call-in-async-handler
async def handler_bad(request):
    resp = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def handler_ok_awaited(request):
    async_client = anthropic.AsyncAnthropic()
    resp = await async_client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def handler_ok_to_thread(request):
    resp = await asyncio.to_thread(client.messages.create, model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# --- llm-unpinned-model-alias ---------------------------------------------

# ruleid: llm-unpinned-model-alias
model = "claude-3-5-sonnet-latest"

# ok: llm-unpinned-model-alias
model = "claude-3-5-sonnet-20241022"


# --- llm-hardcoded-api-key -------------------------------------------------

# ruleid: llm-hardcoded-api-key
client_bad = anthropic.Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz")

# ok: llm-hardcoded-api-key
client_good = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# --- llm-logging-full-prompt-or-response ------------------------------------

resp_f = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-logging-full-prompt-or-response
print(resp_f.content[0].text)

resp_g = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-logging-full-prompt-or-response
print(len(resp_g.content[0].text))


# ===========================================================================
# OpenAI shapes
# ===========================================================================
# Same rules, same rule_ids — the ruleset covers both SDKs via nested
# pattern-either (see llm-security.yaml). Everything below mirrors an
# Anthropic block above, and follows the same isolation discipline: every
# kwarg a block ISN'T testing is present, so one block never trips another
# rule and produces an unannotated match.
#
# Two OpenAI call shapes are covered, and their kwargs differ:
#   chat.completions.create -> max_tokens / max_completion_tokens
#   responses.create        -> max_output_tokens, instructions=
# System separation is a message in the list for chat.completions (the dict
# literal has to be inline — a variable would not match the rule's own
# pattern-not) and `instructions=` for responses.

oai = openai.OpenAI()
aoai = openai.AsyncOpenAI()


# --- llm-prompt-injection-concatenation (OpenAI) ---------------------------

# ruleid: llm-prompt-injection-concatenation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "prefix" + user_input}], max_tokens=100, timeout=5)

# ruleid: llm-prompt-injection-concatenation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Question: {user_input}"}], max_tokens=100, timeout=5)

# ok: llm-prompt-injection-concatenation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "static text only"}], max_tokens=100, timeout=5)

# ruleid: llm-prompt-injection-concatenation
oai.responses.create(model="gpt-4o", input="prefix" + user_input, instructions=SYSTEM, max_output_tokens=100, timeout=5)

# ok: llm-prompt-injection-concatenation
oai.responses.create(model="gpt-4o", input="static text only", instructions=SYSTEM, max_output_tokens=100, timeout=5)


# --- llm-missing-system-user-separation (OpenAI) ---------------------------
# OpenAI has no `system=` kwarg: the separation is a leading system (or, on
# newer reasoning models, "developer") message, or `instructions=` on the
# Responses API. Both accepted forms are asserted as `ok` so a future
# pattern-not edit that drops one is caught.

# ruleid: llm-missing-system-user-separation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ok: llm-missing-system-user-separation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ok: llm-missing-system-user-separation
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "developer", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ruleid: llm-missing-system-user-separation
oai.responses.create(model="gpt-4o", input="hi", max_output_tokens=100, timeout=5)

# ok: llm-missing-system-user-separation
oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100, timeout=5)


# --- llm-output-to-dangerous-sink (OpenAI, taint) --------------------------
# Three response shapes: chat completion, streamed chunk delta, and the
# Responses API's output_text accessor. Streaming matters — it is how a
# real client (e.g. simonw/llm) actually reads responses, so a taint rule
# blind to delta.content is blind on real code.

resp_oa = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=10, timeout=5)
# ruleid: llm-output-to-dangerous-sink
eval(resp_oa.choices[0].message.content)

for chunk_oa in oai_stream:
    # ruleid: llm-output-to-dangerous-sink
    exec(chunk_oa.choices[0].delta.content)

resp_or = oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=10, timeout=5)
# ruleid: llm-output-to-dangerous-sink
subprocess.run(resp_or.output_text)

resp_ok_oa = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=10, timeout=5)
# ok: llm-output-to-dangerous-sink
safe_oa_text = resp_ok_oa.choices[0].message.content


# --- llm-output-to-sql (OpenAI, taint) -------------------------------------

resp_oh = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=10, timeout=5)
# ruleid: llm-output-to-sql
cursor.execute(resp_oh.choices[0].message.content)

resp_oi = oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=10, timeout=5)
# ok: llm-output-to-sql
cursor.execute("SELECT 1")

# WAS a known false positive, now fixed. Passing model output as a BOUND
# PARAMETER is the correct, safe way to use it in SQL, but the rule's
# sink used to be `$CURSOR.execute(...)` — the whole call — so it could
# not tell the query text from the parameter tuple and fired here too.
# The sink now focuses the QUERY argument (focus-metavariable), so this
# is a real `ok` rather than a `todook`: the safe pattern no longer
# produces a finding a reviewer has to dismiss by hand.
# ok: llm-output-to-sql
cursor.execute("SELECT 1 WHERE x = ?", (resp_oi.output_text,))


# --- llm-call-missing-max-tokens (OpenAI) ----------------------------------
# The max_completion_tokens `ok` case is the one most likely to rot: it is
# the kwarg OpenAI's newer reasoning models require INSTEAD of max_tokens,
# so a rule that only excludes max_tokens would flag correct code.

# ruleid: llm-call-missing-max-tokens
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], timeout=5)

# ok: llm-call-missing-max-tokens
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ok: llm-call-missing-max-tokens
oai.chat.completions.create(model="o3", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_completion_tokens=100, timeout=5)

# ruleid: llm-call-missing-max-tokens
oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, timeout=5)

# ok: llm-call-missing-max-tokens
oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100, timeout=5)


# --- llm-call-missing-timeout (OpenAI) -------------------------------------

# ruleid: llm-call-missing-timeout
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100)

# ok: llm-call-missing-timeout
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ruleid: llm-call-missing-timeout
oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100)

# ok: llm-call-missing-timeout
oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100, timeout=5)


# --- cross-vendor pattern-not scoping ---------------------------------------
# The bug the nested pattern-either exists to prevent: each vendor's
# pattern-not must sit inside its OWN patterns block. Flattened, the
# fully-specified Anthropic call below would satisfy the timeout
# pattern-not for the whole rule and suppress the OpenAI finding in the
# same file. The Anthropic call carries every kwarg and is deliberately
# unannotated — it must match nothing — while the OpenAI call beneath it
# must still fire. If this block ever goes quiet, the scoping has
# regressed.

client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)

# ruleid: llm-call-missing-timeout
oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100)


# --- llm-sync-call-in-async-handler (OpenAI) --------------------------------

# ruleid: llm-sync-call-in-async-handler
async def oai_handler_bad(request):
    resp = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def oai_handler_ok_awaited(request):
    resp = await aoai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def oai_handler_ok_to_thread(request):
    resp = await asyncio.to_thread(oai.chat.completions.create, model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=100, timeout=5)
    return resp


# ruleid: llm-sync-call-in-async-handler
async def oai_responses_handler_bad(request):
    resp = oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def oai_responses_handler_ok(request):
    resp = await aoai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=100, timeout=5)
    return resp


# --- llm-hardcoded-api-key (OpenAI + async constructors) --------------------
# The async constructors were a gap for BOTH vendors, not just OpenAI.

# ruleid: llm-hardcoded-api-key
oai_bad = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz")

# ruleid: llm-hardcoded-api-key
aoai_bad = openai.AsyncOpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz")

# ruleid: llm-hardcoded-api-key
anthropic_async_bad = anthropic.AsyncAnthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz")

# ok: llm-hardcoded-api-key
oai_good = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ok: llm-hardcoded-api-key
aoai_good = openai.AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# --- llm-logging-full-prompt-or-response (OpenAI) ---------------------------

resp_oj = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=10, timeout=5)
# ruleid: llm-logging-full-prompt-or-response
print(resp_oj.choices[0].message.content)

resp_ok_log = oai.responses.create(model="gpt-4o", input="hi", instructions=SYSTEM, max_output_tokens=10, timeout=5)
# ruleid: llm-logging-full-prompt-or-response
print(resp_ok_log.output_text)

resp_ol = oai.chat.completions.create(model="gpt-4o", messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}], max_tokens=10, timeout=5)
# ok: llm-logging-full-prompt-or-response
print(len(resp_ol.choices[0].message.content))


# --- llm-unpinned-model-alias: Anthropic-only by design ---------------------
# Rule 6 deliberately has no OpenAI equivalent (see its own message text):
# OpenAI signals a floating alias by the ABSENCE of a date suffix, so
# detecting it would mean flagging every bare model name. These assert that
# deliberate non-coverage, so someone "fixing" the gap has to change a test
# that says why it exists rather than silently widening the rule.

# ok: llm-unpinned-model-alias
model = "gpt-4o"

# ok: llm-unpinned-model-alias
model = "gpt-4o-2024-08-06"


# =======================================================================
# LangChain / LlamaIndex and the wider OWASP coverage.
#
# Same convention as above: each block includes whatever OTHER rules
# would otherwise fire on the same line (max_tokens, request_timeout,
# max_iterations), so every case isolates the one rule it is testing.
# The library symbols are never imported or called for real — semgrep
# parses this file, it does not run it.
# =======================================================================

import torch  # noqa: E402

fetched_url = "https://example.com"
SECRET_KEY_NAME = "ANTHROPIC_API_KEY"


# --- llm-langchain-prompt-from-fstring ----------------------------------

# ruleid: llm-langchain-prompt-from-fstring
tmpl_bad = PromptTemplate.from_template(f"Answer this: {user_input}")

# ruleid: llm-langchain-prompt-from-fstring
tmpl_bad2 = ChatPromptTemplate.from_template(f"Summarise: {user_input}")

# The near-miss: a real template with a slot, which is the whole point —
# the value arrives at invoke time and stays a parameter.
# ok: llm-langchain-prompt-from-fstring
tmpl_ok = PromptTemplate.from_template("Answer this: {question}")


# --- llm-fetched-content-into-prompt (taint) ----------------------------

page = requests.get(fetched_url).text
# ruleid: llm-fetched-content-into-prompt
client.messages.create(model="x", messages=[{"role": "user", "content": page}], max_tokens=100, system=SYSTEM, timeout=5)

# Near-miss: fetched content that never reaches a prompt.
page_ok = requests.get(fetched_url).text
# ok: llm-fetched-content-into-prompt
length_only = len(page_ok)


# --- llm-secret-into-prompt (taint) -------------------------------------

api_key_value = os.environ["SOME_SECRET"]
# ruleid: llm-secret-into-prompt
client.messages.create(model="x", messages=[{"role": "user", "content": api_key_value}], max_tokens=100, system=SYSTEM, timeout=5)

# Near-miss: an env var read for configuration, used as configuration.
model_name = os.environ["MODEL_NAME"]
# ok: llm-secret-into-prompt
client.messages.create(model=model_name, messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-langchain-verbose-enabled --------------------------------------

# ruleid: llm-langchain-verbose-enabled
chain_verbose = LLMChain(llm=None, prompt=None, verbose=True)

# ok: llm-langchain-verbose-enabled
chain_quiet = LLMChain(llm=None, prompt=None, verbose=False)


# --- llm-langchain-hardcoded-api-key ------------------------------------
# (max_tokens/request_timeout present so the missing-cap rules stay out
# of this block)

# ruleid: llm-langchain-hardcoded-api-key
llm_bad_key = ChatOpenAI(model="gpt-4o", openai_api_key="sk-" + "notarealkeyatall1234", max_tokens=100, request_timeout=5)

# ok: llm-langchain-hardcoded-api-key
llm_env_key = ChatOpenAI(model="gpt-4o", openai_api_key=os.environ["OPENAI_API_KEY"], max_tokens=100, request_timeout=5)


# --- llm-trust-remote-code ----------------------------------------------

# ruleid: llm-trust-remote-code
model_remote = AutoModel.from_pretrained("some/model", trust_remote_code=True)

# ok: llm-trust-remote-code
model_plain = AutoModel.from_pretrained("some/model")


# --- llm-llamaindex-download-loader -------------------------------------

# ruleid: llm-llamaindex-download-loader
Loader = download_loader("GithubRepositoryReader")

# ok: llm-llamaindex-download-loader
reader_ok = SimpleDirectoryReader("./data")


# --- llm-unsafe-model-deserialization -----------------------------------

# ruleid: llm-unsafe-model-deserialization
weights_bad = torch.load("checkpoint.pt")

# ok: llm-unsafe-model-deserialization
weights_ok = torch.load("checkpoint.pt", weights_only=True)


# --- llm-output-to-html (taint) -----------------------------------------

resp_html = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-html
page_out = HTMLResponse(resp_html.content[0].text)

# Near-miss: the same value returned as text, which is the fix.
resp_text = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-output-to-html
plain_out = PlainTextResponse(resp_text.content[0].text)


# --- llm-llamaindex-pandas-query-engine ---------------------------------

# ruleid: llm-llamaindex-pandas-query-engine
pandas_engine = PandasQueryEngine(df=None)

# ok: llm-llamaindex-pandas-query-engine
vector_engine = VectorStoreIndex([]).as_query_engine()


# --- llm-langchain-python-repl-tool -------------------------------------

# ruleid: llm-langchain-python-repl-tool
repl_tool = PythonREPLTool()

# ok: llm-langchain-python-repl-tool
search_tool = DuckDuckGoSearchRun()


# --- llm-langchain-shell-tool -------------------------------------------

# ruleid: llm-langchain-shell-tool
shell_tool = ShellTool()

# ok: llm-langchain-shell-tool
calc_tool = Calculator()


# --- llm-nl-to-sql-engine -----------------------------------------------

# ruleid: llm-nl-to-sql-engine
sql_engine = NLSQLTableQueryEngine(sql_database=None)

# ok: llm-nl-to-sql-engine
sql_handwritten = cursor.execute("SELECT 1")


# --- llm-agent-allow-dangerous ------------------------------------------

# ruleid: llm-agent-allow-dangerous
df_agent = create_pandas_dataframe_agent(None, None, allow_dangerous_code=True)

# ok: llm-agent-allow-dangerous
df_agent_safe = create_pandas_dataframe_agent(None, None, allow_dangerous_code=False)


# --- llm-agent-missing-max-iterations -----------------------------------
# (verbose left at its default so this block doesn't also trip
# llm-langchain-verbose-enabled)

# ruleid: llm-agent-missing-max-iterations
agent_unbounded = AgentExecutor(agent=None, tools=[])

# ok: llm-agent-missing-max-iterations
agent_bounded = AgentExecutor(agent=None, tools=[], max_iterations=5)


# --- llm-langchain-missing-max-tokens -----------------------------------
# (request_timeout present in both so llm-langchain-missing-timeout
# stays out of this block)

# ruleid: llm-langchain-missing-max-tokens
llm_no_cap = ChatAnthropic(model="claude-sonnet-4-5-20250929", request_timeout=5)

# ok: llm-langchain-missing-max-tokens
llm_capped = ChatAnthropic(model="claude-sonnet-4-5-20250929", max_tokens=1000, request_timeout=5)


# --- llm-langchain-missing-timeout --------------------------------------
# (max_tokens present in both so llm-langchain-missing-max-tokens stays
# out of this block)

# ruleid: llm-langchain-missing-timeout
llm_no_timeout = ChatAnthropic(model="claude-sonnet-4-5-20250929", max_tokens=1000)

# ok: llm-langchain-missing-timeout
llm_with_timeout = ChatAnthropic(model="claude-sonnet-4-5-20250929", max_tokens=1000, request_timeout=5)


# --- kwargs-splat calls are not evidence of a missing cap ---------------
# Regression cases for the false positives found by scanning this repo's
# own codeguard/pipeline/llm_call.py, which sets max_tokens and timeout
# in a dict and passes **create_kwargs. Semgrep cannot see inside the
# dict, so the rules must stay quiet rather than assert a defect they
# cannot verify.

splat_kwargs = dict(
    model="x",
    system=SYSTEM,
    messages=[{"role": "user", "content": "hi"}],
    max_tokens=100,
    timeout=5,
)

# ok: llm-call-missing-max-tokens
client.messages.create(**splat_kwargs)

# ok: llm-call-missing-timeout
client.messages.create(**splat_kwargs)

lc_kwargs = dict(model="claude-sonnet-4-5-20250929", max_tokens=1000, request_timeout=5)

# ok: llm-langchain-missing-max-tokens
ChatAnthropic(**lc_kwargs)

# ok: llm-langchain-missing-timeout
ChatAnthropic(**lc_kwargs)
