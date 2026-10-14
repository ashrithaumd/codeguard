// CommonJS and a namespaced constructor: the same rules, plain JavaScript.
const sdk = require("@anthropic-ai/sdk");
const cp = require("child_process");

// ruleid: codeguard-js-llm-call-missing-timeout
const client = new sdk.Anthropic({
  // ruleid: codeguard-js-llm-hardcoded-api-key
  apiKey: "sk-ant-api03-placeholder",
});

async function run(question) {
  const prompt = "Answer briefly: " + question;
  const resp = await client.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 100,
    system: "You answer questions.",
    // ruleid: codeguard-js-llm-prompt-injection-concatenation
    messages: [{ role: "user", content: prompt }],
  });
  // ruleid: codeguard-js-llm-output-to-dangerous-sink
  cp.execSync(resp.content[0].text);
  // ok: codeguard-js-llm-output-to-dangerous-sink
  cp.execFileSync("echo", [resp.content[0].text]);
}

module.exports = { run };
