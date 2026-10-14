// Planted: a "run this for me" helper that executes whatever shell command
// the model writes.
const OpenAI = require("openai");
const { execSync } = require("child_process");

const openai = new OpenAI({ timeout: 20000 });

async function runTask(task) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-2024-08-06",
    max_tokens: 200,
    messages: [
      { role: "system", content: "Reply with a single POSIX shell command that performs the task. No prose." },
      { role: "user", content: task },
    ],
  });
  const command = completion.choices[0].message.content.trim();
  return execSync(command, { encoding: "utf8", timeout: 10000 });
}

module.exports = { runTask };
