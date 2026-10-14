// Near miss: the model only picks from a fixed menu; its answer is parsed,
// checked against the menu, and never executed or interpolated.
const OpenAI = require("openai");

const openai = new OpenAI({ timeout: 20000 });
const ACTIONS = new Set(["refund", "escalate", "close"]);

async function chooseAction(ticket) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-2024-08-06",
    max_tokens: 50,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: 'Return {"action": "refund" | "escalate" | "close"} for the ticket.' },
      { role: "user", content: ticket },
    ],
  });
  let action;
  try {
    action = JSON.parse(completion.choices[0].message.content).action;
  } catch {
    return "escalate";
  }
  return ACTIONS.has(action) ? action : "escalate";
}

module.exports = { chooseAction };
