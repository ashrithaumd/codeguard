// Planted: a floating "-latest" alias in a production summariser.
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ timeout: 30_000 });

export async function summarise(text: string): Promise<string> {
  const message = await anthropic.messages.create({
    model: "claude-3-5-haiku-latest",
    max_tokens: 150,
    system: "Summarise the text in two sentences.",
    messages: [{ role: "user", content: text }],
  });
  const block = message.content[0];
  return block.type === "text" ? block.text : "";
}
