// Near miss: the model's summary is stored, but only ever as a bound
// parameter; the SQL text is a constant.
import Anthropic from "@anthropic-ai/sdk";
import { Pool } from "pg";

const anthropic = new Anthropic({ timeout: 30_000 });
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function summariseAndStore(noteId: number, body: string) {
  const message = await anthropic.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 200,
    system: "Summarise the note in one sentence.",
    messages: [{ role: "user", content: body }],
  });
  const summary = message.content[0].type === "text" ? message.content[0].text : "";
  await pool.query("UPDATE notes SET summary = $1 WHERE id = $2", [summary, noteId]);
}
