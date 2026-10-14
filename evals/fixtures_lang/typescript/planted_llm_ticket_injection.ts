// Planted: the ticket body is spliced into the prompt one line above the
// call, then passed in as the user turn -- injection through a variable.
import Anthropic from "@anthropic-ai/sdk";
import type { Request, Response } from "express";

const anthropic = new Anthropic({ timeout: 30_000 });

export async function triageTicket(req: Request, res: Response) {
  const { subject, body } = req.body as { subject: string; body: string };
  const prompt = "Classify this support ticket as billing, bug or other.\n\nSubject: " + subject + "\n" + body;
  const message = await anthropic.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 64,
    system: "You are a support triage assistant. Answer with one word.",
    messages: [{ role: "user", content: prompt }],
  });
  const block = message.content[0];
  res.json({ category: block.type === "text" ? block.text.trim().toLowerCase() : "other" });
}
