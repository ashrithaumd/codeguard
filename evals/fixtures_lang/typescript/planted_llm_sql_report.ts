// Planted: "ask your data" -- the model writes the SQL and it runs as is.
import OpenAI from "openai";
import { Pool } from "pg";

const openai = new OpenAI({ timeout: 30_000 });
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function answer(question: string) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-2024-08-06",
    max_tokens: 300,
    messages: [
      { role: "system", content: "Translate the question into one PostgreSQL SELECT over the orders table." },
      { role: "user", content: question },
    ],
  });
  const sql = completion.choices[0].message.content ?? "SELECT 1";
  const { rows } = await pool.query(sql);
  return rows;
}
