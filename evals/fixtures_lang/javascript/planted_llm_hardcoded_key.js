// Planted: a real-looking OpenAI key committed in the client setup.
// Decided by its shape alone; this line must never reach the model.
const OpenAI = require("openai");

const client = new OpenAI({
  apiKey: "sk-proj-NDmK496Tu9EgANNTMd0U4p1LeboUUK0JgpMimCFUjciRRolL",
  timeout: 20000,
});

module.exports = { client };
