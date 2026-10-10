// Near miss: a non-literal filename, but only ever one of three constants.
const fs = require("fs");
const path = require("path");

const TEMPLATES = { welcome: "welcome.html", reset: "reset.html", invite: "invite.html" };

function loadTemplate(kind) {
  const file = TEMPLATES[kind] || TEMPLATES.welcome;
  return fs.readFileSync(path.join(__dirname, "templates", file), "utf8");
}

module.exports = { loadTemplate };
