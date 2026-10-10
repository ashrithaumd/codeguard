// Planted: user input from the request reaches eval.
const express = require("express");
const app = express();

app.get("/calc", (req, res) => {
  const expression = req.query.expr;
  res.send(String(eval(expression)));
});
