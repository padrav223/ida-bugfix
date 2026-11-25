const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const acorn = require("acorn");

function engine() {
  const context = { window: { acorn } };
  vm.runInNewContext(fs.readFileSync("ast-engine.js", "utf8"), context);
  return context.window.IDAASTEngine;
}

test("détecte une injection SQL par propagation depuis req.query", () => {
  const result = engine().analyze("server.js", [
    "app.get('/user', (req, res) => {",
    "  const id = req.query.id;",
    "  db.query('SELECT * FROM users WHERE id=' + id);",
    "});"
  ].join("\n"));
  assert.equal(result.parsed, true);
  assert.ok(result.findings.some(x => x.ruleId === "js.sql-injection" && x.line === 3));
});

test("détecte une injection de commande depuis req.body", () => {
  const result = engine().analyze("server.js", [
    "app.post('/run', (req, res) => {",
    "  const command = req.body.command;",
    "  child_process.exec('tool ' + command);",
    "});"
  ].join("\n"));
  assert.ok(result.findings.some(x => x.ruleId === "js.command-injection"));
});

test("détecte une XSS DOM par affectation innerHTML", () => {
  const result = engine().analyze("client.js", [
    "const params = new URLSearchParams(location.search);",
    "const message = params.get('message');",
    "element.innerHTML = message;"
  ].join("\n"));
  assert.ok(result.findings.some(x => x.ruleId === "js.dom-xss"));
});

test("détecte les options TLS dangereuses et les hachages faibles", () => {
  const result = engine().analyze("network.js", [
    "const options = { rejectUnauthorized: false };",
    "const digest = crypto.createHash('md5');"
  ].join("\n"));
  assert.ok(result.findings.some(x => x.ruleId === "js.insecure-tls"));
  assert.ok(result.findings.some(x => x.ruleId === "js.weak-hash"));
});

test("n'émet pas d'alerte SQL pour une entrée constante sans source non fiable", () => {
  const result = engine().analyze("safe.js", "db.query('SELECT 1');");
  assert.equal(result.findings.filter(x => x.ruleId === "js.sql-injection").length, 0);
});

test("ne divulgue pas la valeur contrôlée dans les constats", () => {
  const result = engine().analyze("server.js", [
    "const userInput = req.query.value;",
    "eval(userInput);"
  ].join("\n"));
  assert.ok(result.findings.some(x => x.ruleId === "js.tainted-eval"));
  assert.equal(JSON.stringify(result.findings).includes("req.query.value"), false);
});
