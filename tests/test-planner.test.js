const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function planner() {
  const context = { window: {} };
  vm.runInNewContext(fs.readFileSync("test-planner.js", "utf8"), context);
  return context.window.IDATestPlanner;
}

test("propose npm ci et npm test sans exécuter le projet", () => {
  const result = planner().plan([
    { path: "package.json", content: JSON.stringify({ scripts: { test: "vitest run", lint: "eslint ." } }) },
    { path: "package-lock.json", content: "{}" }
  ]);
  assert.equal(result.execution, "not_run");
  assert.equal(result.steps[0].install, "npm ci");
  assert.deepEqual(Array.from(result.steps[0].tests), ["npm test"]);
  assert.deepEqual(Array.from(result.steps[0].checks), ["npm run lint"]);
});

test("propose les commandes Go, Rust et Maven", () => {
  const result = planner().plan([
    { path: "go.mod", content: "module example.com/demo" },
    { path: "Cargo.toml", content: "[package]" },
    { path: "pom.xml", content: "<project/>" }
  ]);
  assert.ok(result.steps.some(x => x.ecosystem === "Go" && x.tests.includes("go test ./...")));
  assert.ok(result.steps.some(x => x.ecosystem === "Rust" && x.tests.includes("cargo test --locked")));
  assert.ok(result.steps.some(x => x.ecosystem === "Java / Maven" && x.tests.includes("mvn -B test")));
});

test("propose pytest avec requirements-dev.txt", () => {
  const result = planner().plan([
    { path: "requirements-dev.txt", content: "pytest==8.0.0" },
    { path: "tests/test_app.py", content: "def test_app(): pass" }
  ]);
  assert.ok(result.steps.some(x => x.ecosystem === "Python" && x.install === "python -m pip install -r requirements-dev.txt" && x.tests.includes("python -m pytest -q")));
  assert.equal(result.execution, "not_run");
});
