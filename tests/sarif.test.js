const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

test("export SARIF 2.1.0 avec règle, gravité et emplacement", () => {
  const context = { window: {} };
  vm.runInNewContext(fs.readFileSync("sarif.js", "utf8"), context);
  const result = context.window.IDASarif.build({
    repository: "owner/project",
    generatedAt: "2026-11-25T00:00:00.000Z",
    findings: [{
      level: "high",
      ruleId: "OSV:GHSA-demo",
      title: "Dépendance vulnérable",
      description: "Une version vulnérable a été détectée.",
      file: "package-lock.json",
      line: 12,
      confidence: "high",
      source: "OSV.dev",
      fix: "Mettre à jour la dépendance."
    }]
  }, "github");
  assert.equal(result.version, "2.1.0");
  assert.equal(result.runs[0].tool.driver.name, "IDA BugFix");
  assert.equal(result.runs[0].results[0].ruleId, "OSV:GHSA-demo");
  assert.equal(result.runs[0].results[0].level, "error");
  assert.equal(result.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
  assert.equal(result.runs[0].properties.repository, "owner/project");
});
