const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function loadEngine(fetchImpl = async () => ({ ok: true, json: async () => ({ results: [] }) })) {
  const context = { window: {}, fetch: fetchImpl, console, AbortController, setTimeout, clearTimeout };
  vm.runInNewContext(fs.readFileSync("security-engine.js", "utf8"), context);
  return context.window.IDASecurityEngine;
}

test("détecte les formats connus de secrets sans afficher leur valeur", () => {
  const engine = loadEngine();
  const findings = engine.scanSecrets("config.js", [
    'const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";',
    'const aws = "AKIA1234567890123456";',
    'const placeholder = "YOUR_API_KEY_HERE";'
  ].join("\n"));
  assert.ok(findings.some(x => x.ruleId === "secret.github-token"));
  assert.ok(findings.some(x => x.ruleId === "secret.aws-access-key"));
  assert.ok(!findings.some(x => x.description.includes("ghp_")));
  assert.equal(findings.length, 2);
});

test("interroge OSV avec les seules coordonnées des dépendances verrouillées", async () => {
  let sentBody;
  const engine = loadEngine(async (url, options) => {
    assert.equal(url, "https://api.osv.dev/v1/querybatch");
    sentBody = JSON.parse(options.body);
    return { ok: true, json: async () => ({ results: [{ vulns: [{
      id: "GHSA-example-1234",
      summary: "Version vulnérable de test",
      database_specific: { severity: "HIGH" }
    }] }] }) };
  });
  const result = await engine.auditDependencies([{
    path: "package-lock.json",
    content: JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "sample", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20" }
    } })
  }]);
  assert.equal(result.packages, 1);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].level, "high");
  assert.equal(result.findings[0].ruleId, "OSV:GHSA-example-1234");
  assert.deepEqual(sentBody.queries, [{
    package: { name: "lodash", ecosystem: "npm" },
    version: "4.17.20"
  }]);
});

test("signale proprement l'absence de fichier de verrouillage reconnu", async () => {
  const engine = loadEngine();
  const result = await engine.auditDependencies([{ path: "src/index.js", content: "console.log('hello')" }]);
  assert.equal(result.packages, 0);
  assert.equal(result.findings.length, 0);
});

test("analyse aussi les fichiers requirements de développement", async () => {
  let sentBody;
  const engine = loadEngine(async (_url, options) => {
    sentBody = JSON.parse(options.body);
    return { ok: true, json: async () => ({ results: [{ vulns: [] }] }) };
  });
  const result = await engine.auditDependencies([{
    path: "requirements-dev.txt",
    content: "flask==2.0.0\npytest==7.0.0\n"
  }]);
  assert.equal(result.packages, 2);
  assert.equal(sentBody.queries.length, 2);
  assert.equal(sentBody.queries[0].package.ecosystem, "PyPI");
});

test("détecte aussi les secrets non entourés de guillemets dans les fichiers .env", () => {
  const engine = loadEngine();
  const findings = engine.scanSecrets(".env", "API_KEY=sk_live_fake_value_123456789\n");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "secret-assignment");
  assert.ok(!JSON.stringify(findings).includes("sk_live_fake_value_123456789"));
});
