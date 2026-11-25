/* IDA BugFix test planner. It proposes commands but never executes them. */
(() => {
  function plan(files){
    const byPath=new Map((files||[]).map(f=>[String(f.path||f.name||"").replace(/\\/g,"/"),String(f.content||"")]));
    const names=[...byPath.keys()],base=n=>names.find(p=>p.split("/").pop().toLowerCase()===n);
    const has=n=>!!base(n),get=n=>byPath.get(base(n))||"";
    const steps=[],ecosystems=[];
    const add=(ecosystem,install,tests,checks=[],notes=[])=>{
      ecosystems.push(ecosystem);steps.push({ecosystem,install,tests,checks,notes});
    };
    if(has("package.json")){
      let pkg={};try{pkg=JSON.parse(get("package.json"));}catch{}
      const scripts=pkg.scripts||{};
      const manager=has("pnpm-lock.yaml")?"pnpm":has("yarn.lock")?"yarn":has("bun.lockb")||has("bun.lock")?"bun":"npm";
      const install=manager==="npm"?(has("package-lock.json")?"npm ci":"npm install"):manager==="pnpm"?"pnpm install --frozen-lockfile":manager==="yarn"?"yarn install --immutable":"bun install --frozen-lockfile";
      const tests=scripts.test?manager==="npm"?"npm test":manager+" test":has("vitest.config.js")?"npx vitest run":has("jest.config.js")?"npx jest --runInBand":null;
      const checks=[];
      if(scripts.lint)checks.push(manager==="npm"?"npm run lint":manager+" lint");
      if(scripts.typecheck)checks.push(manager==="npm"?"npm run typecheck":manager+" typecheck");
      add("JavaScript / Node.js",install,tests?[tests]:[],checks,tests?[]:["Aucun script de test explicite détecté dans package.json."]);
    }
    if(has("pyproject.toml")||has("requirements.txt")||names.some(p=>/\.py$/i.test(p))){
      const config=get("pyproject.toml"),req=get("requirements.txt")+"\n"+get("requirements-dev.txt");
      const pytest=/pytest/i.test(config+" "+req)||has("pytest.ini")||has("conftest.py");
      const tests=pytest?["python -m pytest -q"]:["python -m unittest discover -v"];
      const install=has("requirements.txt")?"python -m pip install -r requirements.txt":has("pyproject.toml")?"python -m pip install -e .":"";
      add("Python",install,tests,[],pytest?[]:["Pytest non détecté : unittest est proposé par défaut."]);
    }
    if(has("go.mod"))add("Go","go mod download",["go test ./..."],["go vet ./..."]);
    if(has("cargo.toml"))add("Rust","cargo fetch --locked",["cargo test --locked"],["cargo clippy --all-targets --all-features -- -D warnings"]);
    if(has("composer.json")){
      let composer={};try{composer=JSON.parse(get("composer.json"));}catch{}
      const hasTest=!!composer.scripts?.test||has("phpunit.xml")||has("phpunit.xml.dist");
      add("PHP / Composer","composer install --no-interaction --prefer-dist",composer.scripts?.test?["composer test"]:hasTest?["vendor/bin/phpunit"]:[],[],hasTest?[]:["Aucune commande de test PHP explicite détectée."]);
    }
    if(has("pom.xml")){
      const wrapper=names.some(p=>p.split("/").pop()==="mvnw");
      add("Java / Maven",wrapper?"./mvnw -B -DskipTests dependency:go-offline":"mvn -B -DskipTests dependency:go-offline",[wrapper?"./mvnw -B test":"mvn -B test"]);
    }
    if(has("build.gradle")||has("build.gradle.kts")){
      const wrapper=names.some(p=>p.split("/").pop()==="gradlew");
      add("Java / Gradle",wrapper?"./gradlew dependencies":"gradle dependencies",[wrapper?"./gradlew test":"gradle test"]);
    }
    return {ecosystems:[...new Set(ecosystems)],steps,execution:"not_run",warning:"Plan proposé uniquement. IDA BugFix n'a exécuté aucune commande du projet. Un environnement isolé et une autorisation explicite seront nécessaires pour lancer ces tests.",generatedAt:new Date().toISOString()};
  }
  window.IDATestPlanner={plan};
})();
