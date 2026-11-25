/* IDA BugFix security engine v2 — client-side secret patterns + OSV dependency checks.
   Only package coordinates/versions are sent to OSV; source files are never uploaded. */
(() => {
  const SECRET_RULES = [
    {id:"secret.private-key",level:"critical",re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,why:"Bloc de clé privée détecté."},
    {id:"secret.aws-access-key",level:"critical",re:/\bAKIA[0-9A-Z]{16}\b/,why:"Identifiant de clé d'accès AWS détecté."},
    {id:"secret.github-token",level:"critical",re:/\bgh[pousr]_[A-Za-z0-9_]{30,}\b/,why:"Jeton GitHub à format reconnaissable détecté."},
    {id:"secret.github-fine-grained",level:"critical",re:/\bgithub_pat_[A-Za-z0-9_]{40,}\b/,why:"Jeton GitHub à accès fin détecté."},
    {id:"secret.slack-token",level:"high",re:/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,why:"Jeton Slack à format reconnaissable détecté."},
    {id:"secret.google-api-key",level:"high",re:/\bAIza[0-9A-Za-z_-]{30,}\b/,why:"Clé API Google à format reconnaissable détectée."},
    {id:"secret.stripe-live",level:"critical",re:/\bsk_live_[0-9A-Za-z]{20,}\b/,why:"Clé secrète Stripe live détectée."},
    {id:"secret.jwt",level:"high",re:/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,why:"Chaîne au format JWT détectée."},
    {id:"secret-assignment",level:"high",re:/\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)\b\s*[:=]\s*(?:"([^"\s]{12,})"|'([^'\s]{12,})'|([A-Za-z0-9_./+=-]{16,}))/i,why:"Affectation contenant une valeur qui ressemble à un secret."}
  ];
  const PLACEHOLDERS=/^(?:your[_ -]?.*|replace[_ -]?.*|changeme|example|dummy|test|xxx+|<.*>|\$\{.*\}|process\.env\..*)$/i;
  function secretFindings(path,content){
    const out=[],lines=content.split(/\r?\n/);
    lines.forEach((line,i)=>{
      for(const rule of SECRET_RULES){
        const m=line.match(rule.re);if(!m)continue;
        if(rule.id==="secret-assignment"){
          const value=m[1]||m[2]||m[3]||"";
          if(PLACEHOLDERS.test(value))continue;
        }
        out.push({level:rule.level,title:"Secret potentiellement exposé",file:path,line:i+1,ruleId:rule.id,confidence:rule.id==="secret-assignment"?"medium":"high",source:"IDA Secret Rules",description:rule.why+" La valeur n'est jamais reproduite dans le rapport.",fix:"Révoquer immédiatement la valeur si elle est réelle, vérifier les journaux et l'historique Git, puis utiliser une variable d'environnement ou un gestionnaire de secrets."});
        break;
      }
    });
    return out;
  }
  const norm=(s)=>String(s||"").trim().replace(/^['"]|['"]$/g,"");
  function addPkg(out,name,version,ecosystem,file){
    name=norm(name);version=norm(version).replace(/^[=v\s]+/,"");
    if(!name||!version||/[*xX]|[<>~^|, ]/.test(version))return;
    out.push({name,version,ecosystem,file});
  }
  function parsePackages(files){
    const out=[];
    for(const f of files){
      const path=f.path||f.name||"",base=path.split("/").pop().toLowerCase(),text=f.content||"";
      if(base==="package-lock.json"||base==="npm-shrinkwrap.json"){
        try{
          const j=JSON.parse(text);
          if(j.packages&&typeof j.packages==="object"){
            for(const [key,p] of Object.entries(j.packages)){
              if(!key||!key.includes("node_modules/"))continue;
              const name=key.split("node_modules/").pop();addPkg(out,name,p.version,"npm",path);
            }
          }else{
            const walk=(deps)=>{for(const [name,p] of Object.entries(deps||{})){addPkg(out,name,p.version,"npm",path);walk(p.dependencies)}};
            walk(j.dependencies);
          }
        }catch{}
      }else if(base==="requirements.txt"||/^requirements-.+\.txt$/.test(base)){
        for(const line of text.split(/\r?\n/)){const m=line.match(/^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)/);if(m)addPkg(out,m[1],m[2],"PyPI",path);}
      }else if(base==="go.mod"){
        let inBlock=false;
        for(const line of text.split(/\r?\n/)){if(/^\s*require\s*\(/.test(line)){inBlock=true;continue}if(inBlock&&/^\s*\)/.test(line)){inBlock=false;continue}const m=line.match(/^\s*(?:require\s+)?([^\s]+)\s+(v\d[^\s]*)/);if(m)addPkg(out,m[1],m[2],"Go",path);}
      }else if(base==="cargo.lock"){
        let name="",version="";
        for(const line of text.split(/\r?\n/)){const n=line.match(/^name\s*=\s*"([^"]+)"/),v=line.match(/^version\s*=\s*"([^"]+)"/);if(n)name=n[1];if(v)version=v[1];if(name&&version){addPkg(out,name,version,"crates.io",path);name="";version="";}}
      }else if(base==="composer.lock"){
        try{const j=JSON.parse(text);for(const p of [...(j.packages||[]),...(j["packages-dev"]||[])])addPkg(out,p.name,p.version,"Packagist",path);}catch{}
      }
    }
    const seen=new Set();return out.filter(p=>{const k=[p.ecosystem,p.name,p.version].join("|");if(seen.has(k))return false;seen.add(k);return true}).slice(0,300);
  }
  async function auditDependencies(files){
    const packages=parsePackages(files);
    if(!packages.length)return {findings:[],packages:0,status:"Aucun verrou de dépendances reconnu."};
    const findings=[];
    for(let i=0;i<packages.length;i+=100){
      const batch=packages.slice(i,i+100);
      try{
        const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),12000);
        let response;try{response=await fetch("https://api.osv.dev/v1/querybatch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({queries:batch.map(p=>({package:{name:p.name,ecosystem:p.ecosystem},version:p.version}))}),signal:controller.signal});}finally{clearTimeout(timeout);}
        if(!response.ok)throw new Error("OSV HTTP "+response.status);
        const data=await response.json(),results=data.results||[];
        results.forEach((r,index)=>{
          const pkg=batch[index];(r.vulns||[]).forEach(v=>{
            const ids=[v.id,...(v.aliases||[])].filter(Boolean).slice(0,4);
            const severityText=(v.database_specific?.severity||"").toUpperCase();
            const cvss=Number(v.severity?.find(x=>x.type==="CVSS_V3")?.score);
            const level=/CRITICAL/.test(severityText)||cvss>=9?"critical":/HIGH/.test(severityText)||cvss>=7?"high":/MODERATE|MEDIUM/.test(severityText)||cvss>=4?"medium":severityText?"low":"medium";
            findings.push({level,title:"Dépendance vulnérable : "+pkg.name+"@"+pkg.version,file:pkg.file,line:0,ruleId:"OSV:"+v.id,confidence:"high",source:"OSV.dev",description:(v.summary||v.details||"Une vulnérabilité connue correspond à cette version.")+" Références : "+ids.join(", "),fix:"Mettre à jour vers une version corrigée indiquée par OSV.dev, vérifier les changements incompatibles puis relancer les tests."});
          });
        });
      }catch(e){return {findings,packages:packages.length,status:"Vérification OSV partielle ou indisponible : "+(e.message||"erreur réseau")};}
    }
    return {findings,packages:packages.length,status:"Vérification OSV terminée."};
  }
  window.IDASecurityEngine={scanSecrets:secretFindings,auditDependencies};
})();
