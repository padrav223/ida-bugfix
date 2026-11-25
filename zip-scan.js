// IDA BugFix 2.0.9 — analyse statique locale des archives ZIP.
let lastZipReport=null;
const zipPicker=document.getElementById("zipFile");
document.getElementById("chooseZipBtn").addEventListener("click",()=>zipPicker.click());
zipPicker.addEventListener("change",()=>{const file=zipPicker.files&&zipPicker.files[0];document.getElementById("zipFileName").textContent=file?file.name+" · "+(file.size/1024/1024).toFixed(2)+" Mo":"Aucun fichier sélectionné";document.getElementById("zipError").textContent="";});
const ZIP_META_FILE=/(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|requirements(?:-prod)?\.txt|go\.mod|cargo\.lock|composer\.lock)$/i;
const ZIP_TEXT_EXT=/\.(?:js|jsx|ts|tsx|mjs|cjs|json|html|css|scss|md|yml|yaml|toml|py|php|java|go|rs|sql|sh|env|xml|vue|svelte|txt|mod|lock)$/i;
const ZIP_SKIP=/(?:^|\/)(?:node_modules|vendor|dist|build|coverage|\.git|\.next|\.nuxt|\.venv|venv|__pycache__)(?:\/|$)/i;
function zipFinding(level,title,file,line,description,recommendation){return {level,title,file,line,description,recommendation};}
function inspectZipText(path,content,out){
 const lines=content.split(/\r?\n/),ext=path.split(".").pop().toLowerCase();
 if(window.IDASecurityEngine)out.push(...window.IDASecurityEngine.scanSecrets(path,content));
 if(ext==="json"){try{JSON.parse(content)}catch(e){out.push(zipFinding("high","JSON invalide",path,0,"Syntaxe JSON invalide : "+e.message,"Corriger la syntaxe puis valider le fichier."));}}
 lines.forEach((line,i)=>{const n=i+1;
  if(/\beval\s*\(/.test(line))out.push(zipFinding("high","Utilisation de eval()",path,n,"Du texte est exécuté comme du code. Le risque dépend de sa provenance.","Remplacer eval() par une logique explicite ou un parseur adapté."));
  if(/innerHTML\s*=/.test(line))out.push(zipFinding("medium","Affectation directe à innerHTML",path,n,"Une donnée non fiable peut créer une faille XSS.","Préférer textContent ou assainir le HTML."));
  if(/\bconsole\.(?:log|debug)\s*\(/.test(line)&&!/(?:test|spec)\./i.test(path))out.push(zipFinding("low","Trace de débogage",path,n,"Un appel console est présent dans un fichier applicatif.","Retirer les traces inutiles avant la mise en production."));
  if(/\bTODO\b|\bFIXME\b/.test(line))out.push(zipFinding("info","Marqueur TODO/FIXME",path,n,"Le code signale un travail potentiellement inachevé.","Vérifier si cette tâche reste à faire."));
  if(/https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?/i.test(line))out.push(zipFinding("medium","Adresse locale codée en dur",path,n,"Cette URL peut ne pas fonctionner en production.","Utiliser une configuration par environnement."));
 });
 if(/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(path)&&/\bfetch\s*\(/.test(content)&&!/\b(?:catch|try\s*\{)/.test(content))out.push(zipFinding("info","Gestion des erreurs réseau à vérifier",path,0,"Un appel fetch existe sans gestion d’erreur évidente. Vérification approximative.","Vérifier les statuts HTTP et gérer les erreurs réseau."));
}
function renderZipFindings(findings){
 const host=document.getElementById("zipFindings");host.replaceChildren();
 if(!findings.length){const p=document.createElement("p");p.className="metric-line";p.textContent="Aucune alerte détectée par les règles activées. Cela ne prouve pas l’absence de bugs.";host.append(p);return;}
 const order={critical:0,high:1,medium:2,low:3,info:4};findings.sort((a,b)=>(order[a.level]??5)-(order[b.level]??5));
 findings.forEach(f=>{const el=document.createElement("article");el.className="finding";const badge=document.createElement("span");badge.className="severity "+(f.level==="critical"||f.level==="high"?"high":f.level==="medium"?"medium":"low");badge.textContent=f.level.toUpperCase();const body=document.createElement("div"),h=document.createElement("h3"),p=document.createElement("p"),d=document.createElement("p"),code=document.createElement("code"),file=document.createElement("span");h.textContent=f.title;p.textContent=f.description;code.textContent=f.recommendation;d.append(code);body.append(h,p,d);file.className="file";file.textContent=f.file+(f.line?" · ligne "+f.line:"");el.append(badge,body,file);host.append(el);});
}
document.getElementById("zipForm").addEventListener("submit",async e=>{
 e.preventDefault();const byId=id=>document.getElementById(id),file=byId("zipFile").files[0],btn=byId("zipForm").querySelector('button[type="submit"]');byId("zipError").textContent="";if(!file)return;
 if(!window.JSZip){byId("zipError").textContent="Le module ZIP n’a pas pu être chargé. Vérifiez votre connexion puis rechargez la page.";return;}
 if(file.size>30*1024*1024){byId("zipError").textContent="Archive trop volumineuse : limite de 30 Mo.";return;}
 btn.disabled=true;btn.textContent="Analyse locale…";byId("zipResults").classList.remove("hidden");byId("zipNotice").textContent="Lecture de l’archive…";byId("zipFindings").replaceChildren();
 try{
  const archive=await JSZip.loadAsync(file,{checkCRC32:false}),entries=Object.values(archive.files).filter(x=>!x.dir&&!ZIP_SKIP.test(x.name));
  const candidates=entries.filter(x=>(ZIP_TEXT_EXT.test(x.name)||ZIP_META_FILE.test(x.name))&&!x.name.split("/").some(part=>part.startsWith(".git"))).slice(0,300),findings=[],sourceFiles=[];let inspected=0,totalBytes=0,tooLarge=0;
  for(const entry of candidates){try{const meta=entry._data||{},declared=Number(meta.uncompressedSize),compressed=Number(meta.compressedSize);if(!Number.isFinite(declared)||declared<0||declared>1024*1024||totalBytes+declared>25*1024*1024||(compressed>0&&declared/compressed>200)){tooLarge++;continue;}totalBytes+=declared;const data=await entry.async("uint8array");if(data.byteLength>1024*1024||data.byteLength>declared){tooLarge++;continue;}const content=new TextDecoder("utf-8",{fatal:false}).decode(data);inspected++;sourceFiles.push({path:entry.name,content});inspectZipText(entry.name,content,findings);}catch{tooLarge++;}}
  let dependencyAudit={findings:[],packages:0,status:"Moteur OSV indisponible."};if(window.IDASecurityEngine){dependencyAudit=await window.IDASecurityEngine.auditDependencies(sourceFiles);findings.push(...dependencyAudit.findings);if(dependencyAudit.packages&&!dependencyAudit.findings.length)findings.push(zipFinding("info","Aucune vulnérabilité OSV trouvée","Dépendances",0,dependencyAudit.packages+" dépendances épinglées vérifiées dans OSV.dev.","Vérifier également les dépendances non reconnues et relancer les tests."));if(dependencyAudit.status&&!dependencyAudit.status.includes("terminée"))findings.push(zipFinding("info","Audit des dépendances incomplet","Dépendances",0,dependencyAudit.status,"Relancer avec une connexion stable ou vérifier sur OSV.dev."));}
  if(!inspected)findings.push(zipFinding("info","Aucun fichier compatible analysé","—",0,"Aucun fichier texte compatible n’a été trouvé dans les limites définies.","Vérifier le contenu de l’archive et les extensions prises en charge."));
  const counts={critical:0,high:0,medium:0,low:0,info:0};findings.forEach(f=>counts[f.level]=(counts[f.level]||0)+1);
  lastZipReport={version:"2.3.0",archive:file.name,archiveBytes:file.size,filesInArchive:entries.length,filesInspected:inspected,filesSkipped:Math.max(0,entries.length-inspected-tooLarge),filesOverLimit:tooLarge,counts,findings,engines:{static:"IDA rules",secrets:"IDA Secret Rules",dependencies:"OSV.dev",dependencyPackages:dependencyAudit.packages,dependencyStatus:dependencyAudit.status},generatedAt:new Date().toISOString(),execution:"Aucun code exécuté; analyse statique locale dans le navigateur."};window.dispatchEvent(new CustomEvent("ida:report-ready",{detail:{kind:"zip",report:lastZipReport}}));
  byId("zipSummary").textContent=inspected+" fichiers inspectés · "+findings.length+" observations · "+tooLarge+" fichiers ignorés pour dépassement de limite.";
  byId("zipNotice").textContent="Analyse terminée dans votre navigateur. Le contenu du ZIP n’a pas été envoyé à IDA BugFix. Alertes heuristiques : aucun code exécuté et aucun fichier corrigé.";renderZipFindings(findings);
 }catch(err){byId("zipError").textContent="Impossible de lire cette archive ZIP : "+(err.message||"format non reconnu");byId("zipResults").classList.add("hidden");}
 finally{btn.disabled=false;btn.textContent="Analyser le ZIP →";}
});
document.getElementById("zipResetBtn").addEventListener("click",()=>{document.getElementById("zipResults").classList.add("hidden");document.getElementById("zipFile").value="";document.getElementById("zipFileName").textContent="Aucun fichier sélectionné";document.getElementById("zipError").textContent="";lastZipReport=null;});
document.getElementById("zipReportBtn").addEventListener("click",()=>{if(!lastZipReport)return;const blob=new Blob([JSON.stringify(lastZipReport,null,2)],{type:"application/json;charset=utf-8"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="ida-bugfix-2.0.9-rapport-zip.json";a.click();URL.revokeObjectURL(a.href);});
