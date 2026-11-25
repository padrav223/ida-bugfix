const $ = (id) => document.getElementById(id);
let lastReport = null;
// Scanner revision: prioritise environment files and package metadata before the general file cap.
const MAX_FILES = 60, MAX_FILE_BYTES = 150000;
const SECRET_FILE = /^\.env(?:\.(?!example$|sample$|template$)[a-z0-9_-]+)?$/i;
const TEXT_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs|json|html|css|scss|md|yml|yaml|toml|py|php|java|go|rs|sql|sh)$/i;
function escapeText(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function parseRepoUrl(value){
  let u; try{u=new URL(value)}catch{throw Error("Adresse invalide. Collez une URL GitHub complète.");}
  if(u.hostname!=="github.com") throw Error("Seuls les dépôts hébergés sur github.com sont acceptés.");
  const p=u.pathname.split("/").filter(Boolean);
  if(p.length<2) throw Error("L'adresse doit être au format github.com/proprietaire/depot.");
  return {owner:p[0],repo:p[1].replace(/\.git$/,"")};
}
async function githubJSON(url){
  const r=await fetch(url,{headers:{Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}});
  if(!r.ok){if(r.status===404)throw Error("Dépôt introuvable ou privé. Cette version analyse uniquement les dépôts publics.");if(r.status===403||r.status===429)throw Error("Limite de consultation GitHub atteinte. Réessayez plus tard.");throw Error("GitHub a répondu avec l'erreur HTTP "+r.status+".");}
  return r.json();
}
function finding(level,title,file,line,description,fix){
  return {level,title,file,line,description,fix};
}
function inspectFile(path,content,findings){
  const lines=content.split(/\r?\n/), ext=path.split(".").pop().toLowerCase();
  const add=(l,t,d,f)=>findings.push(finding(l,t,path,t?lines.indexOf(t)+1:0,d,f));
  if(ext==="json"){try{JSON.parse(content)}catch(e){findings.push(finding("high","JSON invalide",path,0,"Le fichier ne peut pas être analysé comme JSON : "+e.message,"Corriger la syntaxe JSON puis relancer l'analyse."));}}
  lines.forEach((line,i)=>{
    if(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)||/(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-\/+=]{16,}["']/i.test(line))
      findings.push(finding("critical","Possible secret exposé",path,i+1,"Une chaîne ressemblant à une clé ou un secret est présente. Sa valeur n'est pas affichée.","Révoquer la clé si elle est réelle, puis la déplacer vers des variables d'environnement."));
    if(/\beval\s*\(/.test(line)) findings.push(finding("high","Utilisation de eval()",path,i+1,"eval() exécute du texte comme du code et peut créer une faille si l'entrée n'est pas maîtrisée.","Éviter eval() et utiliser une logique explicite ou un parseur sûr."));
    if(/innerHTML\s*=/.test(line)) findings.push(finding("medium","Affectation directe à innerHTML",path,i+1,"Si la valeur contient des données non fiables, cela peut permettre une injection HTML ou JavaScript.","Préférer textContent ou assainir strictement le HTML avant insertion."));
    if(/\bconsole\.(?:log|debug)\s*\(/.test(line)&&!/(?:test|spec)\./i.test(path)) findings.push(finding("low","Trace console présente",path,i+1,"Un appel console peut laisser des informations de débogage en production.","Retirer ou contrôler cette trace avant la mise en production."));
    if(/\bTODO\b|\bFIXME\b/.test(line)) findings.push(finding("info","Marqueur TODO/FIXME",path,i+1,"Le code contient un élément de travail non résolu.","Vérifier si cette tâche est toujours nécessaire."));
    if(/https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?/i.test(line)) findings.push(finding("medium","URL locale codée en dur",path,i+1,"Une adresse locale peut ne pas fonctionner une fois l'application déployée.","Utiliser une configuration par environnement."));
  });
  if((ext==="js"||ext==="jsx"||ext==="ts"||ext==="tsx") && /\bfetch\s*\(/.test(content) && !/\b(?:catch|\.then\s*\([^)]*,\s*|try\s*\{)/.test(content))
    findings.push(finding("info","Vérifier la gestion des erreurs réseau",path,0,"Un appel fetch est présent, mais aucune gestion d'erreur évidente n'a été repérée dans ce fichier. Vérification heuristique, pas une preuve de bug.","Vérifier les statuts HTTP et traiter les erreurs réseau."));
}
function renderFindings(findings){
  const host=$("findingsList");host.replaceChildren();
  const order={critical:0,high:1,medium:2,low:3,info:4};
  findings.sort((a,b)=>(order[a.level]??5)-(order[b.level]??5));
  for(const f of findings){
    const el=document.createElement("article");el.className="finding";
    const sev=document.createElement("span");sev.className="severity "+(f.level==="critical"||f.level==="high"?"high":f.level==="medium"?"medium":"low");sev.textContent=f.level.toUpperCase();
    const body=document.createElement("div"),h=document.createElement("h3"),p=document.createElement("p"),detail=document.createElement("p"),code=document.createElement("code"),file=document.createElement("span");
    h.textContent=f.title;p.textContent=f.description;code.textContent=f.fix;detail.append(code);file.className="file";file.textContent=f.file+(f.line?" · ligne "+f.line:"");
    body.append(h,p,detail);el.append(sev,body,file);host.append(el);
  }
}
function updateStats(files,findings){
  const cards=document.querySelectorAll(".stat-card .stat-value");
  if(cards[0])cards[0].textContent=String(files);
  if(cards[1])cards[1].textContent=String(findings.filter(x=>["critical","high","medium"].includes(x.level)).length);
  if(cards[2])cards[2].textContent="0";
}
async function runScan(url){
  const {owner,repo}=parseRepoUrl(url), base="https://api.github.com/repos/"+encodeURIComponent(owner)+"/"+encodeURIComponent(repo);
  $("analysisTitle").textContent="Analyse en cours…";$("analysisSubtitle").textContent=owner+"/"+repo;
  $("analysisPanel").classList.remove("hidden");$("findingsList").replaceChildren();
  $("analysisPanel").scrollIntoView({behavior:"smooth",block:"start"});
  const repoInfo=await githubJSON(base);
  const branch=repoInfo.default_branch;
  const tree=await githubJSON(base+"/git/trees/"+encodeURIComponent(branch)+"?recursive=1");
  if(tree.truncated)throw Error("Le dépôt est trop volumineux pour une analyse complète via cette version. Analyse interrompue pour éviter un résultat trompeur.");
  const candidates=(tree.tree||[]).filter(x=>x.type==="blob"&&(TEXT_EXT.test(x.path)||SECRET_FILE.test(x.path.split("/").pop()))&&x.size<=MAX_FILE_BYTES&&!/(?:^|\/)(?:node_modules|vendor|dist|build|coverage|\.git)(?:\/|$)/.test(x.path));
  candidates.sort((a,b)=>{const rank=x=>SECRET_FILE.test(x.path.split("/").pop())?0:x.path==="package.json"?1:2;return rank(a)-rank(b)||a.path.localeCompare(b.path);});
  const selected=candidates.slice(0,MAX_FILES), findings=[];
  let read=0, skipped=Math.max(0,candidates.length-selected.length);
  for(const item of selected){
    try{
      const raw="https://raw.githubusercontent.com/"+encodeURIComponent(owner)+"/"+encodeURIComponent(repo)+"/"+encodeURIComponent(branch)+"/"+item.path.split("/").map(encodeURIComponent).join("/");
      const r=await fetch(raw);if(!r.ok)continue;
      const content=await r.text();read++;inspectFile(item.path,content,findings);
      $("analysisSubtitle").textContent="Inspection : "+read+"/"+selected.length+" fichiers";
    }catch(e){/* un fichier inaccessible n'interrompt pas les autres */}
  }
  const packageItem=selected.find(x=>x.path==="package.json");
  let scripts=[];
  if(packageItem){try{const r=await fetch("https://raw.githubusercontent.com/"+owner+"/"+repo+"/"+branch+"/package.json");const pkg=await r.json();scripts=Object.keys(pkg.scripts||{});}catch{}}
  if(!read)findings.push(finding("info","Aucun fichier texte analysable","—",0,"Aucun fichier compatible n'a pu être récupéré dans les limites définies.","Vérifier la visibilité du dépôt et les types de fichiers."));
  if(!findings.length)findings.push(finding("info","Aucun problème détecté par les règles activées","—",0,"L'analyse statique limitée n'a pas trouvé les motifs recherchés. Cela ne garantit pas l'absence de bugs.","Exécuter les tests du projet et faire une revue humaine."));
  const counts={critical:0,high:0,medium:0,low:0,info:0};findings.forEach(f=>counts[f.level]=(counts[f.level]||0)+1);
  const summary={repository:owner+"/"+repo,branch,filesRead:read,filesConsidered:selected.length,filesSkipped:skipped,counts,findings,generatedAt:new Date().toISOString(),scripts};
  lastReport=summary;renderFindings(findings);updateStats(read,findings);
  $("analysisTitle").textContent="Diagnostic réel — "+owner+"/"+repo;
  $("analysisSubtitle").textContent=read+" fichiers inspectés · branche "+branch+" · "+findings.length+" observations";
  const notice=$("analysisPanel").querySelector(".notice");
  notice.textContent="Analyse statique réelle, limitée à "+MAX_FILES+" fichiers texte de moins de "+Math.round(MAX_FILE_BYTES/1000)+" Ko. Aucun code n'a été exécuté. Les alertes heuristiques doivent être vérifiées.";
  const label=$("analysisPanel").querySelector(".demo-label");if(label){label.textContent="ANALYSE STATIQUE";label.classList.remove("demo-label");label.classList.add("step-badge");}
  if(skipped) $("analysisSubtitle").textContent+=" · "+skipped+" fichiers supplémentaires ignorés";
  return summary;
}
$("scanForm").addEventListener("submit",async e=>{
  e.preventDefault();$("formError").textContent="";const btn=$("scanForm").querySelector('button[type="submit"]');btn.disabled=true;btn.textContent="Analyse…";
  try{await runScan($("repoUrl").value.trim());}
  catch(err){$("formError").textContent=err.message||"Une erreur est survenue."; $("analysisTitle").textContent="Analyse non terminée";}
  finally{btn.disabled=false;btn.innerHTML='Analyser <span>→</span>';}
});
$("demoBtn").addEventListener("click",()=>{
  $("formError").textContent="La démonstration fictive a été retirée. Collez l'URL d'un dépôt GitHub public pour lancer une vraie inspection statique.";
});
$("resetBtn").addEventListener("click",()=>{$("analysisPanel").classList.add("hidden");$("repoUrl").value="";$("formError").textContent="";lastReport=null;$("new-scan").scrollIntoView({behavior:"smooth"});});
$("reportBtn").addEventListener("click",()=>{
  if(!lastReport){$("formError").textContent="Aucun rapport réel à exporter.";return;}
  const blob=new Blob([JSON.stringify(lastReport,null,2)],{type:"application/json;charset=utf-8"}),a=document.createElement("a");
  a.href=URL.createObjectURL(blob);a.download="ida-bugfix-rapport.json";a.click();URL.revokeObjectURL(a.href);
});
$("menuBtn").addEventListener("click",()=>$("sidebar").classList.toggle("open"));
document.querySelectorAll(".nav-link").forEach(a=>a.addEventListener("click",()=>$("sidebar").classList.remove("open")));
