/* IDA BugFix Pro: historique local, filtres et rapports imprimables. */
(() => {
 const KEY="ida-bugfix-pro-history-v1", $=id=>document.getElementById(id);
 const read=()=>{try{return JSON.parse(localStorage.getItem(KEY)||"[]")}catch{return[]}};
 const write=x=>{try{localStorage.setItem(KEY,JSON.stringify(x.slice(0,20)));return true}catch{return false}};
 const counts=r=>r.counts||{}, total=c=>Object.values(c).reduce((n,v)=>n+(Number(v)||0),0);
 function download(data,name){const b=new Blob([JSON.stringify(data,null,2)],{type:"application/json"}),u=URL.createObjectURL(b),a=document.createElement("a");a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
 function print(row){
  const r=row.report||{}, fs=r.findings||r.diagnostics||[], c=counts(r);
  const esc=s=>String(s??"").replace(/[&<>"']/g,x=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[x]));
  const rows=fs.map(f=>'<tr><td>'+esc(f.level||f.category||"—")+'</td><td>'+esc(f.title)+'</td><td>'+esc(f.file||f.url||"—")+(f.line?" · ligne "+esc(f.line):"")+'</td><td>'+esc(f.description||"")+'</td><td>'+esc(f.fix||f.recommendation||f.display||"")+'</td></tr>').join("");
  const scores=(r.scores||[]).map(s=>'<li>'+esc(s.label)+': <b>'+esc(s.score??"—")+'/100</b></li>').join("");
  const w=window.open("","_blank");if(!w){alert("Autorisez les fenêtres pop-up pour créer le rapport imprimable.");return}
  w.document.write('<!doctype html><html lang="fr"><meta charset="utf-8"><title>Rapport IDA BugFix</title><style>body{font:13px/1.5 Arial;color:#17251b;margin:30px}h1{font-size:24px}table{border-collapse:collapse;width:100%;font-size:11px}td,th{border:1px solid #dce5db;padding:7px;text-align:left;vertical-align:top}th{background:#eef4ed}button{padding:10px;background:#287844;color:white;border:0;border-radius:6px}@media print{button{display:none}body{margin:12mm}tr{break-inside:avoid}}</style><body><button onclick="window.print()">Imprimer / Enregistrer en PDF</button><h1>IDA BugFix — Rapport professionnel</h1><b>'+esc(row.title)+'</b><p>'+esc(new Date(row.savedAt).toLocaleString("fr-FR"))+' · '+esc(row.kind)+'</p><p>'+Object.entries(c).map(([k,v])=>esc(k.toUpperCase())+": "+esc(v)).join(" · ")+'</p>'+(scores?'<h2>Scores</h2><ul>'+scores+'</ul>':"")+'<h2>Constats ('+fs.length+')</h2><table><tr><th>Niveau</th><th>Constat</th><th>Emplacement</th><th>Explication</th><th>Recommandation</th></tr>'+rows+'</table><p>Les alertes sont des pistes à vérifier. Ce rapport ne constitue pas une certification de sécurité.</p></body></html>');
  w.document.close();
 }
 function render(){
  const host=$("proHistoryList");if(!host)return;const list=read();host.replaceChildren();
  $("proHistoryCount").textContent=list.length+" / 20 rapports";$("proHistoryEmpty").classList.toggle("hidden",list.length>0);
  list.forEach((row,i)=>{const el=document.createElement("article");el.className="pro-history-item";const info=document.createElement("div"),b=document.createElement("b"),s=document.createElement("small"),meta=document.createElement("span");b.textContent=row.title;s.textContent=new Date(row.savedAt).toLocaleString("fr-FR")+" · "+row.kind;meta.textContent=total(counts(row.report))+" observations";
   info.append(b,s,meta);const actions=document.createElement("div");actions.className="pro-history-actions";
   [["Rapport PDF",()=>print(row)],["JSON",()=>download(row.report,"ida-bugfix-"+row.kind+".json")],["×",()=>{const a=read();a.splice(i,1);write(a);render()}]].forEach(([label,fn])=>{const btn=document.createElement("button");btn.className="button secondary";btn.textContent=label;btn.addEventListener("click",fn);actions.append(btn)});
   el.append(info,actions);host.append(el);
  });
 }
 function filters(){
  [["findingsList","analysisPanel"],["zipFindings","zip-scan"],["siteAuditList","siteResults"]].forEach(([id])=>{const host=$(id);if(!host||host.dataset.pro)return;host.dataset.pro="1";
   const bar=document.createElement("div");bar.className="pro-filter-bar";const q=document.createElement("input");q.type="search";q.placeholder="Rechercher un constat…";q.setAttribute("aria-label","Rechercher un constat");
   const sel=document.createElement("select");sel.setAttribute("aria-label","Filtrer par gravité");[["all","Tous les niveaux"],["critical","Critique"],["high","Élevé"],["medium","Moyen"],["low","Faible"],["info","Information"]].forEach(([v,t])=>{const o=document.createElement("option");o.value=v;o.textContent=t;sel.append(o)});
   const apply=()=>host.querySelectorAll(".finding").forEach(el=>{const badge=(el.querySelector(".severity")?.textContent||"").toLowerCase(),v=sel.value,term=q.value.toLowerCase();const aliases={critical:"critical critique",high:"high élevé",medium:"medium moyen",low:"low faible",info:"info information"};el.hidden=!( (v==="all"||aliases[v].split(" ").some(x=>badge.includes(x))) && el.textContent.toLowerCase().includes(term));});
   q.addEventListener("input",apply);sel.addEventListener("change",apply);bar.append(q,sel);host.parentNode.insertBefore(bar,host);new MutationObserver(apply).observe(host,{childList:true,subtree:true});
  });
 }
 window.IDAPro={render,print,download};
 window.addEventListener("ida:report-ready",e=>{const d=e.detail;if(!d?.report)return;const title=d.report.repository||d.report.archive||d.report.url||"Analyse";const ok=write([{kind:d.kind,title,report:d.report,savedAt:new Date().toISOString()},...read()]);render();if($("proStorageStatus"))$("proStorageStatus").textContent=ok?"Rapport enregistré localement sur cet appareil.":"Stockage local plein : exportez le rapport JSON."});
 $("proPrintCurrent")?.addEventListener("click",()=>{const x=read()[0];if(x)print(x);else alert("Aucun rapport enregistré.")});
 $("proExportHistory")?.addEventListener("click",()=>download(read(),"ida-bugfix-historique.json"));
 $("proClearHistory")?.addEventListener("click",()=>{if(confirm("Effacer l'historique local ?")){localStorage.removeItem(KEY);render()}});
 filters();render();
})();