/* Generates an actionable checklist from current rendered findings; never edits code. */
(() => {
 const host=document.getElementById("fixPlan");if(!host)return;
 const rank={critical:0,high:1,medium:2,low:3,info:4};
 function build(){
  const items=[...document.querySelectorAll("#findingsList .finding,#zipFindings .finding,#siteAuditList .finding")].filter(x=>!x.hidden);
  host.replaceChildren();
  if(!items.length){const p=document.createElement("p");p.className="form-note";p.textContent="Aucun constat affiché. Lancez une analyse GitHub, ZIP ou site pour générer votre plan.";host.append(p);return}
  const parsed=items.map(el=>({el,level:(el.querySelector(".severity")?.textContent||"info").toLowerCase(),title:el.querySelector("h3")?.textContent||"Constat",text:el.textContent})).sort((a,b)=>(rank[a.level]??5)-(rank[b.level]??5));
  const steps=parsed.slice(0,30);
  steps.forEach((x,i)=>{const card=document.createElement("article"),b=document.createElement("b"),s=document.createElement("small");b.textContent=(i+1)+". ["+x.level.toUpperCase()+"] "+x.title;s.textContent=x.text.replace(x.title,"").trim().slice(0,450)+" — Action : examiner le contexte, appliquer une correction revue par un développeur, lancer les tests du projet puis refaire le diagnostic.";card.append(b,s);host.append(card)});
  if(parsed.length>steps.length){const p=document.createElement("p");p.className="form-note";p.textContent=(parsed.length-steps.length)+" autres constats ne sont pas affichés dans ce plan.";host.append(p)}
 }
 const observer=new MutationObserver(build);
 ["findingsList","zipFindings","siteAuditList"].forEach(id=>{const el=document.getElementById(id);if(el)observer.observe(el,{childList:true,subtree:true})});
 build();
})();
