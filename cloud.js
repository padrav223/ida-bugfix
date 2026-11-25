/* IDA BugFix cloud accounts and report sync. */
(() => {
 const $=id=>document.getElementById(id), CFG="ida-bugfix-supabase-config";
 let client=null,user=null;
 const say=t=>{if($("cloudStatus"))$("cloudStatus").textContent=t};
 const config=()=>{try{return JSON.parse(localStorage.getItem(CFG)||"{}")}catch{return{}}};
 function init(){
  const c=config();if($("supabaseUrl"))$("supabaseUrl").value=c.url||"";
  if($("supabaseKey"))$("supabaseKey").value=c.key||"";
  if(!window.supabase?.createClient){say("Bibliothèque Supabase indisponible : vérifiez la connexion.");return}
  if(c.url&&c.key){try{client=window.supabase.createClient(c.url,c.key);client.auth.getSession().then(({data})=>{if(data.session)activate(data.session.user)}).catch(()=>say("Impossible de restaurer la session."))}catch{say("Configuration Supabase invalide.")}}
 }
 function saveConfig(){
  const url=$("supabaseUrl").value.trim().replace(/\/$/,""),key=$("supabaseKey").value.trim();
  if(!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url)||!key){say("URL Supabase ou clé publique invalide.");return}
  localStorage.setItem(CFG,JSON.stringify({url,key}));client=window.supabase.createClient(url,key);say("Configuration enregistrée. Vous pouvez créer un compte ou vous connecter.");
 }
 async function activate(u){
  user=u;$("cloudUser").textContent=u.email||"Compte IDA";say("Connecté : "+(u.email||"compte actif"));
  const {data:existingProfile}=await client.from("ida_profiles").select("user_id").eq("user_id",u.id).maybeSingle();
  if(!existingProfile)await client.from("ida_profiles").insert({user_id:u.id,display_name:u.email||null});
  const [{data:profile},{data:licenses},{data:reports}] = await Promise.all([
   client.from("ida_profiles").select("user_id").eq("user_id",u.id).maybeSingle(),
   client.from("ida_licenses").select("plan,status,ends_at").eq("user_id",u.id).eq("status","active").order("created_at",{ascending:false}).limit(1),
   client.from("ida_reports").select("id",{count:"exact",head:true}).eq("user_id",u.id)
  ]);
  const license=licenses?.[0];$("cloudPlan").textContent="Offre : "+(license?.plan||"free").toUpperCase()+(license?.ends_at?" · jusqu'au "+new Date(license.ends_at).toLocaleDateString("fr-FR"):"");
  $("cloudReportCount").textContent=String(reports?.length??0);
  await syncLocal();
 }
 async function syncLocal(){
  if(!client||!user)return;
  let list=[];try{list=JSON.parse(localStorage.getItem("ida-bugfix-pro-history-v1")||"[]")}catch{}
  for(const row of list.slice(0,20)){
   const report=row.report||{},kind=["github","zip","site"].includes(row.kind)?row.kind:"github";
   const key=report.generatedAt||row.savedAt;
   const {data:existing}=await client.from("ida_reports").select("id").eq("user_id",user.id).eq("kind",kind).eq("created_at",key).maybeSingle();
   if(!existing)await client.from("ida_reports").insert({user_id:user.id,kind,title:String(row.title||"Analyse").slice(0,240),report,created_at:key});
  }
  const {count}=await client.from("ida_reports").select("id",{count:"exact",head:true}).eq("user_id",user.id);
  $("cloudReportCount").textContent=String(count||0);
 }
 async function auth(action){
  if(!client){say("Configurez d'abord votre projet Supabase.");return}
  const email=$("cloudEmail").value.trim(),password=$("cloudPassword").value;
  if(!email||!password){say("Saisissez votre adresse e-mail et votre mot de passe.");return}
  try{
   const result=action==="signup"?await client.auth.signUp({email,password}):await client.auth.signInWithPassword({email,password});
   if(result.error)throw result.error;
   if(result.data.session)await activate(result.data.user);
   else say("Compte créé. Vérifiez votre e-mail pour confirmer l'inscription, puis connectez-vous.");
  }catch(e){say("Erreur d'authentification : "+(e.message||"vérifiez les paramètres Supabase"))}
 }
 $("saveCloudConfig")?.addEventListener("click",saveConfig);
 $("cloudSignUp")?.addEventListener("click",()=>auth("signup"));
 $("cloudSignIn")?.addEventListener("click",()=>auth("signin"));
 $("cloudSignOut")?.addEventListener("click",async()=>{if(client)await client.auth.signOut();user=null;$("cloudUser").textContent="Non connecté";$("cloudPlan").textContent="Offre : locale / gratuite";say("Session fermée.")});
 window.addEventListener("ida:report-ready",()=>{if(user)syncLocal()});
 init();
})();
