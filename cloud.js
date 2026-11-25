/* IDA BugFix cloud accounts and report sync — dedicated Supabase project. */
(() => {
 const $=id=>document.getElementById(id), CFG="ida-bugfix-supabase-config";
 const DEFAULT_CONFIG={url:"https://jahqximmxhycoslprifl.supabase.co",key:"sb_publishable_vGcjL9tVl4ky8f50gHqwaw_fcJCzjIm"};
 let client=null,user=null;
 const say=t=>{if($("cloudStatus"))$("cloudStatus").textContent=t};
 const config=()=>{try{return {...DEFAULT_CONFIG,...JSON.parse(localStorage.getItem(CFG)||"{}")}}catch{return DEFAULT_CONFIG}};
 function init(){
  const c=config();
  if(!$("supabaseUrl")||!$("supabaseKey"))return;
  $("supabaseUrl").value=c.url||"";
  $("supabaseKey").value=c.key||"";
  if(!window.supabase?.createClient){say("Bibliothèque Supabase indisponible : vérifiez la connexion.");return}
  try{
   client=window.supabase.createClient(c.url,c.key);
   if(!localStorage.getItem(CFG))localStorage.setItem(CFG,JSON.stringify(c));
   client.auth.getSession().then(({data,error})=>{
    if(error)throw error;
    if(data.session)activate(data.session.user);
    else say("Base IDA BugFix connectée. Créez un compte ou connectez-vous.");
   }).catch(()=>say("Base prête. Connectez-vous pour activer la synchronisation."));
  }catch{say("Configuration Supabase invalide.");}
 }
 function saveConfig(){
  const url=$("supabaseUrl").value.trim().replace(/\/$/, ""),key=$("supabaseKey").value.trim();
  if(!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url)||!key){say("URL Supabase ou clé publique invalide.");return}
  localStorage.setItem(CFG,JSON.stringify({url,key}));client=window.supabase.createClient(url,key);say("Configuration enregistrée. Vous pouvez créer un compte ou vous connecter.");
 }
 async function activate(u){
  user=u;$("cloudUser").textContent=u.email||"Compte IDA";say("Connecté : "+(u.email||"compte actif"));
  const {data:existingProfile,error:profileReadError}=await client.from("ida_profiles").select("user_id").eq("user_id",u.id).maybeSingle();
  if(profileReadError)throw profileReadError;
  if(!existingProfile){
   const {error}=await client.from("ida_profiles").insert({user_id:u.id,display_name:u.email||null});
   if(error)throw error;
  }
  const [{data:licenses,error:licenseError},{count,error:countError}] = await Promise.all([
   client.from("ida_licenses").select("plan,status,ends_at").eq("user_id",u.id).eq("status","active").order("created_at",{ascending:false}).limit(1),
   client.from("ida_reports").select("id",{count:"exact",head:true}).eq("user_id",u.id)
  ]);
  if(licenseError)throw licenseError;if(countError)throw countError;
  const license=licenses?.[0];
  $("cloudPlan").textContent="Offre : "+(license?.plan||"free").toUpperCase()+(license?.ends_at?" · jusqu'au "+new Date(license.ends_at).toLocaleDateString("fr-FR"):"");
  $("cloudReportCount").textContent=String(count||0);
  await syncLocal();
 }
 async function syncLocal(){
  if(!client||!user)return;
  let list=[];try{list=JSON.parse(localStorage.getItem("ida-bugfix-pro-history-v1")||"[]")}catch{}
  for(const row of list.slice(0,20)){
   const report=row.report||{},kind=["github","zip","site"].includes(row.kind)?row.kind:"github";
   const rawDate=report.generatedAt||row.savedAt;
   if(!rawDate)continue;
   const createdAt=new Date(rawDate);
   if(Number.isNaN(createdAt.getTime()))continue;
   const stamp=createdAt.toISOString();
   const {data:existing,error:lookupError}=await client.from("ida_reports").select("id").eq("user_id",user.id).eq("kind",kind).eq("created_at",stamp).maybeSingle();
   if(lookupError)throw lookupError;
   if(!existing){
    const {error}=await client.from("ida_reports").insert({user_id:user.id,kind,title:String(row.title||"Analyse").slice(0,240),report,created_at:stamp});
    if(error)throw error;
   }
  }
  const {count,error}=await client.from("ida_reports").select("id",{count:"exact",head:true}).eq("user_id",user.id);
  if(error)throw error;
  $("cloudReportCount").textContent=String(count||0);
  say("Synchronisation terminée · "+(count||0)+" rapport(s) dans le cloud.");
 }
 async function auth(action){
  if(!client){say("La base IDA BugFix n'est pas initialisée.");return}
  const email=$("cloudEmail").value.trim(),password=$("cloudPassword").value;
  if(!email||!password){say("Saisissez votre adresse e-mail et votre mot de passe.");return}
  try{
   const result=action==="signup"
    ?await client.auth.signUp({email,password,options:{emailRedirectTo:window.location.href.split("#")[0].split("?")[0]}})
    :await client.auth.signInWithPassword({email,password});
   if(result.error)throw result.error;
   if(result.data.session)await activate(result.data.user);
   else say("Compte créé. Vérifiez votre e-mail pour confirmer l'inscription, puis connectez-vous.");
  }catch(e){say("Erreur : "+(e.message||"vérifiez les paramètres Auth et les URL de redirection."))}
 }
 $("saveCloudConfig")?.addEventListener("click",saveConfig);
 $("cloudSignUp")?.addEventListener("click",()=>auth("signup"));
 $("cloudSignIn")?.addEventListener("click",()=>auth("signin"));
 $("cloudSignOut")?.addEventListener("click",async()=>{
  if(client)await client.auth.signOut();user=null;
  $("cloudUser").textContent="Non connecté";$("cloudPlan").textContent="Offre : Free";
  $("cloudReportCount").textContent="0";say("Session fermée.");
 });
 window.addEventListener("ida:report-ready",()=>{if(user)syncLocal().catch(e=>say("Synchronisation à vérifier : "+(e.message||"erreur cloud")))});
 init();
})();