/* IDA BugFix AST Security Engine — Acorn-based JavaScript analysis.
   Static analysis only: no project code is executed. */
(() => {
  const JS_EXT=/\.(?:js|mjs|cjs)$/i;
  const MAX_NODES=100000;
  const RULES={
    "js.tainted-eval":{level:"critical",title:"Entrée non fiable exécutée comme du code",fix:"Supprimer eval()/Function() et remplacer par une logique explicite. Ne jamais transformer une entrée utilisateur en code."},
    "js.dom-xss":{level:"high",title:"Injection DOM potentielle (XSS)",fix:"Utiliser textContent ou créer les éléments DOM explicitement. Si du HTML riche est indispensable, appliquer un assainisseur maintenu et une politique stricte."},
    "js.command-injection":{level:"critical",title:"Injection de commande système potentielle",fix:"Éviter le shell. Utiliser spawn/execFile avec un exécutable fixe et un tableau d'arguments validés; ne jamais concaténer des entrées utilisateur."},
    "js.sql-injection":{level:"critical",title:"Injection SQL potentielle",fix:"Utiliser des requêtes paramétrées et transmettre les valeurs séparément du texte SQL."},
    "js.path-traversal":{level:"high",title:"Chemin de fichier contrôlé par une entrée non fiable",fix:"Résoudre le chemin sous un répertoire racine autorisé, normaliser puis vérifier qu'il reste dans cette racine. Préférer une liste blanche d'identifiants."},
    "js.ssrf":{level:"high",title:"URL de requête contrôlée par une entrée non fiable (SSRF possible)",fix:"Autoriser uniquement des domaines/protocoles connus, bloquer les plages IP internes et valider la destination après résolution DNS."},
    "js.open-redirect":{level:"medium",title:"Redirection contrôlée par une entrée non fiable",fix:"Utiliser une liste blanche de destinations ou des chemins relatifs internes."},
    "js.weak-hash":{level:"medium",title:"Algorithme de hachage faible",fix:"Utiliser SHA-256 ou mieux pour l'intégrité. Pour les mots de passe, utiliser Argon2id, scrypt ou bcrypt avec paramètres adaptés."},
    "js.insecure-tls":{level:"high",title:"Vérification TLS désactivée",fix:"Réactiver la vérification des certificats TLS. Ne pas définir rejectUnauthorized à false en production."},
    "js.weak-random":{level:"medium",title:"Générateur aléatoire non cryptographique utilisé pour un secret",fix:"Utiliser crypto.randomBytes() ou crypto.randomUUID() côté serveur, ou crypto.getRandomValues() dans le navigateur."}
  };
  const childKeys=(node)=>Object.keys(node).filter(k=>k!=="start"&&k!=="end"&&k!=="loc"&&k!=="range"&&k!=="comments"&&k!=="tokens");
  function memberName(node){
    if(!node||node.type!=="MemberExpression")return "";
    return node.computed?(node.property?.value??""):node.property?.name||"";
  }
  function isMember(node,object,property){
    return node?.type==="MemberExpression"&&memberName(node)===property&&(
      node.object?.type==="Identifier"&&node.object.name===object ||
      node.object?.type==="MemberExpression"&&memberName(node.object)===object
    );
  }
  function tainted(node,vars,depth=0){
    if(!node||depth>12)return false;
    if(node.type==="Identifier")return vars.has(node.name);
    if(node.type==="MemberExpression"){
      const obj=node.object, prop=memberName(node);
      if(obj?.type==="Identifier"&&(
        (obj.name==="req"&&["query","body","params","headers"].includes(prop))||
        (obj.name==="location"&&["search","hash"].includes(prop))||
        (obj.name==="window"&&prop==="location")
      ))return true;
      if(obj?.type==="MemberExpression"&&obj.object?.name==="req"&&["query","body","params","headers"].includes(memberName(obj)))return true;
      return tainted(obj,vars,depth+1);
    }
    if(node.type==="CallExpression"||node.type==="NewExpression"){
      const c=node.callee;
      if(c?.type==="MemberExpression"&&memberName(c)==="get"&&c.object?.type==="NewExpression"&&c.object.callee?.name==="URLSearchParams")return true;
      if(c?.type==="MemberExpression"&&c.object?.name==="URLSearchParams"&&memberName(c)==="get")return true;
      return node.arguments?.some(x=>tainted(x,vars,depth+1))||tainted(c,vars,depth+1);
    }
    if(node.type==="TemplateLiteral")return node.expressions.some(x=>tainted(x,vars,depth+1));
    if(node.type==="BinaryExpression"||node.type==="LogicalExpression")return tainted(node.left,vars,depth+1)||tainted(node.right,vars,depth+1);
    if(node.type==="ConditionalExpression")return tainted(node.test,vars,depth+1)||tainted(node.consequent,vars,depth+1)||tainted(node.alternate,vars,depth+1);
    if(node.type==="ArrayExpression")return node.elements.some(x=>tainted(x,vars,depth+1));
    if(node.type==="ObjectExpression")return node.properties.some(p=>tainted(p.value,vars,depth+1));
    if(node.type==="AwaitExpression"||node.type==="ChainExpression"||node.type==="ParenthesizedExpression")return tainted(node.argument||node.expression,vars,depth+1);
    if(node.type==="AssignmentExpression")return tainted(node.right,vars,depth+1);
    return false;
  }
  function analyze(path,source){
    const out=[];
    if(!JS_EXT.test(path))return {findings:out,parsed:false,status:"Extension non prise en charge par l'analyse AST JavaScript."};
    const parser=window.acorn;
    if(!parser?.parse)return {findings:out,parsed:false,status:"Analyse AST indisponible : le parseur Acorn n'a pas été chargé."};
    let ast;
    try{ast=parser.parse(source,{ecmaVersion:"latest",sourceType:"module",locations:true,allowHashBang:true});}
    catch(first){try{ast=parser.parse(source,{ecmaVersion:"latest",sourceType:"script",locations:true,allowHashBang:true});}
      catch(second){return {findings:out,parsed:false,status:"Fichier ignoré par l'analyse AST : syntaxe non prise en charge ou erreur de syntaxe ("+(second.message||first.message)+")."};}}
    const vars=new Set(),seen=new Set();
    const emit=(id,node,detail,confidence="high",suggestedChange=null)=>{
      const rule=RULES[id];if(!rule)return;
      const line=node?.loc?.start?.line||0,key=id+":"+line;if(seen.has(key))return;seen.add(key);
      out.push({level:rule.level,title:rule.title,file:path,line,ruleId:id,confidence,source:"IDA AST Engine",description:detail,fix:rule.fix,...(suggestedChange?{suggestedChange:{...suggestedChange,requiresReview:true}}:{})});
    };
    const stack=[ast];let visited=0;
    while(stack.length){
      const node=stack.pop();if(!node||typeof node!=="object"||typeof node.type!=="string")continue;
      if(++visited>MAX_NODES){return {findings:out,parsed:true,status:"Analyse AST arrêtée à la limite de sécurité de "+MAX_NODES+" nœuds."};}
      if(node.type==="VariableDeclarator"&&node.id?.type==="Identifier"&&tainted(node.init,vars))vars.add(node.id.name);
      if(node.type==="AssignmentExpression"&&node.left?.type==="Identifier"&&tainted(node.right,vars))vars.add(node.left.name);
      if(node.type==="CallExpression"){
        const c=node.callee, name=c?.type==="Identifier"?c.name:memberName(c), obj=c?.object;
        const arg=node.arguments?.[0], input=tainted(arg,vars);
        if((name==="eval"||name==="Function")&&input)emit("js.tainted-eval",node,"Une donnée issue d'une requête, d'un paramètre ou d'une URL atteint un exécuteur dynamique.", "high");
        if((name==="write"&&obj?.name==="document"||name==="insertAdjacentHTML")&&input)emit("js.dom-xss",node,"Une donnée non fiable atteint une méthode qui interprète du HTML.", "high");
        if(name==="exec"||name==="execSync"){
          if(input)emit("js.command-injection",node,"Une donnée non fiable atteint une commande exécutée via un shell.", "high");
        }
        if(name==="query"||name==="execute"||name==="raw"){
          if(input||node.arguments?.some(x=>x.type==="TemplateLiteral"&&tainted(x,vars)))emit("js.sql-injection",node,"Une donnée non fiable atteint un argument de requête SQL sans preuve de paramétrage.", "medium");
        }
        if((name==="join"||name==="resolve")&&obj?.name==="path"&&input)emit("js.path-traversal",node,"Un chemin construit avec une donnée non fiable peut sortir du répertoire attendu.", "medium");
        if((c?.name==="fetch"||name==="get"||name==="request"||name==="post")&&input){
          const isFetch=c?.name==="fetch"||name==="fetch";
          if(isFetch||obj?.name==="axios"||obj?.name==="http"||obj?.name==="https"||obj?.name==="got")emit("js.ssrf",node,"L'adresse ou la cible réseau dépend d'une donnée contrôlable par un utilisateur.", "medium");
        }
        if(name==="redirect"&&input)emit("js.open-redirect",node,"La destination de redirection dépend d'une entrée non fiable.", "medium");
        if(name==="createHash"&&arg?.type==="Literal"&&["md5","sha1"].includes(String(arg.value).toLowerCase())){const before=source.slice(node.start,node.end),after=before.replace("'md5'","'sha256'").replace("'sha1'","'sha256'").replace('"md5"','"sha256"').replace('"sha1"','"sha256"');emit("js.weak-hash",node,"Un algorithme de hachage cryptographique obsolète est demandé : "+arg.value+".","high",after!==before?{before,after,reason:"Proposition SHA-256; vérifier la compatibilité des empreintes et protocoles."}:null);}
      }
      if(node.type==="AssignmentExpression"&&node.left?.type==="MemberExpression"&&["innerHTML","outerHTML"].includes(memberName(node.left))&&tainted(node.right,vars)){const before=source.slice(node.start,node.end),after=before.replace(".innerHTML =",".textContent =").replace(".outerHTML =",".textContent =");emit("js.dom-xss",node,"Une valeur issue d'une entrée non fiable est affectée à "+memberName(node.left)+".","high",after!==before?{before,after,reason:"Remplacement proposé de l'interprétation HTML par du texte brut."}:null);}
      if(node.type==="Property"&&node.key?.name==="rejectUnauthorized"&&node.value?.type==="Literal"&&node.value.value===false){const before=source.slice(node.start,node.end),after=before.replace("false","true");emit("js.insecure-tls",node,"La validation du certificat TLS est explicitement désactivée.","high",after!==before?{before,after,reason:"Réactivation proposée de la validation TLS."}:null);}
      if(node.type==="CallExpression"&&node.callee?.type==="MemberExpression"&&node.callee.object?.name==="Math"&&memberName(node.callee)==="random"){
        const parentName=source.slice(Math.max(0,node.start-100),node.start).match(/\b(?:token|secret|key|session|nonce)\w*\s*[:=]\s*$/i);
        if(parentName)emit("js.weak-random",node,"Math.random() semble participer à la création d'un identifiant sensible.","medium");
      }
      const keys=childKeys(node);
      for(let i=keys.length-1;i>=0;i--){
        const value=node[keys[i]];
        if(Array.isArray(value)){for(let j=value.length-1;j>=0;j--)if(value[j]&&typeof value[j]==="object")stack.push(value[j]);}
        else if(value&&typeof value==="object")stack.push(value);
      }
    }
    return {findings:out,parsed:true,status:"Analyse AST terminée ("+visited+" nœuds parcourus).",nodes:visited};
  }
  window.IDAASTEngine={analyze};
})();
