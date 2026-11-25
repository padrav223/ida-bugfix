/* IDA BugFix SARIF 2.1.0 export for interoperability with code-scanning tools. */
(() => {
  const levelMap={critical:"error",high:"error",medium:"warning",low:"note",info:"note"};
  function slug(s){return String(s||"finding").toLowerCase().replace(/[^a-z0-9._-]+/g,"-").replace(/^-+|-+$/g,"").slice(0,80)||"finding";}
  function build(report,kind){
    const findings=report?.findings||report?.diagnostics||[];
    const rules=new Map(),results=[];
    for(const f of findings){
      const ruleId=String(f.ruleId||("IDA/"+slug(f.title)));
      if(!rules.has(ruleId))rules.set(ruleId,{id:ruleId,name:ruleId,shortDescription:{text:String(f.title||"IDA BugFix finding")},help:{text:String(f.fix||f.recommendation||"Review this finding and verify the suggested remediation.")}});
      const result={ruleId,level:levelMap[f.level]||"warning",message:{text:[f.title,f.description].filter(Boolean).join(": ")||"Finding reported by IDA BugFix."},properties:{severity:f.level||"medium",confidence:f.confidence||"heuristic",source:f.source||"IDA BugFix",remediation:f.fix||f.recommendation||""}};
      if(f.file&&f.file!=="—"){
        const physicalLocation={artifactLocation:{uri:String(f.file).replace(/\\/g,"/")}};
        if(Number(f.line)>0)physicalLocation.region={startLine:Number(f.line)};
        result.locations=[{physicalLocation}];
      }
      results.push(result);
    }
    return {$schema:"https://json.schemastore.org/sarif-2.1.0.json",version:"2.1.0",runs:[{tool:{driver:{name:"IDA BugFix",semanticVersion:"2.3.0",informationUri:"https://padrav223.github.io/ida-bugfix/",rules:[...rules.values()]}},results,properties:{sourceKind:kind||"unknown",generatedAt:report?.generatedAt||new Date().toISOString(),repository:report?.repository||null,archive:report?.archive||null}}]};
  }
  function download(report,kind,name){
    if(!report)return false;
    const payload=build(report,kind),blob=new Blob([JSON.stringify(payload,null,2)],{type:"application/sarif+json;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=url;a.download=name||"ida-bugfix-results.sarif";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return true;
  }
  window.IDASarif={build,download};
})();
