'use strict';
const $=id=>document.getElementById(id);
const results={};const evidenceHistory=[];let tx=(new URLSearchParams(location.search)).get('tx')||'';
if(tx)$('tx').textContent=tx;
async function execute(path, body){
 const key=$('key').value.trim();if(!key)throw Error('Informe a chave do operador.');
 const response=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CIAM-Lab-Key':key},body:JSON.stringify(body||{})});
 let value;try{value=await response.json()}catch{throw Error('Resposta inválida HTTP '+response.status)}
 if(!response.ok)throw Error('HTTP '+response.status+' · '+JSON.stringify(value));return value;
}
function display(section,v){results[section]=v;evidenceHistory.push({section,at:new Date().toISOString(),result:v});$(`${section}-result`).textContent=JSON.stringify(v,null,2);let status=$(`${section}-state`);status.textContent=v.result||v.decision||'RESULTADO';status.className='status '+(/PASS|ALLOW|VERIFIED/.test(status.textContent)?'pass':/FAIL|BLOCKED|DENY/.test(status.textContent)?'fail':'');}
async function action(which){
 let section=which==='pairwise'?'pairwise':which==='claims'?'claims':which==='consent'?'consent':'assurance';
 try{
  if(which==='pairwise')display(section,await execute('/api/m3/s7/pairwise',{same_person_attested:$('attested').checked}));
  if(which==='claims')display(section,await execute('/api/m3/s7/claims'));
  if(which==='consent')display(section,await execute('/api/m3/s7/consent',{link_id:$('link-id').value.trim()}));
  if(which==='start'){
   let r=await execute('/api/m3/s7/transaction/start',{risk_score:Number($('risk').value),unknown_device:$('unknown').checked,operation:'fintech-transfer'});
   tx=r.tx;const url=new URL(location.href);url.searchParams.set('tx',tx);window.history.replaceState(null,'',url.pathname+url.search+url.hash);$('tx').textContent=tx;display(section,r);
  }
  if(which==='aal-start'){
   if(!tx)throw Error('Inicie uma transação antes do step-up.');
   location.assign('http://localhost:8185/s7/stepup?tx='+encodeURIComponent(tx));return;
  }
  if(which==='aal-confirm'){if(!tx)throw Error('Transação ausente');display(section,await execute('/api/m3/s7/transaction/aal2',{tx}));}
  if(which==='n2'){
   if(!tx)throw Error('Transação ausente');const a=$('n2-assertion').value.trim();if(!a)throw Error('Falta atestação N2 assinada.');
   display(section,await execute('/api/m3/s7/transaction/n2',{tx,signed_provider_jwt:a}));$('n2-assertion').value='';
  }
  if(which==='provider'){
   if(!tx)throw Error('Transação ausente');const a=$('assertion').value.trim();if(!a)throw Error('Falta uma atestação real assinada por provedor externo.');
   display(section,await execute('/api/m3/s7/transaction/provider',{tx,signed_provider_jwt:a}));$('assertion').value='';
  }
  if(which==='decision'){if(!tx)throw Error('Transação ausente');display(section,await execute('/api/m3/s7/transaction/decision',{tx}));}
 }catch(e){display(section,{result:'BLOCKED',reason:String(e.message||e)})}
}
document.querySelectorAll('[data-action]').forEach(b=>b.addEventListener('click',()=>action(b.dataset.action)));
$('check').addEventListener('click',()=>action('pairwise'));
$('download').addEventListener('click',()=>{
 const safe=({provider_nonce_for_trusted_bridge,subject_ref_for_trusted_bridge,signed_provider_jwt,...rest})=>rest;
 const report={schema:'magalu-section7-acceptance-v1',at:new Date().toISOString(),
   assessments:Object.fromEntries(Object.entries(results).map(([k,v])=>[k,safe(v)])),
   execution_history:evidenceHistory.map(h=>({...h,result:safe(h.result)})),limitations:['No raw ID/access tokens included','N2 source of truth and vendor provisioning must be verified separately','AAL is not IAL','Operator attestation is not identity federation']};
 const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='magalu-section7-sanitized-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);
});
