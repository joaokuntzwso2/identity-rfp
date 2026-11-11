(() => {
'use strict';
const byId = id => document.getElementById(id);
const text = (id,v) => { byId(id).textContent=String(v ?? '—'); };
const yes = x => x===true;
function verdict(id,passed,detail){
 text(id,passed===true?'PASS':passed===false?'BLOCKED':'PENDENTE');
 text(id+'-detail',detail);
}
function present(report){
 const t=report?.tests||{}, r=report?.resource_api||{}, facts=report?.input_evidence||{};
 verdict('identity',yes(facts.subject_signature_verified)&&yes(facts.actor_signature_verified)&&yes(facts.subject_actor_distinct),
  `Assinatura de Ana: ${yes(facts.subject_signature_verified)} · Bruno: ${yes(facts.actor_signature_verified)} · Identidades distintas: ${yes(facts.subject_actor_distinct)}`);
 const delegated=t.delegated_read||{};
 verdict('exchange',delegated.result==='PASS',
  `WSO2 HTTP ${delegated.http??'—'} · Subject preservado: ${yes(delegated.subject_preserved)} · Actor preservado: ${yes(delegated.actor_preserved)} · Scope reduzido: ${yes(delegated.scope_reduced)}`);
 const read=r.read||{};
 verdict('read',read.http===200&&read.decision==='ALLOW'&&yes(read.token_verified)&&yes(read.audience_verified),
  `HTTP ${read.http??'—'} · ${read.reason||'sem resposta'} · JWT e audience verificados: ${yes(read.token_verified)&&yes(read.audience_verified)}`);
 const approve=r.approval_check||{};
 verdict('approve',approve.http===403&&approve.reason==='INSUFFICIENT_SCOPE'&&yes(approve.token_verified),
  `HTTP ${approve.http??'—'} · ${approve.reason||'sem resposta'} · Nenhum pedido foi alterado`);
 text('verdict',report.result==='PASS'?'PASS · ACEITE TÉCNICO':report.result||'INCOMPLETE');
 text('verdict-detail',report.result==='PASS'?'Delegação, resource API e audience dedicado verificadas. Consulte o relatório sanitizado.':
  'Não declarar aceite até passar a proteção por scope e o audience dedicado. '+(report.next_action||''));
}
async function refresh(){
 const r=await fetch('/api/m3/exchange/status',{cache:'no-store',credentials:'same-origin'});
 if(!r.ok)throw new Error('HTTP '+r.status);
 const d=await r.json();
 const ready=c=>c?.present&&c.secure&&c.looks_jwt&&c.remaining_seconds_unverified>30;
 text('ana',ready(d.capture?.subject)?'JWT capturado · verificação na execução':'Recapture o JWT de Ana');
 text('bruno',ready(d.capture?.actor)?'JWT capturado · verificação na execução':'Recapture o JWT de Bruno');
 const dedicated=d.resource_audience?.mode==='DEDICATED_RESOURCE'&&d.resource_audience?.readback_verified===true;
 text('audience',dedicated?'Audience da API cadastrado e lido do WSO2':'Audience dedicado ausente ou não verificado: aceite bloqueado');
 byId('run').disabled=!d.capture?.can_attempt||!dedicated;
 if(d.report)present(d.report);
}
byId('refresh').addEventListener('click',()=>refresh().catch(e=>{text('notice',e.message);byId('notice').className='notice error'}));
byId('run').addEventListener('click',async()=>{
 const key=byId('key').value.trim();
 if(!key){text('notice','Informe DEMO_OPERATOR_KEY.');return;}
 byId('run').disabled=true;text('notice','Executando WSO2 Token Exchange e duas chamadas à API protegida…');
 try{
  const r=await fetch('/api/m3/exchange/run',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',
    headers:{'Content-Type':'application/json','X-CIAM-Lab-Key':key},body:'{}'});
  const d=await r.json();
  if(!r.ok){throw new Error('HTTP '+r.status+' · '+String(d.detail||d.error||'Falha de execução').slice(0,180));}
  present(d);text('notice',d.result==='PASS'?'Prova HTTP concluída. Exporte a evidência e registre a data da execução.':'Execução feita, mas ainda há critérios incompletos.');
  byId('notice').className='notice'+(d.result==='PASS'?' success':'');
 }catch(e){text('notice',e.message);byId('notice').className='notice error';}
 finally{await refresh().catch(()=>{});}
});
refresh().catch(e=>{text('notice','Não foi possível obter preparação: '+e.message);byId('notice').className='notice error';});
})();
