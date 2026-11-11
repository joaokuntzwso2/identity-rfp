(() => {
'use strict';
const $=id=>document.getElementById(id);
let forward=null,reverse=null,consentReport=null,tokenReport=null;
const text=(id,v)=>{if($(id))$(id).textContent=String(v??'—')};
function msg(s,kind=''){const n=$('notice');n.textContent=s;n.className='feedback '+kind}
function setVerdict(id,value){text(id,value||'PENDENTE');const n=$(id);n.classList.remove('pass','fail','blocked');n.classList.add(value==='PASS'?'pass':value==='FAIL'?'fail':'blocked')}
function overall(){const c=consentReport?.result==='PASS',t=tokenReport?.result==='PASS';setVerdict('consent-badge',consentReport?.result);setVerdict('token-badge',tokenReport?.result);text('overall',c&&t?'ISOLAMENTO COMPROVADO':c||t?'EVIDÊNCIA PARCIAL':'AGUARDANDO PROVAS');text('overall-note',c&&t?'Consentimento e tokens validados por HTTP e WSO2.':'A conclusão depende dos dois capítulos, não apenas da aparência da interface.')}
function showConsent(r){
  consentReport=r||null;
  if(r?.phases){
    const x=r.phases.GRANTED;
    if(x){
      for(const [key,id] of [['netshoes','netshoes'],['magalupay','pay'],['reverse','reverse']]){
        text('consent-'+id,(x.tests[key]?.http??'—')+' HTTP');
        text('consent-'+id+'-reason',x.tests[key]?.reason||'—');
      }
    }
    text('revoke-status',r.phases.REVOKED?'Revogação comprovada por chamadas HTTP reais.':'Revogação ainda não comprovada.');
  }
  overall();
}
function showToken(r){
  tokenReport=r||null;
  const o=r?.controls||{},cross=r?.cross_root_exchanges||{};
  setVerdict('commerce-control',o.commerce_delegation?.result);
  setVerdict('pay-control',o.magalupay_token_issuance?.result);
  setVerdict('issuer-denial',r?.checks?.fintech_resource_rejects_commerce_issuer?'PASS':r?'BLOQUEADO':null);
  setVerdict('subject-exchange',cross.subject_only?.result);
  setVerdict('actor-exchange',cross.subject_and_actor?.result);
  const own=o.magalupay_resource_with_own_token||{};
  const foreign=o.magalupay_resource_with_commerce_token||{};
  const ownPass=own.http===200&&own.decision==='ALLOW'&&own.issuer_verified===true&&own.audience_verified===true;
  const foreignPass=foreign.http===401&&foreign.decision==='DENY'&&foreign.signature_verified===false;
  text('pay-own-http',own.http==null?'PENDENTE':`HTTP ${own.http} · ${own.decision||'SEM DECISÃO'}`);
  text('pay-own-reason',own.reason||'Nenhuma resposta de autorização.');
  text('pay-own-verification',`Assinatura: ${own.signature_verified===true?'SIM':'NÃO'} · Issuer: ${own.issuer_verified===true?'SIM':'NÃO'} · Audience: ${own.audience_verified===true?'SIM':'NÃO'}`);
  text('pay-other-http',foreign.http==null?'PENDENTE':`HTTP ${foreign.http} · ${foreign.decision||'SEM DECISÃO'}`);
  text('pay-other-reason',foreign.reason||'Nenhuma resposta de autorização.');
  text('pay-other-verification',`Rejeição pelo resource server: ${foreignPass?'COMPROVADA':'NÃO COMPROVADA'}`);
  text('resource-controls-note',ownPass&&foreignPass?
    'Dois controles HTTP comprovados. O tenant MagaluPay aceitou o próprio JWT e rejeitou o JWT Commerce. As duas tentativas de troca entre roots também precisam passar.':
    r?'Atenção: falta pelo menos um controle válido do resource server. HTTP 422 é erro de validação de requisição, não prova de isolamento.':'Aguardando execução real da prova OAuth.');
  overall();
}
function redactDisplay(){const data={consent:consentReport,token_exchange:tokenReport};text('raw-evidence',JSON.stringify(data,null,2))}
async function reload(){try{const r=await fetch('/api/m3/isolation/status',{cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Error('HTTP '+r.status);const d=await r.json();for(const b of ['magalu','netshoes','magalupay']){const el=$('session-'+b);el.textContent=d.sessions?.[b]?'AUTENTICADO':'LOGIN NECESSÁRIO';el.className='state '+(d.sessions?.[b]?'ok':'error')}
const forwardFound=d.links?.find(l=>l.source==='magalu'&&l.recipient==='netshoes');const reverseFound=d.links?.find(l=>l.source==='netshoes'&&l.recipient==='magalu');if(forwardFound&&reverseFound){forward=forwardFound.link_id;reverse=reverseFound.link_id;text('prepare-status','Vínculos existentes reconhecidos: '+forwardFound.state+' / reverso '+reverseFound.state+'.')}
text('jwt-ready',d.token_readiness?.can_attempt===true?'PRONTOS':'RECAPTURAR');text('pay-ready',d.fintech_control_ready===true?'CONFIGURADO':'CONFIGURAR');
if(d.token_readiness?.can_attempt===true){msg('As três sessões podem ser confirmadas acima. Ana e Bruno também têm JWTs locais prontos para a prova OAuth.')}else{msg('Se os JWTs expiraram, recapture Ana e Bruno pelo Terminal antes da prova OAuth.')}
showConsent(d.consent_report);showToken(d.token_report);redactDisplay()}catch(e){msg('Não foi possível atualizar o laboratório: '+e.message,'error')}}
async function action(path,payload){const key=$('operator-key').value;if(!key){msg('Informe primeiro a chave DEMO_OPERATOR_KEY do laboratório.','error');$('operator-key').focus();throw Error('OPERATOR_KEY_REQUIRED')}
const res=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CIAM-Lab-Key':key},body:JSON.stringify(payload)});let body;try{body=await res.json()}catch{body={}}if(!res.ok){const reason=body.detail||body.error_type||body.result||('HTTP '+res.status);msg(reason,'error');throw Error(reason)}return body}
async function busy(button,callback){const b=$(button),old=b.textContent;b.disabled=true;b.textContent='Executando…';try{await callback()}catch(e){if(e.message!=='OPERATOR_KEY_REQUIRED')console.warn('Lab action did not complete; inspect sanitized UI status.')}finally{b.disabled=false;b.textContent=old}}
$('refresh').addEventListener('click',reload);
$('prepare').addEventListener('click',()=>busy('prepare',async()=>{const r=await action('/api/m3/isolation/consent/prepare',{});forward=r.forward_link_id;reverse=r.reverse_link_id;text('prepare-status','Vínculos preparados. Nenhum consentimento concedido.');msg('Vínculos criados e associados às sessões reais. Agora conceda explicitamente o propósito Magalu → Netshoes.');await reload()}));
$('grant').addEventListener('click',()=>busy('grant',async()=>{if(!forward||!$('confirm-grant').checked){msg('Prepare os vínculos e marque a confirmação explícita de consentimento.','error');return}const r=await action('/api/m3/isolation/consent/grant',{link_id:forward,acknowledged:true});text('grant-status','GRANTED · evento auditável '+r.event_id.slice(0,8)+'…');$('confirm-grant').checked=false;msg('Concessão registrada. Execute agora as três verificações HTTP.','success')}));
$('consent-test').addEventListener('click',()=>busy('consent-test',async()=>{if(!forward||!reverse){msg('Prepare os dois vínculos antes de testar.','error');return}const r=await action('/api/m3/isolation/consent/run',{link_id:forward,reverse_link_id:reverse});showConsent(r);redactDisplay();msg('HTTP reais coletados. Confirme Netshoes 200, Pay 403 e reverso 403. Depois revogue.','success')}));
$('revoke').addEventListener('click',()=>busy('revoke',async()=>{if(!forward||!$('confirm-revoke').checked){msg('Prepare o vínculo e confirme a revogação.','error');return}const r=await action('/api/m3/isolation/consent/revoke',{link_id:forward,acknowledged:true});text('revoke-status','REVOKED · evento auditável '+r.event_id.slice(0,8)+'…');$('confirm-revoke').checked=false;msg('Revogação registrada. Teste novamente para comprovar bloqueio imediato.')}));
$('revocation-test').addEventListener('click',()=>busy('revocation-test',async()=>{if(!forward||!reverse){msg('Vínculos ainda não preparados.','error');return}const r=await action('/api/m3/isolation/consent/run',{link_id:forward,reverse_link_id:reverse});showConsent(r);redactDisplay();const x=r.phases?.REVOKED?.tests?.netshoes;msg('Pós-revogação: Netshoes HTTP '+(x?.http??'—')+' / '+(x?.reason||'—'),r.result==='PASS'?'success':'')}));
$('token-test').addEventListener('click',()=>busy('token-test',async()=>{msg('Executando controles positivos e tentativas reais no WSO2. Os JWTs permanecem apenas no backend.');const r=await action('/api/m3/isolation/token/run',{});showToken(r);redactDisplay();msg(r.result==='PASS'?'Isolamento de tokens comprovado. Exporte a evidência saneada.':'Prova OAuth incompleta: verifique os controles e o erro saneado.',r.result==='PASS'?'success':'error')}));
reload();
})();
