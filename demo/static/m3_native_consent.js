/* Native WSO2 consent storytelling lab. No credentials or tokens persisted. */
(() => {
'use strict';
const el = id => document.getElementById(id);
const state = { link: '' };
const output = (id, value) => { el(id).textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); };
const key = () => el('key').value.trim();
const link = () => el('link').value;
const errorMessage = value => typeof value?.detail === 'string' ? value.detail : (value?.reason || value?.result || 'WSO2 indisponível ou resposta inválida');
async function call(path, payload = null, authenticated = true, expectedStatus = [200]) {
  const headers = { 'Accept':'application/json' };
  if(payload !== null) headers['Content-Type']='application/json';
  if(authenticated) {
    if(!key()) throw new Error('Informe DEMO_OPERATOR_KEY para executar a prova.');
    headers['X-CIAM-Lab-Key']=key();
  }
  const r = await fetch(path, {
    method:payload === null ? 'GET' : 'POST',
    headers, body: payload === null ? undefined : JSON.stringify(payload),
    credentials:'same-origin',cache:'no-store',redirect:'error'
  });
  let value; try { value=await r.json(); } catch (_) { throw new Error('Resposta HTTP '+r.status+' não é JSON'); }
  if(!r.ok && !expectedStatus.includes(r.status)) throw new Error('HTTP '+r.status+' · '+errorMessage(value));
  return value;
}
async function perform(buttonId, outId, action) {
  const button = el(buttonId); button.disabled=true; button.setAttribute('aria-busy','true');
  output(outId,'Consultando o WSO2 e o consent ledger…');
  try { const result=await action(); output(outId,result); return result; }
  catch (e) { output(outId,'BLOQUEADO · '+String(e.message).slice(0,240)); return null; }
  finally {button.disabled=false;button.removeAttribute('aria-busy');}
}
function requireLink(){if(!link()) throw new Error('Selecione um vínculo Magalu → Netshoes autenticado.');return link();}
async function refresh(){
  const v=await call('/api/m3/native/status', null, false);
  Object.entries(v.sessions || {}).forEach(([name, ready]) => {
    const tag=el('s-'+name); if(tag) {tag.textContent=ready?'✓ AUTH':'LOGIN';tag.style.color=ready?'#20855d':'#b77a0b';}
  });
  const select=el('link'); const current=select.value;
  select.replaceChildren();
  const empty=new Option('Selecione um vínculo Magalu → Netshoes', ''); select.add(empty);
  (v.links||[]).forEach(item => select.add(new Option(item.link_id.slice(0,8)+' · '+item.state, item.link_id)));
  if([...select.options].some(o=>o.value===current)) select.value=current;
  el('business-health').textContent=(v.links||[]).some(x=>x.state==='GRANTED')?'GRANTED':'PENDENTE';
  el('native-health').textContent=v.native_configured?'CONFIGURADO':'PREPARAÇÃO PENDENTE';
  el('verdict').textContent='VERIFICAÇÃO AO VIVO';
  el('verdict-note').textContent='A preparação não constitui aceite. Execute todos os atos para produzir evidência.';
}
el('refresh').addEventListener('click',async()=>{try{await refresh()}catch(e){output('preflight-out',e.message)}});
el('preflight').addEventListener('click',()=>perform('preflight','preflight-out',async()=>{
  const v=await call('/api/m3/native/preflight',{});
  el('native-health').textContent=v.result;
  return v;
}));
el('native-create').addEventListener('click',()=>perform('native-create','native-create-out',async()=>{
  const v=await call('/api/m3/native/mirror-grant',{
    link_id:requireLink(),confirmed:el('confirm-grant').checked,
    subject_attestation:el('confirm-subject').checked
  });
  el('native-health').textContent=v.native_active?'ACTIVE':'NÃO VERIFICADO';
  return v;
}));
async function protectedRead(target='read-out'){
  const v=await call('/api/m3/native/protected-read',{link_id:requireLink()},true,[200,403,503]);
  el('door-native').textContent=v.native_verified?'VERIFICADO':'—';
  el('door-custom').textContent=v.custom_verified?'VERIFICADO':'—';
  el('door-http').textContent=v.http||'—';
  output(target,v);return v;
}
el('read').addEventListener('click',()=>perform('read','read-out',()=>protectedRead()));
el('after').addEventListener('click',()=>perform('after','revoke-out',()=>protectedRead('revoke-out')));
el('revoke').addEventListener('click',()=>perform('revoke','revoke-out',()=>call('/api/m3/native/native-revoke',{
  link_id:requireLink(),confirmed:el('confirm-revoke').checked})));
el('reconcile').addEventListener('click',()=>perform('reconcile','revoke-out',()=>call('/api/m3/native/reconcile',{
  link_id:requireLink()})));
el('accept').addEventListener('click',()=>perform('accept','evidence-out',async()=>{
  const v=await call('/api/m3/native/acceptance',{link_id:requireLink()});
  el('verdict').textContent=v.result;
  el('verdict-note').textContent=v.result==='PASS'?'Live WSO2 native revocation and dual gate verified.':'Ainda existem critérios sem evidência. Veja os campos do relatório.';
  return v;
}));
el('export').addEventListener('click',async()=>{
  try {
    const v=await call('/api/m3/native/evidence',{});
    const blob=new Blob([JSON.stringify(v,null,2)+'\n'],{type:'application/json'});
    const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='magalu-m3-native-consent-sanitized.json';
    document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  } catch(e){output('evidence-out',e.message);}
});
refresh().catch(e=>output('preflight-out','Sessões ainda não disponíveis: '+e.message));
})();
