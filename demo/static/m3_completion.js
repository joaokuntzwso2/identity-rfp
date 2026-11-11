(()=>{'use strict';
const output=id=>document.getElementById(id);
async function api(path,body,slot){
  const key=output('operator').value;
  if(!key){output(slot).textContent='BLOCKED: informe a chave local do operador';return}
  output(slot).textContent='Consultando serviços reais…';
  try{
    const res=await fetch(path,{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-CIAM-LAB-Key':key},
      body:JSON.stringify(body||{})});
    const text=await res.text();let data;
    try{data=JSON.parse(text)}catch(_){data={result:'BLOCKED',http:res.status,response:'Invalid API JSON'}}
    output(slot).textContent=JSON.stringify({http:res.status,...data},null,2);
    return data;
  }catch(_){output(slot).textContent='BLOCKED: falha na conexão local; revise logs do serviço'}
}
const act={
  b2c:()=>api('/api/m3/completion/b2c',{},'b2c'),
  b2b:async()=>{const v=await api('/api/m3/completion/b2b',{},'b2b');if(v)output('ldap').textContent=JSON.stringify({user_store:v.user_store,result:v.result},null,2)},
  'seller-read':()=>api('/api/m3/completion/b2b/action',{action:'view-dashboard'},'b2b'),
  'seller-write':()=>api('/api/m3/completion/b2b/action',{action:'change-payout-account'},'b2b'),
  links:async()=>{const d=await api('/api/m3/completion/consent-links',{},'consent');
    if(d?.links){const s=output('links');s.replaceChildren();
      const def=document.createElement('option');def.value='';def.textContent='Selecione o vínculo atual';s.append(def);
      for(const x of d.links){const o=document.createElement('option');o.value=x.link_id;o.textContent=x.link_id+' · '+x.state;s.append(o)}}},
  consent:()=>{const id=output('links').value;if(!id){output('consent').textContent='BLOCKED: escolha um link pertencente às sessões atuais';return}return api('/api/m3/completion/consent-check',{link_id:id},'consent')},
  exchange:()=>api('/api/m3/exchange/run',{},'exchange'),
  cc:()=>api('/api/m3/completion/m2m/cc',{root:output('root').value},'m2m'),
  jwt:()=>api('/api/m3/completion/m2m/jwt-replay',{root:output('root').value},'m2m'),
  tenant:()=>api('/api/m3/completion/m2m/tenant-boundary',{},'m2m')
};
for(const b of document.querySelectorAll('button[data-action]')) b.addEventListener('click',()=>act[b.dataset.action]());
})();
