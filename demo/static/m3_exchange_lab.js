(() => {
  'use strict';
  const q = sel => document.querySelector(sel);
  const setText = (sel, value) => { const el=q(sel); if(el) el.textContent=String(value ?? '—'); };
  const notice=q('#lab-notice');
  const button=q('#run-tests');
  function showNotice(text, variant='') {
    notice.textContent=text; notice.className='notice '+variant;
  }
  const yesno = value => value === true ? 'SIM' : value === false ? 'NÃO' : '—';
  function compactScopes(v) { return Array.isArray(v)&&v.length ? v.join(' · ') : '—'; }
  function displayCapture(which, data) {
    const valid = !!(data && data.present && data.secure && data.looks_jwt && data.remaining_seconds_unverified > 30);
    const el=q('#'+which+'-signal'); el.className='signal '+(valid?'ready':data?.present?'error':'');
    setText('#'+which+'-state', valid ? 'JWT capturado · aguardando verificação criptográfica' :
      data?.present ? 'Token expirado, inválido ou arquivo inseguro · recapture' : 'JWT ainda não capturado');
  }
  const outcomeText = {PASS:'APROVADO',FAIL:'FALHOU',BLOCKED:'BLOQUEADO',INCOMPLETE:'PENDENTE'};
  function fillCard(key, data) {
    const card=q(`[data-test="${key}"]`);
    if(!card) return;
    const label=card.querySelector('[data-status]');
    const result=data?.result || 'INCOMPLETE';
    label.textContent=outcomeText[result] || result; label.dataset.result=result;
    card.querySelector('[data-http]').textContent=data?.http ?? '—';
    if(key==='escalation_rejected') {
      card.querySelector('[data-signature]').textContent=yesno(data?.forbidden_scope_issued);
      card.querySelector('[data-scope]').textContent=result==='PASS'?'HTTP 403 VALIDADO':result==='FAIL'?'INSEGURO':'INCONCLUSIVO';
    } else {
      card.querySelector('[data-signature]').textContent=yesno(key==='delegated_read'?data?.actor_preserved:data?.signature_verified);
      card.querySelector('[data-scope]').textContent=yesno(data?.scope_reduced);
    }
    const error=data?.oauth_error;
    const detail=error ? `${error.code}: ${error.summary}` :
       data?.token_issued ? `Token emitido: ${compactScopes(data.scope_issued)}. JWT assinado: ${yesno(data.signature_verified)}. Subject preservado: ${yesno(data.subject_preserved)}. Actor preservado: ${yesno(data.actor_preserved)}. API negou aprovação por escopo: ${yesno(data.resource_api_approval_denied)}.` :
       'Ainda não há evidência de token emitido neste cenário.';
    card.querySelector('[data-detail]').textContent=detail;
  }
  function facts(report) {
    const e=report?.input_evidence || {};
    const audience=report?.audience || {};
    const rows=[
      ['Issuer',e.issuer],['Assinatura de Ana / subject',yesno(e.subject_signature_verified)],
      ['Assinatura de Bruno / actor',yesno(e.actor_signature_verified)],
      ['Identidades distintas',yesno(e.subject_actor_distinct)],
      ['Subject (prefixo seguro)',e.subject_id_prefix ? e.subject_id_prefix+'…' : null],
      ['Actor (prefixo seguro)',e.actor_id_prefix ? e.actor_id_prefix+'…' : null],
      ['Escopos de Ana',compactScopes(e.subject_scopes)],
      ['Escopos de Bruno',compactScopes(e.actor_scopes)],
      ['Audience solicitado',audience.requested || 'não configurado'],
      ['Audience verificado no token',yesno(audience.bound)],
      ['Audience cadastrado no client',audience.registered_in_client || 'NÃO VERIFICADO'],
      ['Executado em',report?.timestamp ? new Date(report.timestamp).toLocaleString('pt-BR') : '—'],
    ];
    const target=q('#verified-facts'); target.replaceChildren();
    rows.forEach(([name,value]) => {const row=document.createElement('div');row.className='fact-row';
      const label=document.createElement('span');label.textContent=name;
      const v=document.createElement('b');v.textContent=String(value ?? '—');
      row.append(label,v);target.append(row);});
  }
  function resourceProof(report) {
    const resource=report?.resource_api || {};
    const gates=[['read',resource.read],['approve',resource.approval_check]];
    gates.forEach(([key,data]) => {
      setText('#resource-'+key+'-http',data?.http ?? '—');
      setText('#resource-'+key+'-decision',data?.decision || 'PENDENTE');
      setText('#resource-'+key+'-valid',data ? yesno(data.token_verified===true && data.audience_verified===true) : '—');
      setText('#resource-'+key+'-reason',data?.reason || 'Sem teste executado.');
    });
    const mode=report?.audience?.resource_mode;
    setText('#resource-mode',mode==='DEDICATED_RESOURCE'?'AUDIENCE DE API DEDICADO':
      mode==='EXCHANGE_CLIENT_FALLBACK'?'CLIENT ID · LAB LOCAL':'AUDIENCE PENDENTE');
    setText('#audience-note',mode==='DEDICATED_RESOURCE' && report?.audience?.bound===true ?
      'WSO2 emitiu token para o audience solicitado e a API confirmou esse audience. Verifique também o cadastro da aplicação nas configurações WSO2.':
      'Validação do audience dedicado à API ainda PENDENTE. Um Client ID do laboratório não substitui o audience específico do recurso.');
  }
  function display(report) {
    if (!report) {setText('#hero-verdict','Ainda não validado');setText('#hero-score','0 / 3');return;}
    if (!report.resource_api || !report.resource_api.read || !report.resource_api.approval_check) {
      setText('#resource-read-reason','Relatório anterior ao teste HTTP: execute novamente os 3 atos.');
      setText('#resource-approve-reason','Relatório anterior ao teste HTTP: execute novamente os 3 atos.');
    }
    const statuses=['subject_only_read','delegated_read','escalation_rejected'];
    statuses.forEach(key=>fillCard(key,report.tests?.[key]));
    const passed=statuses.filter(key=>report.tests?.[key]?.result==='PASS').length;
    setText('#hero-score',passed+' / 3');
    const messages={PASS:'Segurança comprovada no recurso',BLOCKED:'Evidência de API bloqueada',FAIL:'Falha de segurança / validação',PARTIAL_AUDIENCE_NOT_BOUND:'3 atos aprovados · audience pendente',INCOMPLETE:'Evidência incompleta'};
    setText('#hero-verdict', messages[report.result] || report.result);
    setText('#hero-subtitle',report.result==='PASS' ? 'Delegação, restrição e audience comprovados.' : 'Não tratar uma rejeição isolada como aprovação do RFP.');
    setText('#diagnosis',report.next_action || report.narrative || 'Revise o fluxo e execute novamente.');
    facts(report);
    resourceProof(report);
  }
  async function refresh(){
    try{ const response=await fetch('/api/m3/exchange/status',{cache:'no-store',credentials:'same-origin'});
      if(!response.ok)throw new Error('HTTP '+response.status);
      const body=await response.json();
      if(body.resource_audience?.mode==='DEDICATED_RESOURCE' && body.resource_audience?.readback_verified===true) {
        q('#audience').value=body.resource_audience.value;
        q('#audience').readOnly=true;
        setText('#audience-registration','Cadastrado no WSO2 · Management API readback confirmado');
      } else {
        q('#audience').readOnly=false;
        setText('#audience-registration', body.resource_audience?.mode==='NOT_CONFIGURED' ?
          'Configuração de audience inconsistente — executar registro novamente.' :
          'Ainda não cadastrado; aceitação final bloqueada.');
      }
      displayCapture('ana',body.capture?.subject);
      displayCapture('bruno',body.capture?.actor);display(body.report);
      if(body.resource_audience_mode)setText('#resource-mode',body.resource_audience_mode==='DEDICATED_RESOURCE'?'AUDIENCE DE API DEDICADO':'CLIENT ID · LAB LOCAL');
      if(body.report)showNotice(body.report_has_resource_http_evidence ? 'Última evidência carregada. Verifique a data antes da apresentação.' : 'Relatório antigo sem chamadas HTTP à API. Execute novamente para concluir a prova.');
      else showNotice('Nenhum relatório salvo. Capture Ana e Bruno e execute os três cenários.');
      button.disabled=!body.capture?.can_attempt;
    }catch(e){showNotice('Não foi possível ler o estado do laboratório: '+e.message,'error');}
  }
  q('#refresh-status').addEventListener('click',refresh);
  button.addEventListener('click',async()=>{
    const key=q('#operator-key').value;
    if(!key){showNotice('Informe a chave local DEMO_OPERATOR_KEY para autorizar o diagnóstico.','error');q('#operator-key').focus();return;}
    const audience=q('#audience').value.trim();
    button.disabled=true;button.textContent='Executando chamadas reais…';
    showNotice('Validando JWTs e executando as 3 trocas diretamente no WSO2…');
    try{
      const response=await fetch('/api/m3/exchange/run',{method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-CIAM-Lab-Key':key},
        body:JSON.stringify({audience:audience||null})});
      const body=await response.json();
      if(!response.ok){showNotice((body.detail||body.error||'Requisição não concluída')+' ['+response.status+']','error');return;}
      display(body);showNotice(body.result==='PASS'?'Todos os gates principais passaram. Exporte a evidência.':
        'Diagnóstico concluído. Veja as falhas e o próximo passo antes de repetir o teste.',body.result==='PASS'?'success':'');
    }catch(e){showNotice('Não foi possível contatar o laboratório: '+e.message,'error');}
    finally {button.textContent='▶ Executar 3 testes reais';button.disabled=false;}
  });
  refresh();
})();
