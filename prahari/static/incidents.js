/* Uses the workspace API helper and safe textContent rendering. */
let incidentOffset=0,incidentSequence=0,selectedIncident=null;
async function loadIncidents(){
 const seq=++incidentSequence;
 try{
  const status=$('incident-filter').value,mode=$('incident-mode').value;
  const [summary,list]=await Promise.all([api('/api/v1/telemetry/summary'),api(`/api/v1/incidents?limit=10&offset=${incidentOffset}${status?'&status='+status:''}${mode?'&mode='+mode:''}`)]);
  if(seq!==incidentSequence)return;
  $('telemetry-events').textContent=summary.events;$('telemetry-sessions').textContent=summary.sessions;
  $('telemetry-open').textContent=(summary.incidents.open||0)+(summary.incidents.investigating||0);
  $('telemetry-model').textContent=summary.model.loaded?'Experimental baseline loaded':'Behaviour model unavailable';
  $('telemetry-mode').textContent=`Live events: ${summary.modes.live||0} · Replay events: ${summary.modes.replay||0} · Last received: ${summary.last_received_at?new Date(summary.last_received_at).toLocaleString():'no telemetry yet'}`;
  const body=$('incidents');body.replaceChildren();
  for(const row of list.items){
   const tr=element('tr'),td=element('td'),button=element('button',row.incident_id.slice(0,8)+' ↗');
   button.onclick=()=>showIncident(row.incident_id);td.append(button);
   tr.append(td,element('td',row.mode),element('td',row.actor_id.slice(0,10)),element('td',row.signals.map(s=>s.title).join(' · ')),element('td',Math.round(row.risk_score)+' / 100'),element('td',row.status));body.append(tr);
  }
  if(!list.items.length){const tr=element('tr'),td=element('td','No incidents for this filter. Connect the protected application or replay a Zeek log.');td.colSpan=6;tr.append(td);body.append(tr);}
  $('incident-prev').disabled=incidentOffset===0;$('incident-next').disabled=incidentOffset+10>=list.total;
  $('incident-page').textContent=`${list.total} incidents`;$('incident-error').textContent='';
 }catch(e){$('incident-error').textContent=e.message;}
}
async function showIncident(id){
 try{
  const r=await api('/api/v1/incidents/'+id);selectedIncident=r;
  const root=$('incident-detail');root.hidden=false;root.replaceChildren();
  root.append(element('h2','Incident '+id.slice(0,8)),element('p',`${r.mode.toUpperCase()} · ${r.status} · Review recommended · No automatic action`));
  root.append(element('p',`Actor ${r.actor_id.slice(0,16)} · ${r.session_ids.length} session(s) · Sensors: ${r.sensors.join(', ')}`));
  const actions=element('div',undefined,'review-actions');
  for(const [label,status] of [['Investigate','investigating'],['Resolve','resolved'],['False positive','false_positive']]){
   const b=element('button',label);b.onclick=async()=>{try{await api('/api/v1/incidents/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});await showIncident(id);await loadIncidents();}catch(e){$('incident-error').textContent=e.message;}};actions.append(b);
  }
  const exportButton=element('button','Export incident JSON');exportButton.onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(r,null,2)],{type:'application/json'}));const a=element('a');a.href=url;a.download='Prahari-incident-'+id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};actions.append(exportButton);root.append(actions);
  for(const e of r.timeline.slice().reverse()){
   const entry=element('details');entry.open=e===r.timeline.at(-1);
   entry.append(element('summary',new Date(e.observed_at).toLocaleString()+' · '+e.kind+' · '+e.sensor_id));
   for(const signal of e.signals){
    entry.append(element('p',signal.title));
    entry.append(element('pre',JSON.stringify(signal.kind==='model'?{scope:signal.scope,deviations:signal.deviations,explanation:signal.explanation}:{feature:signal.feature,observed:signal.observed,threshold:signal.threshold},null,2)));
   }
   if(e.scan_id){const b=element('button','Open linked scan');b.onclick=async()=>{try{render(await api('/api/v1/scans/'+e.scan_id));$('result').scrollIntoView({behavior:'smooth'});}catch(error){$('incident-error').textContent=error.message;}};entry.append(b);}
   root.append(entry);
  }
 }catch(e){$('incident-error').textContent=e.message;}
}
$('incident-filter').onchange=$('incident-mode').onchange=()=>{incidentOffset=0;loadIncidents();};
$('incident-prev').onclick=()=>{incidentOffset=Math.max(0,incidentOffset-10);loadIncidents();};
$('incident-next').onclick=()=>{incidentOffset+=10;loadIncidents();};
$('incident-refresh').onclick=loadIncidents;
$('connect').addEventListener('click',loadIncidents);
loadIncidents();setInterval(()=>{if(!document.hidden)loadIncidents();},5000);
