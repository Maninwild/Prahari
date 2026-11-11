import {randomUUID} from 'node:crypto';
import {mkdirSync,existsSync,readFileSync,writeFileSync,renameSync} from 'node:fs';
import {dirname} from 'node:path';
export class PrahariClient {
 constructor({base,key,mode='enforce',outboxPath,timeout=5000}){
  if(!['monitor','enforce'].includes(mode))throw Error('Invalid integration mode');
  Object.assign(this,{base,key,mode,outboxPath,timeout});
  mkdirSync(dirname(outboxPath),{recursive:true});
  this.queue=existsSync(outboxPath)?JSON.parse(readFileSync(outboxPath,'utf8')):[];
  this.flushing=false;
  this.timer=setInterval(()=>this.flush(),3000);this.timer.unref();
 }
 persist(){const tmp=this.outboxPath+'.tmp';writeFileSync(tmp,JSON.stringify(this.queue));renameSync(tmp,this.outboxPath);}
 async api(path,body){const r=await fetch(this.base+path,{method:'POST',headers:{'Content-Type':'application/json','X-Prahari-Key':this.key},body:JSON.stringify(body),signal:AbortSignal.timeout(this.timeout)});if(!r.ok)throw Error('Prahari unavailable: '+r.status);return r.json();}
 async inspect(input){
  const scan=await this.api('/api/v1/scans',input);
  if(!['Allow','Review','Block'].includes(scan.decision)||!/^[a-f0-9]{32}$/.test(scan.scan_id))throw Error('Invalid scan response');
  const action=this.mode==='monitor'?'allowed':{Allow:'allowed',Review:'held',Block:'blocked'}[scan.decision];
  return {scan,action};
 }
 async acknowledge(scan,action){
  const event={event_id:randomUUID(),scan_id:scan.scan_id,mode:this.mode,action};
  this.queue.push(event);this.persist();await this.flush();return !this.queue.some(e=>e.event_id===event.event_id);
 }
 async flush(){
  if(this.flushing)return;this.flushing=true;
  try{while(this.queue.length){await this.api('/api/v1/enforcement-events',this.queue[0]);this.queue.shift();this.persist();}}
  catch{}finally{this.flushing=false;}
 }
 close(){clearInterval(this.timer);}
}
