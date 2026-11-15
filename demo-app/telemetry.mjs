import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {mkdirSync,existsSync,readFileSync,writeFileSync,renameSync} from 'node:fs';
import {dirname} from 'node:path';
export class TelemetryClient {
 constructor({base,key,pseudonymKey,outboxPath}) {
  Object.assign(this,{base,key,pseudonymKey,outboxPath});
  if(!pseudonymKey)throw Error('PRAHARI_PSEUDONYM_KEY is required for stable session identities');
  mkdirSync(dirname(outboxPath),{recursive:true});
  this.queue=existsSync(outboxPath)?JSON.parse(readFileSync(outboxPath,'utf8')):[];
  this.deadPath=outboxPath+'.rejected.json';
  this.rejected=existsSync(this.deadPath)?JSON.parse(readFileSync(this.deadPath,'utf8')):[];
  this.dropped=0;this.flushing=false;this.timer=setInterval(()=>this.flush(),3000);this.timer.unref();
 }
 hash(value){return createHmac('sha256',this.pseudonymKey).update(value).digest('hex');}
 identity(req,res){
  const cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('prahari_session='))?.split('=')[1]||'';
  let [token,signature]=cookie.split('.');
  const valid=/^[a-f0-9]{32}$/.test(token||'')&&/^[a-f0-9]{64}$/.test(signature||'')&&timingSafeEqual(Buffer.from(signature),Buffer.from(this.hash('cookie:'+token)));
  if(!valid){token=randomBytes(16).toString('hex');signature=this.hash('cookie:'+token);}
  res.setHeader('Set-Cookie',`prahari_session=${token}.${signature}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`);
  const address=(req.socket.remoteAddress||'unknown').replace(/^::ffff:/,'');
  return {actor_id:this.hash('actor:'+address),session_id:this.hash('session:'+token)};
 }
 persist(){writeFileSync(this.outboxPath+'.tmp',JSON.stringify(this.queue));renameSync(this.outboxPath+'.tmp',this.outboxPath);}
 record(event){
  if(this.queue.length>=5000){this.dropped++;return false;}
  this.queue.push(event);this.persist();void this.flush();return true;
 }
 async flush(){
  if(this.flushing)return;this.flushing=true;
  try{while(this.queue.length){
   const response=await fetch(this.base+'/api/v1/telemetry',{method:'POST',headers:{'Content-Type':'application/json','X-Prahari-Key':this.key},body:JSON.stringify(this.queue[0]),signal:AbortSignal.timeout(5000)});
   if(response.ok){this.queue.shift();this.persist();}
   else if([404,409,422].includes(response.status)){
    this.rejected.push({event_id:this.queue[0].event_id,status:response.status});this.rejected=this.rejected.slice(-100);
    writeFileSync(this.deadPath,JSON.stringify(this.rejected));this.queue.shift();this.persist();
   }else break;
  }}catch{}finally{this.flushing=false;}
 }
 close(){clearInterval(this.timer);}
}
