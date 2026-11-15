import http from 'node:http';
import {readFileSync,existsSync,writeFileSync,mkdirSync,renameSync} from 'node:fs';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {TelemetryClient} from './telemetry.mjs';
import {PrahariClient} from './prahari-client.mjs';
const key=process.env.PRAHARI_INTEGRATION_KEY;
if(!key)throw Error('Launch with run_demo.py to configure integration authentication.');
const dir=process.env.PRAHARI_DEMO_DATA||join(process.cwd(),'data','demo');mkdirSync(dir,{recursive:true});
const boardPath=join(dir,'board.json');
let board=existsSync(boardPath)?JSON.parse(readFileSync(boardPath,'utf8')):[];
const client=new PrahariClient({base:process.env.PRAHARI_URL||'http://127.0.0.1:8000',key,mode:process.env.PRAHARI_MODE||'enforce',outboxPath:join(dir,'outbox.json')});
const telemetry=new TelemetryClient({base:client.base,key,pseudonymKey:process.env.PRAHARI_PSEUDONYM_KEY||key,outboxPath:join(dir,'telemetry-outbox.json')});
let reached=0;const stats={allowed:0,blocked:0,held:0,unavailable:0};
function send(res,status,data){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data));}
const server=http.createServer(async(req,res)=>{
 try{
 const host=req.headers.host||'';
 if(!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(host))return send(res,400,{error:'Invalid host'});
 if(req.method==='POST'&&req.headers.origin&&new URL(req.headers.origin).host!==host)return send(res,403,{error:'Cross-origin write rejected'});
 if(req.method==='GET'&&req.url==='/'){res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store','X-Frame-Options':'DENY'});return res.end(readFileSync(new URL('./index.html',import.meta.url)));}
 if(req.method==='GET'&&req.url==='/stats')return send(res,200,{mode:client.mode,handler_reached:reached,...stats,unacknowledged:client.queue.length,telemetry_pending:telemetry.queue.length,telemetry_rejected:telemetry.rejected.length,telemetry_dropped:telemetry.dropped});
 if(req.method==='GET'&&req.url==='/posts')return send(res,200,{posts:board.slice(-30).reverse()});
 const identity=telemetry.identity(req,res);
 const started=performance.now();let linkedScan=null;
 // Only route templates are emitted. Never send request content, cookies or source IP.
 res.once('finish',()=>{
  const route=req.url==='/submit'?'/submit':req.url==='/login'?'/login':'/unknown';
  telemetry.record({event_id:randomUUID(),sensor_id:'protected-board',kind:'http',mode:'live',stream_id:'live',observed_at:new Date().toISOString(),...identity,route,method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(req.method)?req.method:'GET',status_code:res.statusCode,auth_failed:route==='/login'&&res.statusCode===401,scan_id:linkedScan,duration_ms:performance.now()-started});
 });
 if(req.method==='POST'&&req.url==='/login')return send(res,401,{error:'Demo endpoint intentionally rejects authentication; no credentials are accepted or stored'});
 if(req.method!=='POST'||req.url!=='/submit')return send(res,404,{error:'Not found'});
 if(!(req.headers['content-type']||'').startsWith('application/json'))return send(res,415,{error:'JSON required'});
 let chunks=[],size=0;
 for await(const chunk of req){size+=chunk.length;if(size>16000)return send(res,413,{error:'Input too large'});chunks.push(chunk);}
 let body;
 try{body=JSON.parse(Buffer.concat(chunks).toString());if(typeof body.content!=='string'||!body.content.trim()||body.content.length>10000||!['payload','url'].includes(body.input_type))throw Error();}catch{return send(res,400,{error:'Use content and input_type payload or url'});}
 let inspection;
 try{inspection=await client.inspect({input_type:body.input_type,content:body.content});}catch{stats.unavailable++;return send(res,503,{error:'scanner_unavailable',handler_reached:reached,action:'denied'});}
 const {scan,action}=inspection;linkedScan=scan.scan_id;
 // Application handler begins only after the policy gate permits the input.
 if(action==='allowed'){
  const post={id:randomUUID(),type:body.input_type,content:body.content,created_at:new Date().toISOString()};
  const next=[...board,post].slice(-100);writeFileSync(boardPath+'.tmp',JSON.stringify(next));renameSync(boardPath+'.tmp',boardPath);board=next;reached++;
 }
 stats[action]++;
 let recorded=false;try{recorded=await client.acknowledge(scan,action);}catch{}
 send(res,action==='allowed'?200:action==='blocked'?403:409,{decision:scan.decision,action,mode:client.mode,scan_id:scan.scan_id,handler_reached:reached,acknowledgement_recorded:recorded});
 }catch{if(!res.headersSent)send(res,500,{error:'Application operation failed'});else res.end();}
});
server.requestTimeout=15000;
server.listen(Number(process.env.DEMO_PORT||3000),process.env.DEMO_BIND||'127.0.0.1',()=>console.log('Protected board: http://127.0.0.1:'+(process.env.DEMO_PORT||3000)));
