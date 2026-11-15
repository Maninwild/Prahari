import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {TelemetryClient} from './telemetry.mjs';
test('telemetry retries survive restart and permanent errors are visible',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'prahari-'));let status=503;
 const server=http.createServer((req,res)=>{req.resume();res.writeHead(status);res.end('{}');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const config={base:`http://127.0.0.1:${server.address().port}`,key:'test',pseudonymKey:'test-identity',outboxPath:join(dir,'outbox.json')};
 let client=new TelemetryClient(config);
 try{
  client.record({event_id:'one'});
  while(client.flushing)await new Promise(r=>setTimeout(r,10));
  assert.equal(client.queue.length,1);client.close();client=new TelemetryClient(config);
  status=200;await client.flush();assert.equal(client.queue.length,0);
  status=422;client.record({event_id:'bad'});
  while(client.flushing)await new Promise(r=>setTimeout(r,10));
  assert.equal(client.queue.length,0);assert.equal(client.rejected[0].event_id,'bad');
  let cookie;const response={setHeader:(_,value)=>cookie=value};
  const request={headers:{},socket:{remoteAddress:'::ffff:127.0.0.1'}};
  const first=client.identity(request,response);request.headers.cookie=cookie.split(';')[0];
  const second=client.identity(request,response);assert.equal(first.session_id,second.session_id);
  request.headers.cookie='prahari_session='+ '0'.repeat(32)+'.'+'0'.repeat(64);
  assert.notEqual(client.identity(request,response).session_id,first.session_id);
  assert.equal(first.actor_id,client.hash('actor:127.0.0.1'));
 }finally{client.close();await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true});}
});
