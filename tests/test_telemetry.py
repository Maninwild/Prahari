import json,os,tempfile,time,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from prahari.api import create_app
from prahari.detectors.models import Models
from prahari.storage import Store
from prahari.telemetry.schemas import TelemetryEvent
from prahari.telemetry.service import Telemetry,TelemetryError
from scripts.import_zeek import convert

class TelemetryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'test.db'
  self.service=Telemetry(Store(self.path));self.base=time.time()-100
 def tearDown(self):self.tmp.cleanup()
 def event(self,i,**kw):
  data={'event_id':f'event-{i}','sensor_id':'web','mode':'replay','stream_id':'test','kind':'http','actor_id':'a'*64,'session_id':'b'*64,'route':'/products','bytes_out':1000,'observed_at':datetime.fromtimestamp(self.base+i,timezone.utc).isoformat()}
  data.update(kw);return TelemetryEvent(**data)
 def ingest(self,i,**kw):return self.service.ingest(self.event(i,**kw))
 def test_session_and_failed_logins(self):
  for i in range(5):r=self.ingest(i)
  self.assertFalse([s for s in r['signals'] if s['kind']=='rule'])
  for i in range(5,10):r=self.ingest(i,auth_failed=True,status_code=401,route='/login')
  self.assertIn('auth-failures',[s['id'] for s in r['signals']]);self.assertEqual(r['decision'],'Review')
  self.assertEqual(r['action_taken'],'none');self.assertEqual(r['session_features']['count'],10)
  self.assertEqual(self.service.summary()['sessions'],1)
 def test_idempotence_conflict_restart(self):
  first=self.ingest(0);self.assertTrue(self.ingest(0)['duplicate'])
  with self.assertRaises(TelemetryError) as c:self.ingest(0,bytes_out=2)
  self.assertEqual(c.exception.status,409)
  other=Telemetry(Store(self.path));self.assertEqual(other.summary()['events'],1)
  self.assertEqual(other.ingest(self.event(0))['event_id'],first['event_id'])
 def test_expiry_lateness_isolation(self):
  for i in range(4):self.ingest(i,auth_failed=True)
  self.assertEqual(self.ingest(5,auth_failed=True,actor_id='c'*64)['features']['auth_failures'],1)
  self.assertEqual(self.ingest(6,auth_failed=True,stream_id='other')['features']['auth_failures'],1)
  self.assertEqual(self.ingest(7,auth_failed=True,mode='live')['features']['auth_failures'],1)
  self.assertEqual(self.ingest(400,auth_failed=True)['features']['auth_failures'],1)
  self.assertEqual(self.ingest(395)['features']['count'],2)
  with self.assertRaises(TelemetryError):self.ingest(300)
 def test_correlation_and_reopen(self):
  for i in range(5):r=self.ingest(i,auth_failed=True)
  iid=r['incident_id'];self.service.review(iid,'resolved')
  for i in range(10,22):r=self.ingest(i,kind='flow',session_id=None,sensor_id='zeek',destination='198.51.100.1',destination_port=i,connection_failed=True)
  self.assertEqual(r['incident_id'],iid)
  incident=self.service.detail(iid);self.assertEqual(incident['status'],'open')
  self.assertEqual(set(incident['kinds']),{'http','flow'})
  self.assertIn('port-probing',[s['id'] for s in incident['signals']])
  self.assertEqual(self.service.incidents(mode='live')['total'],0)
 def test_bad_live_time(self):
  for ts in (time.time()+120,time.time()-86401):
   with self.assertRaises(TelemetryError):self.ingest(0,mode='live',observed_at=datetime.fromtimestamp(ts,timezone.utc))
 def test_zeek_mapping(self):
  row={'ts':100,'uid':'abc','id.orig_h':'192.0.2.10','id.resp_h':'198.51.100.1','id.resp_p':80,'duration':2,'proto':'tcp','conn_state':'S0','orig_bytes':123}
  e=convert(row,'secret');TelemetryEvent(**e)
  self.assertNotIn('192.0.2.10',json.dumps(e));self.assertTrue(e['connection_failed']);self.assertEqual(e['bytes_out'],123)
  self.assertNotEqual(e['actor_id'],convert(row,'different')['actor_id'])
  self.assertEqual(datetime.fromisoformat(e['observed_at']).timestamp(),102)
 def test_auth_validation_scan_link_and_reviews(self):
  with patch.dict(os.environ,{'PRAHARI_INTEGRATION_KEY':'integration','PRAHARI_API_KEY':'workspace'}),TestClient(create_app(Models(),self.path)) as c:
   e=self.event(0).model_dump(mode='json')
   self.assertEqual(c.post('/api/v1/telemetry',json=e).status_code,401)
   c.headers['Authorization']='Bearer workspace';self.assertEqual(c.post('/api/v1/telemetry',json=e).status_code,401)
   c.headers['X-Prahari-Key']='integration'
   for bad in ({**e,'raw_cookie':'SECRET'},{**e,'route':'/x?password=SECRET'}):self.assertEqual(c.post('/api/v1/telemetry',json=bad).status_code,422)
   self.assertEqual(c.post('/api/v1/telemetry',json={**e,'scan_id':'f'*32}).status_code,404)
   for i in range(3):
    scan=c.post('/api/v1/scans',json={'input_type':'payload','content':'<script>alert(1)</script>'}).json()
    e=self.event(i,scan_id=scan['scan_id']).model_dump(mode='json');r=c.post('/api/v1/telemetry',json=e)
    self.assertEqual(r.status_code,200,r.text)
   r=r.json();self.assertIn('repeated-attacks',[s['id'] for s in r['signals']]);iid=r['incident_id']
   self.assertEqual(c.patch('/api/v1/incidents/'+iid,json={'status':'investigating'}).json()['status'],'investigating')
   self.assertEqual(c.get('/api/v1/incidents?mode=replay').json()['total'],1)
   self.assertEqual(c.post('/api/v1/telemetry',json={**e,'event_id':'new-id'}).status_code,409)
   self.assertEqual(c.get('/api/v1/telemetry/summary').json()['events'],3)
 def test_rules_and_model_failure(self):
  from prahari.telemetry.detection import rules
  self.assertEqual(len(rules({'count':60,'auth_failures':5,'attack_scans':3,'unique_routes':20,'error_ratio':.6},'http')),4)
  self.assertEqual(len(rules({'count':20,'unique_ports':15,'unique_destinations':20,'failure_ratio':.7,'bytes_out':60000000,'out_in_ratio':20},'flow')),3)
  self.service.model.bundle=None;self.service.model.error='missing'
  for i in range(5):r=self.ingest(i,auth_failed=True)
  self.assertFalse(r['model']['loaded']);self.assertIsNotNone(r['incident_id'])
 def test_anomaly_signal(self):
  model=self.service.model;self.assertIsNotNone(model.bundle)
  signal=model.analyse({'count':1000,'unique_destinations':800,'unique_ports':500,'failure_ratio':1,'bytes_out':10**10,'out_in_ratio':10**7},'flow')
  self.assertIsNotNone(signal);self.assertEqual(signal['kind'],'model');self.assertIn('synthetic',signal['scope'])

if __name__=='__main__':unittest.main()
