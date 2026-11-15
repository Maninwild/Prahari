import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from prahari.api import create_app
from prahari.detectors.models import Models
from prahari.detectors.phishing_features import extract_features,domain_group

class ReleaseTests(unittest.TestCase):
 def test_feature_repairs(self):
  self.assertEqual(extract_features('https://microsoft.com')['shortener'],0)
  self.assertEqual(extract_features('https://example.com/?x=bit.ly')['shortener'],0)
  self.assertEqual(extract_features('https://bit.ly/x')['shortener'],1)
  self.assertEqual(extract_features('https://[::1]/')['ip_host'],1)
  self.assertEqual(domain_group('https://a.b.example.co.uk'),'example.co.uk')
  self.assertEqual(extract_features('https://www.github.com'),extract_features('https://github.com'))
 def test_auth_origin_policy_and_review(self):
  with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'PRAHARI_API_KEY':'test-key','PRAHARI_INTEGRATION_KEY':'event-key'}):
   path=Path(d)/'db.sqlite'
   with TestClient(create_app(Models(),path)) as c:
    self.assertEqual(c.get('/api/v1/scans').status_code,401)
    self.assertEqual(c.get('/api/v1/scans',headers={'Authorization':'Bearer wrong'}).status_code,401)
    c.headers['Authorization']='Bearer test-key'
    self.assertEqual(c.post('/api/v1/scans',json={'input_type':'payload','content':'hello'},headers={'Origin':'https://evil.example'}).status_code,403)
    self.assertEqual(c.get('/',headers={'Host':'evil.example'}).status_code,400)
    self.assertEqual(c.put('/api/v1/policy',json={'mode':'protect'}).status_code,200)
    r=c.post('/api/v1/scans',json={'input_type':'payload','content':'<script>alert(1)</script>'}).json()
    self.assertEqual(r['decision'],'Block')
    sid=r['scan_id']
    self.assertEqual(c.post(f'/api/v1/scans/{sid}/review',json={'verdict':'malicious'}).status_code,200)
    self.assertEqual(c.get(f'/api/v1/scans/{sid}').json()['review']['verdict'],'malicious')
    self.assertEqual(c.get('/api/v1/scans?q='+sid[:8]).json()['total'],1)
    e={'event_id':'retry-test','scan_id':sid,'mode':'enforce','action':'blocked'}
    self.assertEqual(c.post('/api/v1/enforcement-events',json=e).status_code,401)
    for _ in range(2):self.assertEqual(c.post('/api/v1/enforcement-events',json=e,headers={'X-Prahari-Key':'event-key'}).status_code,200)
    self.assertEqual(c.get('/api/v1/dashboard/summary').json()['enforced_blocks'],1)
    e['event_id']='conflict'
    self.assertEqual(c.post('/api/v1/enforcement-events',json=e,headers={'X-Prahari-Key':'event-key'}).status_code,409)
   with TestClient(create_app(Models(),path)) as c:
    c.headers['Authorization']='Bearer test-key'
    self.assertEqual(c.get('/api/v1/policy').json()['mode'],'protect')
    self.assertEqual(c.get(f'/api/v1/scans/{sid}').json()['enforcement_events'][0]['action'],'blocked')
