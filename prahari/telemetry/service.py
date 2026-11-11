"""Atomic, persistent telemetry aggregation. No payloads, cookies or source IPs stored."""
import hashlib,json,time,uuid
from datetime import datetime,timezone
from .anomaly import AnomalyModel
from .detection import features,rules

class TelemetryError(Exception):
    def __init__(self,status,message):self.status,self.message=status,message

class Telemetry:
    def __init__(self,store):
        self.store=store;self.model=AnomalyModel()
        with store.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS telemetry_events (
              id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, actor TEXT NOT NULL,
              scope TEXT NOT NULL, observed REAL NOT NULL, received REAL NOT NULL,
              session TEXT, scan_id TEXT, payload TEXT NOT NULL, result TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS telemetry_actor_time ON telemetry_events(scope,actor,observed);
            CREATE UNIQUE INDEX IF NOT EXISTS telemetry_scan ON telemetry_events(scan_id) WHERE scan_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS incidents (
              id TEXT PRIMARY KEY, actor TEXT NOT NULL, scope TEXT NOT NULL,
              opened REAL NOT NULL, updated REAL NOT NULL, status TEXT NOT NULL,
              risk REAL NOT NULL, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incident_actor_time ON incidents(scope,actor,updated);
            ''')

    def ingest(self,event):
        started=time.perf_counter();now=time.time();ts=event.observed_at.timestamp()
        raw=event.model_dump(mode='json')
        encoded=json.dumps(raw,sort_keys=True,separators=(',',':'))
        fingerprint=hashlib.sha256(encoded.encode()).hexdigest()
        scope=event.mode+':'+event.stream_id
        eid=hashlib.sha256((scope+':'+event.sensor_id+':'+event.event_id).encode()).hexdigest()
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT fingerprint,result FROM telemetry_events WHERE id=?',(eid,)).fetchone()
            if old:
                if old[0]!=fingerprint:raise TelemetryError(409,'Event ID already exists with different content')
                return {**json.loads(old[1]),'duplicate':True}
            if event.mode=='live' and (ts>now+30 or ts<now-86400):
                raise TelemetryError(422,'Live event time must be within the last 24 hours and at most 30 seconds ahead')
            last=db.execute('SELECT MAX(observed) FROM telemetry_events WHERE scope=? AND actor=?',(scope,event.actor_id)).fetchone()[0]
            if last is not None and ts<last-30:
                raise TelemetryError(422,'Event is more than 30 seconds behind the actor stream watermark')
            end=max(ts,last or ts)
            if event.scan_id:
                if db.execute('SELECT 1 FROM telemetry_events WHERE scan_id=?',(event.scan_id,)).fetchone():
                    raise TelemetryError(409,'Scan already linked to telemetry')
                scan=db.execute('SELECT result FROM scans WHERE id=?',(event.scan_id,)).fetchone()
                if not scan:raise TelemetryError(404,'Linked scan not found')
                scan=json.loads(scan[0]);raw['rule_attack']=any(f['evidence_kind']=='rule' for f in scan['findings'])
                raw['scan_risk']=scan['risk_score'] or 0
            else:raw['rule_attack']=False;raw['scan_risk']=0
            # Bounded retention for a local prototype. Incidents keep evidence snapshots.
            db.execute('DELETE FROM telemetry_events WHERE received<?',(now-7*86400,))
            db.execute("DELETE FROM incidents WHERE scope LIKE 'live:%' AND updated<?",(now-30*86400,)) if event.mode=='live' else None
            if db.execute('SELECT COUNT(*) FROM telemetry_events').fetchone()[0]>=100000:
                raise TelemetryError(429,'Local telemetry capacity reached; export and rotate the database')
            rows=db.execute('SELECT payload FROM telemetry_events WHERE scope=? AND actor=? AND observed>=? AND observed<=? ORDER BY observed',(scope,event.actor_id,end-300,end)).fetchall()
            if len(rows)>=1024:raise TelemetryError(429,'Actor window capacity reached')
            window=[json.loads(row[0]) for row in rows]+[raw]
            vector=features(window,event.kind)
            signals=rules(vector,event.kind)
            anomaly=self.model.analyse(vector,event.kind)
            if anomaly:signals.append(anomaly)
            risk=max([raw['scan_risk']]+[s['score'] for s in signals])
            incident_id=None
            if signals:
                previous=db.execute("SELECT id,data,status FROM incidents WHERE scope=? AND actor=? AND updated>=? ORDER BY updated DESC LIMIT 1",(scope,event.actor_id,end-300)).fetchone()
                if previous:
                    incident_id,data,status=previous;data=json.loads(data)
                    status=status if status in ('open','investigating') else 'open'
                else:
                    if db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]>=10000:raise TelemetryError(429,'Incident capacity reached')
                    incident_id=uuid.uuid4().hex;status='open'
                    data={'signals':{},'timeline':[],'sensors':[],'kinds':[],'session_ids':[], 'mode':event.mode,'stream_id':event.stream_id}
                    db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?)',(incident_id,event.actor_id,scope,ts,ts,status,risk,'{}'))
                for s in signals:data['signals'][s['id']]=s
                for field,value in [('sensors',event.sensor_id),('kinds',event.kind),('session_ids',event.session_id)]:
                    if value and value not in data[field]:data[field]=(data[field]+[value])[-50:]
                data['timeline'].append({'event_id':eid,'observed_at':event.observed_at.isoformat(),
                    'kind':event.kind,'sensor_id':event.sensor_id,'session_id':event.session_id,
                    'scan_id':event.scan_id,'risk_score':risk,'signals':signals,'features':vector})
                data['timeline']=sorted(data['timeline'],key=lambda x:x['observed_at'])[-100:]
                db.execute('UPDATE incidents SET updated=?,status=?,risk=MAX(risk,?),data=? WHERE id=?',(end,status,risk,json.dumps(data),incident_id))
            result={'event_id':eid,'duplicate':False,'incident_id':incident_id,'risk_score':round(risk,2),
                'decision':'Review' if signals or raw['scan_risk']>=30 else 'Allow',
                'action_taken':'none','signals':signals,'features':vector,'window_seconds':300,
                'session_features':features([x for x in window if x.get('session_id')==event.session_id],event.kind) if event.session_id else None,
                'model':self.model.status(),'processing_ms':round((time.perf_counter()-started)*1000,2)}
            db.execute('INSERT INTO telemetry_events VALUES (?,?,?,?,?,?,?,?,?,?)',
                (eid,fingerprint,event.actor_id,scope,ts,now,event.session_id,event.scan_id,json.dumps(raw),json.dumps(result)))
        return result

    def incidents(self,status=None,mode=None,limit=20,offset=0):
        clauses=[];args=[]
        if status:clauses.append('status=?');args.append(status)
        if mode:clauses.append('scope LIKE ?');args.append(mode+':%')
        where=' WHERE '+' AND '.join(clauses) if clauses else ''
        with self.store.connect() as db:
            total=db.execute('SELECT COUNT(*) FROM incidents'+where,args).fetchone()[0]
            rows=db.execute('SELECT id,actor,scope,opened,updated,status,risk,data FROM incidents'+where+' ORDER BY updated DESC LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
        return {'total':total,'items':[self._incident(r,False) for r in rows]}

    def _incident(self,r,detail=True):
        data=json.loads(r[7]);data['signals']=list(data['signals'].values())
        if not detail:data.pop('timeline',None)
        return {'incident_id':r[0],'actor_id':r[1],'opened_at':datetime.fromtimestamp(r[3],timezone.utc).isoformat(),
            'updated_at':datetime.fromtimestamp(r[4],timezone.utc).isoformat(),'status':r[5],'risk_score':r[6],
            'decision':'Review','action_taken':'none',**data}

    def detail(self,iid):
        with self.store.connect() as db:r=db.execute('SELECT id,actor,scope,opened,updated,status,risk,data FROM incidents WHERE id=?',(iid,)).fetchone()
        if not r:raise TelemetryError(404,'Incident not found')
        return self._incident(r)

    def review(self,iid,status):
        with self.store.connect() as db:
            changed=db.execute('UPDATE incidents SET status=? WHERE id=?',(status,iid)).rowcount
        if not changed:raise TelemetryError(404,'Incident not found')
        return self.detail(iid)

    def summary(self):
        with self.store.connect() as db:
            events=db.execute('SELECT COUNT(*),COUNT(DISTINCT actor),COUNT(DISTINCT session),MAX(received) FROM telemetry_events').fetchone()
            statuses=dict(db.execute('SELECT status,COUNT(*) FROM incidents GROUP BY status').fetchall())
            modes=dict(db.execute("SELECT substr(scope,1,instr(scope,':')-1),COUNT(*) FROM telemetry_events GROUP BY 1").fetchall())
        return {'events':events[0],'actors':events[1],'sessions':events[2], 'last_received_at':datetime.fromtimestamp(events[3],timezone.utc).isoformat() if events[3] else None,
          'incidents':statuses,'modes':modes,'model':self.model.status(),'retention_days':7,'window_seconds':300}
