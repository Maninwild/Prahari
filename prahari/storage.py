import sqlite3
from contextlib import contextmanager
import json
from pathlib import Path

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL, decision TEXT NOT NULL, result TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS enforcement (event_id TEXT PRIMARY KEY, scan_id TEXT UNIQUE NOT NULL, mode TEXT NOT NULL, action TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS reviews (scan_id TEXT PRIMARY KEY, verdict TEXT NOT NULL, reviewed_at TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS scans_created ON scans(created)')
            db.execute('PRAGMA journal_mode=WAL')
    def setting(self,key,default=None):
        with self.connect() as db:row=db.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
        return row[0] if row else default
    def set_setting(self,key,value):
        with self.connect() as db:db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',(key,value))
    def review(self,scan_id,verdict):
        from datetime import datetime,timezone
        with self.connect() as db:db.execute('INSERT OR REPLACE INTO reviews VALUES (?,?,?)',(scan_id,verdict,datetime.now(timezone.utc).isoformat()))
    def event(self, event):
        values = (event.event_id,event.scan_id,event.mode,event.action)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT event_id,scan_id,mode,action FROM enforcement WHERE event_id=? OR scan_id=?',(event.event_id,event.scan_id)).fetchone()
            if existing:
                if existing != values: raise ValueError('Conflicting acknowledgement')
                return
            db.execute('INSERT INTO enforcement VALUES (?,?,?,?)',values)
    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10)
        try:
            with db:yield db
        finally:db.close()
    def save(self, result, kind):
        stored=result.model_dump()
        for finding in stored['findings']:finding['excerpt']=None
        with self.connect() as db:
            db.execute('INSERT INTO scans VALUES (?,?,?,?,?)', (result.scan_id,result.created_at,kind,result.decision,json.dumps(stored)))
    def list(self, decision, limit, offset, query=''):
        where = ' WHERE decision=?' if decision else ''
        args = [decision] if decision else []
        if query:
            where += (' AND ' if where else ' WHERE ') + 'id LIKE ?'
            args.append('%'+query+'%')
        with self.connect() as db:
            total = db.execute('SELECT count(*) FROM scans'+where,args).fetchone()[0]
            rows = db.execute('SELECT id,created,kind,decision FROM scans'+where+' ORDER BY created DESC LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
        return {'total':total,'items':[dict(zip(['scan_id','created_at','input_type','decision'],r)) for r in rows]}
    def get(self, scan_id):
        with self.connect() as db:
            row = db.execute('SELECT result FROM scans WHERE id=?',(scan_id,)).fetchone()
            events = db.execute('SELECT event_id,mode,action FROM enforcement WHERE scan_id=?',(scan_id,)).fetchall()
        if not row: return None
        result = json.loads(row[0])
        with self.connect() as db:review=db.execute('SELECT verdict,reviewed_at FROM reviews WHERE scan_id=?',(scan_id,)).fetchone()
        result['review'] = dict(zip(['verdict','reviewed_at'],review)) if review else None
        result['enforcement_events'] = [dict(zip(['event_id','mode','action'],event)) for event in events]
        return result
    def summary(self):
        with self.connect() as db:
            rows = db.execute('SELECT decision,count(*) FROM scans GROUP BY decision').fetchall()
            actions = dict(db.execute('SELECT action,count(*) FROM enforcement GROUP BY action').fetchall())
            recent=db.execute('SELECT substr(created,1,10),count(*) FROM scans GROUP BY substr(created,1,10) ORDER BY 1 DESC LIMIT 7').fetchall()
            reviewed=db.execute('SELECT count(*) FROM reviews').fetchone()[0]
        counts = {'Allow':0,'Review':0,'Block':0,**dict(rows)}
        return {'total':sum(counts.values()),'decisions':counts,'enforced_blocks':actions.get('blocked',0),'enforcement':actions,'reviewed':reviewed,'daily':[{'date':d,'count':c} for d,c in reversed(recent)]}
