"""Ingest Zeek JSON conn.log; replay historical files or follow a live sensor log."""
import argparse,hashlib,hmac,ipaddress,json,os,time,sys
from datetime import datetime,timezone
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError

def convert(row,key,mode='replay',stream='zeek-replay',sensor='zeek'):
    ip=ipaddress.ip_address(row['id.orig_h'])
    address=str(getattr(ip,'ipv4_mapped',None) or ip)
    destination=str(ipaddress.ip_address(row['id.resp_h']))
    duration=float(row.get('duration',0))
    # Zeek ts is connection start. Use completion time for the observation window.
    ended=float(row['ts'])+duration
    actor=hmac.new(key.encode(),('actor:'+address).encode(),hashlib.sha256).hexdigest()
    identity=hashlib.sha256((str(row['uid'])+':'+str(row['ts'])).encode()).hexdigest()
    return {'event_id':identity,'sensor_id':sensor,'mode':mode,'stream_id':stream,
       'observed_at':datetime.fromtimestamp(ended,timezone.utc).isoformat(),'actor_id':actor,
       'kind':'flow','destination':destination,'destination_port':int(row['id.resp_p']),
       'protocol':row.get('proto','unknown'),'duration_ms':duration*1000,
       'bytes_out':int(row.get('orig_bytes',0)),'bytes_in':int(row.get('resp_bytes',0)),
       'packets':int(row.get('orig_pkts',0))+int(row.get('resp_pkts',0)),
       'connection_failed':row.get('conn_state') in ('S0','REJ','RSTOS0','RSTRH','SH','SHR')}

def post(base,key,event):
    request=Request(base.rstrip('/')+'/api/v1/telemetry',data=json.dumps(event).encode(),
       headers={'Content-Type':'application/json','X-Prahari-Key':key})
    try:
        with urlopen(request,timeout=10) as response:return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f'Telemetry rejected (HTTP {error.code}). Check server configuration and event time; cursor was not advanced.') from None

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path);parser.add_argument('--base',default='http://127.0.0.1:8000')
    parser.add_argument('--stream',default='zeek-replay');parser.add_argument('--sensor',default='zeek')
    parser.add_argument('--follow',action='store_true');parser.add_argument('--checkpoint',type=Path,default=Path('data/zeek-checkpoint.json'))
    args=parser.parse_args()
    key=os.getenv('PRAHARI_INTEGRATION_KEY','');pseudo=os.getenv('PRAHARI_PSEUDONYM_KEY','')
    local=Path('data/pseudonym.key')
    if not pseudo and local.exists():pseudo=local.read_text().strip()
    if not key or not pseudo:parser.error('Set PRAHARI_INTEGRATION_KEY and PRAHARI_PSEUDONYM_KEY (or use data/pseudonym.key)')
    if args.follow:
        offset=0;source=str(args.file.resolve());stat=args.file.stat()
        identity=[stat.st_dev,stat.st_ino]
        config={'source':source,'sensor':args.sensor,'stream':args.stream,'identity':identity}
        if args.checkpoint.exists():
            saved=json.loads(args.checkpoint.read_text())
            if all(saved.get(k)==v for k,v in config.items()):offset=saved['offset']
        args.checkpoint.parent.mkdir(parents=True,exist_ok=True)
        with args.file.open('rb') as log:
            log.seek(offset)
            while True:
                current=args.file.stat()
                if [current.st_dev,current.st_ino]!=identity or current.st_size<log.tell():
                    raise RuntimeError('Log rotated or truncated. Restart this adapter to select the new file.')
                start=log.tell();line=log.readline()
                if not line.endswith(b'\n'):
                    log.seek(start);time.sleep(.25);continue
                if line.strip():
                    event=convert(json.loads(line),pseudo,'live',args.stream,args.sensor)
                    result=post(args.base,key,event)
                    print(json.dumps({'event_id':result['event_id'],'incident_id':result['incident_id']}),flush=True)
                temp=args.checkpoint.with_suffix('.tmp');temp.write_text(json.dumps({**config,'offset':log.tell()}));temp.replace(args.checkpoint)
    else:
        events=[]
        with args.file.open() as log:
            for line in log:
                if not line.strip():continue
                if len(events)>=100000:raise ValueError('Replay limit is 100,000 flows; split the input file')
                events.append(convert(json.loads(line),pseudo,'replay',args.stream,args.sensor))
        events.sort(key=lambda e:datetime.fromisoformat(e['observed_at']).timestamp());incidents=set()
        for event in events:
            result=post(args.base,key,event)
            if result['incident_id']:incidents.add(result['incident_id'])
        print(json.dumps({'flows_processed':len(events),'incidents':len(incidents),'mode':'replay'}))
if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:pass
    except Exception as error:sys.exit(str(error))
