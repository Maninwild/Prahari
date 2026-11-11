"""Five-minute rolling features and explainable advisory rules."""
FEATURES = {
 'http': ['count', 'unique_routes', 'auth_failures', 'error_ratio', 'attack_scans', 'bytes_out'],
 'flow': ['count', 'unique_destinations', 'unique_ports', 'failure_ratio', 'bytes_out', 'out_in_ratio'],
}

def features(events, kind):
    rows=[e for e in events if e['kind']==kind]
    n=len(rows)
    outbound=sum(e['bytes_out'] for e in rows)
    inbound=sum(e['bytes_in'] for e in rows)
    common={'count':n,'bytes_out':outbound}
    if kind=='http':
        return {**common,'unique_routes':len({e['route'] for e in rows}),
          'auth_failures':sum(e['auth_failed'] for e in rows),
          'error_ratio':sum(e['status_code']>=400 for e in rows)/max(n,1),
          'attack_scans':sum(e.get('rule_attack',False) for e in rows)}
    return {**common,'unique_destinations':len({e['destination'] for e in rows}),
      'unique_ports':len({e['destination_port'] for e in rows}),
      'failure_ratio':sum(e['connection_failed'] for e in rows)/max(n,1),
      'out_in_ratio':outbound/max(inbound,1)}

def rules(f,kind):
    result=[]
    def add(code,title,score,feature,threshold):
        result.append({'id':code,'title':title,'kind':'rule','score':score,
         'feature':feature,'observed':f[feature],'threshold':threshold,'window_seconds':300})
    if kind=='http':
        if f['auth_failures']>=5:add('auth-failures','Repeated authentication failures',80,'auth_failures',5)
        if f['attack_scans']>=3:add('repeated-attacks','Repeated explicit web attack patterns',85,'attack_scans',3)
        if f['count']>=60:add('request-burst','High request volume',60,'count',60)
        if f['unique_routes']>=15 and f['error_ratio']>=.5:
            add('route-probing','Many routes with mostly error responses',75,'unique_routes',15)
    else:
        if f['unique_ports']>=10 and f['failure_ratio']>=.5:
            add('port-probing','Multiple destination ports with failed connections',85,'unique_ports',10)
        if f['unique_destinations']>=15:
            add('host-fanout','Connections to many destinations',65,'unique_destinations',15)
        if f['bytes_out']>=50_000_000 and f['out_in_ratio']>=10:
            add('outbound-volume','Large asymmetric outbound transfer',75,'bytes_out',50_000_000)
    return result
