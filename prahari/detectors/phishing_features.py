"""Version 2 lexical features. Same implementation at fit and prediction."""
from urllib.parse import urlsplit, unquote
from collections import Counter
import math, ipaddress, re
import tldextract
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(),include_psl_private_domains=True)
SHORTENERS = {'bit.ly','tinyurl.com','t.co','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly'}
WORDS = ('verify','secure','account','login','signin','password','billing','update','confirm','bank')
def hostname(url):
    p=urlsplit(url if '://' in url else 'https://'+url)
    host=(p.hostname or '').lower().rstrip('.')
    try:host=host.encode('idna').decode('ascii')
    except UnicodeError:pass
    return host

def domain_group(url):
    host=hostname(url)
    parsed=EXTRACT(host)
    return parsed.top_domain_under_public_suffix or host

def extract_features(url):
    p=urlsplit(url if '://' in url else 'https://'+url)
    host=hostname(url)
    host=host[4:] if host.startswith('www.') else host
    parts=EXTRACT(host)
    try:ipaddress.ip_address(host);is_ip=1
    except ValueError:is_ip=0
    freq=Counter(host)
    entropy=-sum((n/max(1,len(host)))*math.log2(n/max(1,len(host))) for n in freq.values())
    return {'host_length':len(host),'host_digits':sum(x.isdigit() for x in host),'host_hyphens':host.count('-'),'host_entropy':entropy,'subdomain_count':len(parts.subdomain.split('.')) if parts.subdomain else 0,'ip_host':is_ip,'punycode':int('xn--' in host),'shortener':int(host in SHORTENERS),'https':int(p.scheme.lower()=='https'),'host_keywords':sum(w in host for w in WORDS),'path_length':len(p.path),'path_depth':len([x for x in p.path.split('/') if x]),'query_length':len(p.query),'query_parameters':len(p.query.split('&')) if p.query else 0,'encoded_chars':len(re.findall(r'%[a-fA-F0-9]{2}',url)),'url_digits':sum(x.isdigit() for x in url),'at_sign':url.count('@'),'path_keywords':sum(w in unquote(p.path).lower() for w in WORDS)}
FEATURE_NAMES=list(extract_features('https://example.com'))
