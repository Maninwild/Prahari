"""Bounded inspection views. No fetching and no payload execution."""
from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote, unquote_plus
import html
import ipaddress
import json
import re
import unicodedata
from .schemas import ScanInput

@dataclass
class Component:
    name: str
    text: str
    decode_percent: bool = False
    form_plus: bool = False

@dataclass
class Parsed:
    components: list[Component] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    url: str | None = None


def validate_url(text):
    if re.search(r'[\s\x00-\x1f\x7f]', text):
        raise ValueError('URL contains whitespace or control characters; percent-encode values.')
    try:
        p = urlsplit(text)
        host = p.hostname
        _ = p.port
        if p.scheme.lower() not in ('http', 'https') or not host:
            raise ValueError()
        if p.username is not None or p.password is not None:
            raise ValueError('Credential-bearing URLs are unsupported.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            host = host.encode('idna').decode('ascii')
            if len(host) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in host.rstrip('.').split('.')):
                raise ValueError()
        return p
    except (ValueError, UnicodeError) as error:
        raise ValueError('Enter a valid absolute HTTP(S) URL without embedded credentials.') from error


def pairs(text, prefix, out):
    # Preserve duplicate keys and raw bytes for evidence views.
    parts = text.split('&') if text else []
    if len(parts) > 100:
        out.issues.append('Parameter count exceeds supported limit (100).')
    for index, pair in enumerate(parts[:100]):
        key, _, value = pair.partition('=')
        out.components.extend([Component(f'{prefix}[{index}].key', key, True, True), Component(f'{prefix}[{index}].value', value, True, True)])
        # Inspect the pair as well for signatures depending on a parameter name.
        out.components.append(Component(f'{prefix}[{index}].pair', pair, True, True))


def body_parts(body, kind, out):
    if kind == 'application/json':
        try:
            def no_duplicates(items):
                d = {}
                for key, value in items:
                    if key in d:
                        raise ValueError('Duplicate JSON keys')
                    d[key] = value
                return d
            obj = json.loads(body, object_pairs_hook=no_duplicates)
            def walk(v, depth=0):
                if depth > 20 or len(out.components) > 300:
                    raise ValueError('JSON complexity limit')
                if isinstance(v, dict):
                    for k, x in v.items():
                        out.components.append(Component(f'json.key[{len(out.components)}]', k))
                        walk(x, depth+1)
                elif isinstance(v, list):
                    for x in v: walk(x, depth+1)
                elif isinstance(v, str):
                    out.components.append(Component(f'json.value[{len(out.components)}]', v))
            walk(obj)
        except (ValueError, RecursionError):
            out.issues.append('Malformed, ambiguous or overly complex JSON body.')
    elif kind == 'application/x-www-form-urlencoded':
        pairs(body, 'form', out)
    elif kind == 'text/plain':
        out.components.append(Component('body', body))
    else:
        out.issues.append('Unsupported body content type: analysis is incomplete.')


def parse(data: ScanInput) -> Parsed:
    out = Parsed()
    if data.input_type == 'url':
        p = validate_url(data.content.strip())
        out.url = data.content.strip()
        out.components.append(Component('url.path', p.path, True))
        pairs(p.query, 'query', out)
        if p.fragment: out.components.append(Component('url.fragment', p.fragment, True))
    elif data.input_type == 'payload':
        body_parts(data.content, data.content_type, out)
    else:
        text = data.content.replace('\r\n', '\n')
        head, sep, body = text.partition('\n\n')
        lines = head.split('\n')
        match = re.fullmatch(r'([A-Z]+) ([^\s]+) HTTP/(1\.[01]|2(?:\.0)?)', lines[0])
        if not match:
            raise ValueError('Use a complete request line: METHOD /path HTTP/1.1; encode spaces in the target.')
        target = match.group(2)
        if not target.startswith('/') or target.startswith('//') or '#' in target:
            raise ValueError('Only origin-form request targets (/path?query) are supported.')
        p = urlsplit(target)
        out.components.append(Component('request.path', p.path, True))
        pairs(p.query, 'query', out)
        headers = {}
        for i, line in enumerate(lines[1:]):
            key, colon, val = line.partition(':')
            if not colon or not re.fullmatch(r'[!#$%&\x27*+.^_`|~0-9a-zA-Z-]+', key):
                out.issues.append('Malformed header.')
                continue
            key = key.lower()
            if key in headers: out.issues.append('Repeated headers require review.')
            headers[key] = val.strip()
            out.components.append(Component(f'header[{i}]', val.strip()))
        if 'transfer-encoding' in headers or headers.get('content-encoding', 'identity') != 'identity':
            out.issues.append('Encoded or chunked bodies are unsupported.')
        if 'content-length' in headers:
            try:
                if int(headers['content-length']) != len(body.encode('utf-8')): out.issues.append('Content-Length does not match supplied body.')
            except ValueError: out.issues.append('Invalid Content-Length.')
        if sep and body:
            kind = headers.get('content-type', 'text/plain').split(';')[0].strip().lower()
            body_parts(body, kind, out)
    if any(re.search(r'%(?![0-9a-fA-F]{2})', c.text) for c in out.components if c.decode_percent):
        out.issues.append('Malformed percent encoding.')
    return out


def views(component):
    yield 'raw', component.text, []
    current = component.text
    steps = []
    if component.form_plus and '+' in current:
        current = current.replace('+', ' ')
        steps.append('form plus to space')
    for i in range(2):
        decoded = unquote(current, errors='strict') if component.decode_percent else current
        decoded = html.unescape(unicodedata.normalize('NFKC', decoded))
        if decoded != current:
            steps.append(f'heuristic decode {i+1}')
        if decoded == current:
            break
        current = decoded
    if current != component.text:
        yield 'decoded', current, steps
