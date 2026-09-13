#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import hashlib
import io
import json
import os
import platform
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
# Official releases pinned by archive and extracted-binary SHA256.
# GOST: https://github.com/go-gost/gost
# Backhaul: https://github.com/Musixal/Backhaul
# Rathole: https://github.com/rathole-org/rathole
THIRD_PARTY_RELEASES = {
    "gost": ("3.3.0", "https://github.com/go-gost/gost/releases/download/v3.3.0/gost_3.3.0_linux_amd64.tar.gz", "676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5", "1d8f971e9447cf4114fb1376b85c8c14e840db50ae8dbe895398a34e97c13e08"),
    "backhaul": ("0.7.2", "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz", "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc", "7f1b1439d7fe1d15ae0b376e15614fe13d8a12f6e07a90263e310ea2a9d601fb"),
    "rathole": ("0.5.0", "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip", "3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e", "d2202f2aa3a432135bddbe1c6104600c6577cd4507a70e77c08741c7ad879926"),
}
def ensure_dependencies():
    if os.geteuid() != 0:
        raise RuntimeError("Run this manager with sudo python3 multi-tunnel.py")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    version = tuple(int(part) for part in release.get("VERSION_ID", "0").strip('"').split("."))
    if release.get("ID", "").strip('"') != "ubuntu" or version < (22, 4) or platform.machine() != "x86_64":
        raise RuntimeError("This release supports Ubuntu 22.04+ on x86_64 only")
    packages = ["python3", "openssl", "ufw", "iproute2", "ca-certificates", "iptables"]
    status = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package} ${db:Status-Status}\\n", *packages], capture_output=True, text=True)
    installed = set(status.stdout.splitlines())
    if all(f"{package} installed" in installed for package in packages):
        return
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    subprocess.run(["apt-get", "update"], check=True, timeout=600, env=env, capture_output=True, text=True)
    subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", *packages], check=True, timeout=600, env=env, capture_output=True, text=True)
def _release_download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "multi-tunnel/2.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=45) as response:
                if not response.geturl().startswith("https://"):
                    raise RuntimeError("Refusing an insecure download redirect")
                data = response.read(128 * 1024 * 1024 + 1)
                if len(data) > 128 * 1024 * 1024:
                    raise RuntimeError("Release archive exceeds size limit")
                return data
        except urllib.error.HTTPError as error:
            if attempt == 2 or error.code not in {408, 429, 500, 502, 503, 504}:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)
    raise RuntimeError("Release download failed")
def _release_executable(data, url, engine):
    archive_data = io.BytesIO(data)
    if url.endswith(".zip"):
        with zipfile.ZipFile(archive_data) as archive:
            members = [member for member in archive.infolist() if member.filename == engine]
            if len(members) != 1 or members[0].is_dir() or members[0].file_size > 128 * 1024 * 1024:
                raise RuntimeError("Invalid executable in ZIP archive")
            return archive.read(members[0])
    with tarfile.open(fileobj=archive_data, mode="r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == engine]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 128 * 1024 * 1024:
            raise RuntimeError("Invalid executable in TAR archive")
        with archive.extractfile(members[0]) as source:
            return source.read()
def install_binary(engine):
    if engine not in THIRD_PARTY_RELEASES:
        raise ValueError("Unknown tunnel engine")
    ensure_dependencies()
    version, url, archive_sha, executable_sha = THIRD_PARTY_RELEASES[engine]
    directory = Path("/usr/local/lib/multi-tunnel/bin")
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination = directory / f"{engine}-{version}"
    if destination.is_file() and not destination.is_symlink():
        if hashlib.sha256(destination.read_bytes()).hexdigest() == executable_sha:
            destination.chmod(0o755)
            return str(destination)
    archive = _release_download(url)
    if hashlib.sha256(archive).hexdigest() != archive_sha:
        raise RuntimeError(f"{engine}: release archive SHA256 mismatch")
    executable = _release_executable(archive, url, engine)
    if hashlib.sha256(executable).hexdigest() != executable_sha:
        raise RuntimeError(f"{engine}: executable SHA256 mismatch")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{engine}-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(executable)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o755)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return str(destination)
def compile_backhaul(s,role,base):
    transport=s['transport']
    d={'transport':transport,'token':s['token'],'keepalive_period':int(s['keepalive']),'nodelay':True,'sniffer':bool(s['sniffer'] and role=='iran'),'web_port':int(s.get('monitor',0)) if s['sniffer'] and role=='iran' else 0,'sniffer_log':base+'/usage.json','log_level':'info','skip_optz':True}
    if transport in ('tcpmux','wsmux'):
        d.update(mux_version=int(s['mux_version']),mux_framesize=32768,mux_recievebuffer=int(s['mux_buffer']),mux_streambuffer=int(s['mux_stream']))
    if role=='iran':
        section='server'
        d.update(bind_addr='127.0.0.1:'+str(s['control']),heartbeat=int(s.get('heartbeat',20)),channel_size=2048,ports=[str(p)+'=127.0.0.1:'+str(q) for p,q in s['maps']]+['127.0.0.1:'+str(s['health_i'])+'=127.0.0.1:'+str(s['health_f'])])
        if transport=='tcp': d['accept_udp']=bool(s.get('udp_over_tcp',False))
        if transport in ('tcpmux','wsmux'): d['mux_con']=int(s['mux_con'])
    else:
        section='client'
        d.update(remote_addr='127.0.0.1:'+str(s['bridge']),connection_pool=int(s.get('pool',8)),retry_interval=3,dial_timeout=10,aggressive_pool=False)
    return '['+section+']\n'+'\n'.join(k+' = '+json.dumps(v) for k,v in d.items())+'\n'
def compile_rathole(s, role, base):
    side = 'server' if role == 'iran' else 'client'
    lines = [f'[{side}]']
    lines.append(('bind_addr = ' + json.dumps('127.0.0.1:' + str(s['control']))) if side == 'server' else ('remote_addr = ' + json.dumps('127.0.0.1:' + str(s['bridge']))))
    lines += ['default_token = ' + json.dumps(s['token']), f'[{side}.transport]', 'type = ' + json.dumps('websocket' if s['transport'] == 'ws' else 'tcp'), f'[{side}.transport.tcp]', 'nodelay = true', 'keepalive_secs = ' + str(s['keepalive']), 'keepalive_interval = 5']
    if s['transport'] == 'ws':
        lines += [f'[{side}.transport.websocket]', 'tls = false']
    for i, (public, target) in enumerate(s['maps']):
        addr = ('0.0.0.0:' + str(public)) if side == 'server' else ('127.0.0.1:' + str(target))
        lines += [f'[{side}.services.p{i}]', 'type = "tcp"', ('bind_addr = ' if side == 'server' else 'local_addr = ') + json.dumps(addr)]
    lines += [f'[{side}.services.health]', 'type = "tcp"', ('bind_addr = ' if side == 'server' else 'local_addr = ') + json.dumps('127.0.0.1:' + str(s['health_i'] if side == 'server' else s['health_f']))]
    return '\n'.join(lines) + '\n'
def _gost_addr(host, port):
    return ('[' + host + ']' if ':' in host else host) + ':' + str(port)
def _gost_auth(s):
    return {'username': 'multi', 'password': s['token']}
def _gost_tls(s, base, server=False):
    if server:
        return {'certFile': s.get('origin_cert', base + '/cert.pem'), 'keyFile': s.get('origin_key', base + '/key.pem')}
    tls = {'secure': True, 'serverName': s['endpoint']}
    if not s['cdn']:
        tls['caFile'] = base + '/ca.pem'
    return tls
def _gost_node(s, base, transport):
    node = {'name': 'foreign', 'addr': _gost_addr(s['endpoint'], s['front']), 'connector': {'type': 'relay', 'auth': _gost_auth(s), 'metadata': {'nodelay': True}}, 'dialer': {'type': transport, 'tls': _gost_tls(s, base)}}
    if transport == 'wss':
        node['dialer']['metadata'] = {'path': '/multi/' + s.get('peer_id',s['id']), 'keepalive': True, 'ttl': str(s['keepalive']) + 's'}
    return node
def _gost_chain(s, base, transport):
    return [{'name': 'foreign', 'hops': [{'name': 'transport', 'nodes': [_gost_node(s, base, transport)]}]}]
def _gost_relay(s, base, transport, reverse):
    listener = {'type': transport, 'tls': _gost_tls(s, base, True)}
    if transport == 'wss':
        listener['metadata'] = {'path': '/multi/' + s['id']}
    service = {'name': 'receiver', 'addr': '0.0.0.0:' + str(s['front']), 'bypass': 'targets', 'handler': {'type': 'relay', 'auth': _gost_auth(s), 'metadata': {'bind': bool(reverse), 'readTimeout': '15s', 'nodelay': True, 'udpBufferSize': 65535}}, 'listener': listener}
    # Bypass restricts CONNECT destinations; GOST does not apply it to BIND addresses.
    # Generated rtcp/rudp requests below explicitly bind 127.0.0.1. Never share token.
    targets = ['127.0.0.1'] if reverse else ['127.0.0.1:' + str(p) for p in sorted({int(q) for _, q in s['maps']} | {int(s['health_f'])})]
    return {'services': [service], 'bypasses': [{'name': 'targets', 'whitelist': True, 'matchers': targets}]}
def _gost_forward(name, listen, target, protocol='tcp', chained=False, reverse=False):
    kind = ('r' if reverse else '') + protocol
    service = {'name': name, 'addr': listen, 'handler': {'type': kind}, 'listener': {'type': kind}, 'forwarder': {'nodes': [{'name': 'target', 'addr': target}]}}
    if protocol == 'udp':
        service['listener']['metadata'] = {'keepAlive': True, 'ttl': '60s', 'readBufferSize': 65535}
    if chained:
        service['listener' if reverse else 'handler']['chain'] = 'foreign'
    return service
def compile_spec(s, role, base):
    if role not in ('iran', 'foreign'):
        raise ValueError('Invalid node role')
    engine, transport = s['engine'], s['transport']
    files = {}
    if engine == 'gost':
        simple = transport in ('tcp', 'udp')
        if s['cdn'] and transport != 'ws':
            raise ValueError('GOST CDN mode requires WS')
        if simple:
            if role == 'foreign':
                return files
            services = [_gost_forward('p' + str(i), '0.0.0.0:' + str(p), _gost_addr(s['endpoint'], q), transport) for i, (p, q) in enumerate(s['maps'])]
            services.append(_gost_forward('health', '127.0.0.1:' + str(s['health_i']), _gost_addr(s['endpoint'], s['health_f']), transport))
            config = {'services': services}
        else:
            wire = {'ws': 'wss', 'grpc': 'grpc', 'tcpmux': 'mtls'}[transport]
            if role == 'foreign':
                config = _gost_relay(s, base, wire, False)
            else:
                services = [_gost_forward('p' + str(i), '0.0.0.0:' + str(p), '127.0.0.1:' + str(q), chained=True) for i, (p, q) in enumerate(s['maps'])]
                services.append(_gost_forward('health', '127.0.0.1:' + str(s['health_i']), '127.0.0.1:' + str(s['health_f']), chained=True))
                config = {'services': services, 'chains': _gost_chain(s, base, wire)}
    elif engine in ('backhaul', 'rathole'):
        wire = 'wss' if s['cdn'] else 'tls'
        if role == 'foreign':
            config = _gost_relay(s, base, wire, True)
        else:
            protocols = ('tcp', 'udp') if engine == 'backhaul' and transport == 'udp' else ('tcp',)
            services = [_gost_forward('carrier-' + p, '127.0.0.1:' + str(s['bridge']), '127.0.0.1:' + str(s['control']), p, True, True) for p in protocols]
            config = {'services': services, 'chains': _gost_chain(s, base, wire)}
        files['engine.toml'] = compile_backhaul(s, role, base) if engine == 'backhaul' else compile_rathole(s, role, base)
    else:
        raise ValueError('Unsupported engine')
    files['gost.json'] = json.dumps(config, ensure_ascii=True, indent=2) + '\n'
    return files
import base64, binascii, datetime, fcntl, getpass, hmac, ipaddress, re, secrets, shlex, shutil, socket, sys, threading
VERSION = '2.2.0'
ROOT = Path('/etc/multi-tunnel')
SCRIPT = Path('/usr/local/lib/multi-tunnel/multi-tunnel.py')
UNITS = Path('/etc/systemd/system')
DEFAULT_PORTS = '443,2083,2053,1115,1117'
TRANSPORTS = {'gost':('tcp','udp','ws','grpc','tcpmux'),'backhaul':('tcp','udp','ws','wsmux','tcpmux'),'rathole':('tcp','ws')}
SHARED = ('schema_version','id','revision','engine','transport','endpoint','cdn','maps','front','bridge','health_f','token','keepalive','udp_over_tcp','mux_con','mux_version','mux_stream','mux_buffer')
def run(args, check=True, timeout=180):
    p = subprocess.run([str(x) for x in args], text=True, capture_output=True, timeout=timeout)
    if check and p.returncode: raise RuntimeError((p.stderr or p.stdout or 'Command failed')[-1500:])
    return p.stdout.strip()
def write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp = tempfile.mkstemp(prefix='.'+path.name,dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(data); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(),0o600)
        os.replace(tmp,path)
    finally: Path(tmp).unlink(missing_ok=True)
def read(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).is_file() else default
def valid_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,23}',value): raise ValueError('Tunnel name: 1..24 lowercase letters, digits or hyphens.')
    return value
def host(value):
    if not isinstance(value,str): raise ValueError('Invalid endpoint.')
    value = value.strip().lower()
    try:
        address = ipaddress.ip_address(value)
        if address.version!=4: raise ValueError('Use IPv4 in this release.')
        return str(address)
    except ValueError:
        if re.fullmatch(r'[0-9.]+',value): raise ValueError('Invalid IPv4 address.')
        labels = value.split('.')
        if len(value)>253 or len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels): raise ValueError('Enter a domain or IPv4, without protocol, path or port.')
        return value
def integer(value, low, high, label):
    if type(value)!=int or not low<=value<=high: raise ValueError(f'{label} must be {low}..{high}.')
    return value
def port(value): return integer(int(value),1,65535,'Port')
def parse_maps(value):
    result = []
    for item in value.split(','):
        parts = item.strip().split(':')
        if len(parts) not in (1,2): raise ValueError('Use 443,2083 or 443:8443,2083:2083.')
        result.append([port(parts[0]),port(parts[-1])])
    if not 1<=len(result)<=128 or len({x[0] for x in result})!=len(result): raise ValueError('Empty, duplicate or excessive ports.')
    return result
def validate_shared(s):
    if not isinstance(s,dict) or set(s)!=set(SHARED): raise ValueError('Unexpected or missing pairing fields.')
    if type(s['schema_version'])!=int or s['schema_version']!=2: raise ValueError('Unsupported pairing version.')
    valid_id(s['id'])
    for key,size in [('token',64),('revision',32)]:
        if not isinstance(s[key],str) or not re.fullmatch('[0-9a-f]{'+str(size)+'}',s[key]): raise ValueError('Invalid '+key)
    if s['engine'] not in TRANSPORTS or s['transport'] not in TRANSPORTS[s['engine']]: raise ValueError('Unsupported engine/transport.')
    if host(s['endpoint'])!=s['endpoint']: raise ValueError('Endpoint is not canonical.')
    for key in ('cdn','udp_over_tcp'):
        if type(s[key])!=bool: raise ValueError('Invalid '+key)
    maps = s['maps']
    if not isinstance(maps,list) or not 1<=len(maps)<=128: raise ValueError('Invalid port maps.')
    for pair in maps:
        if not isinstance(pair,list) or len(pair)!=2: raise ValueError('Invalid port pair.')
        for p in pair: integer(p,1,65535,'Port')
    if len({p for p,_ in maps})!=len(maps): raise ValueError('Duplicate Iran ports.')
    for key in ('front','bridge','health_f'): integer(s[key],1,65535,key)
    if len({s[k] for k in ('front','bridge','health_f')})!=3: raise ValueError('Foreign internal port collision.')
    bound = {s['health_f']} | ({s['front']} if not (s['engine']=='gost' and s['transport'] in ('tcp','udp')) else set()) | ({s['bridge']} if s['engine']!='gost' else set())
    if bound & {q for _,q in maps}: raise ValueError('Foreign service/transport port collision.')
    if s['cdn']:
        try: ipaddress.ip_address(s['endpoint'])
        except ValueError: pass
        else: raise ValueError('Cloudflare mode requires a hostname.')
        if s['front'] not in (443,2053,2083,2087,2096,8443): raise ValueError('Unsupported Cloudflare HTTPS port.')
        if s['engine']=='gost' and s['transport']!='ws': raise ValueError('GOST Cloudflare mode requires WS.')
    if s['udp_over_tcp'] and (s['engine'],s['transport'])!=('backhaul','tcp'): raise ValueError('UDP-over-TCP is a Backhaul TCP option.')
    integer(s['keepalive'],5,300,'Keepalive')
    integer(s['mux_con'],1,64,'Mux connections')
    integer(s['mux_version'],1,2,'Mux version')
    integer(s['mux_stream'],4096,67108864,'Mux stream buffer')
    integer(s['mux_buffer'],s['mux_stream'],67108864,'Mux receive buffer')
    return s
def simple_gost(s): return s['engine']=='gost' and s['transport'] in ('tcp','udp')
def encode_pair(s, ca=''):
    shared = validate_shared({k:s[k] for k in SHARED})
    payload = json.dumps({'spec':shared,'ca':ca},separators=(',',':')).encode()
    return 'MULTI2.'+base64.urlsafe_b64encode(payload).decode()
def decode_pair(value):
    if not value.startswith('MULTI2.') or len(value)>65536: raise ValueError('Invalid connection code.')
    try:
        payload = base64.b64decode(value[7:],altchars=b'-_',validate=True)
        data = json.loads(payload)
    except (ValueError,UnicodeError,binascii.Error) as e: raise ValueError('Invalid connection code encoding.') from e
    if not isinstance(data,dict) or set(data)!= {'spec','ca'}: raise ValueError('Invalid connection envelope.')
    s = validate_shared(data['spec'])
    ca = data['ca']
    if not isinstance(ca,str) or len(ca)>16384: raise ValueError('Invalid public certificate.')
    if not simple_gost(s) and not s['cdn']:
        if not ca.startswith('-----BEGIN CERTIFICATE-----') or 'PRIVATE KEY' in ca: raise ValueError('Missing public CA certificate.')
        with tempfile.TemporaryDirectory() as d:
            write(Path(d)/'ca.pem',ca)
            run(['openssl','x509','-in',d+'/ca.pem','-noout','-checkend','0'])
    elif ca: raise ValueError('Unexpected certificate data.')
    return s,ca
def ask(label, default=''):
    print()
    try: value = input(label+(f' [{default}]' if default!='' else '')+': ').strip()
    finally: print()
    return value if value else str(default)
def choose(label, options, default):
    labels = {'iran':'Iran','foreign':'Foreign','gost':'GOST','backhaul':'Backhaul','rathole':'Rathole','tcp':'TCP','udp':'UDP','ws':'WS','grpc':'gRPC','tcpmux':'TCPMux','wsmux':'WSMux','y':'Yes','n':'No','status':'Status','test':'test tunnel connection','edit':'Edit','delete':'Delete','restart':'Restart','logs':'Logs','code':'Show connection code','cert':'get cert for sub domain','ssh':'Set up Iran via SSH'}
    print()
    for number, option in enumerate(options,1): print(str(number)+') '+labels.get(option,option))
    value = ask(label,options.index(default)+1)
    try: number = int(value)
    except ValueError: raise ValueError('Invalid selection. Enter an option number.') from None
    if not 1<=number<=len(options): raise ValueError('Invalid selection. Enter an option number.')
    return options[number-1]
def yes(label, default=False): return choose(label,('y','n'),'y' if default else 'n')=='y'
def confirm_yn(label):
    while True:
        value = ask(label+' (y/n)')
        if value in ('y','n'): return value=='y'
        print('Please enter y or n.')
def all_manifests():
    return [read(p) for p in ROOT.glob('[a-z0-9]*/manifest.json') if read(p,{}).get('schema_version')==2]
def legacy_ids():
    return [p.parent.name for p in ROOT.glob('[a-z0-9]*/spec.json') if read(p,{}).get('schema_version')!=2]
def protocols(s):
    if s['udp_over_tcp']: return ('tcp','udp')
    return ('udp',) if s['transport']=='udp' else ('tcp',)
def claims(s):
    if s['role']=='iran':
        out = [(p,t,'0.0.0.0') for p,_ in s['maps'] for t in protocols(s)]
        out += [(s['health_i'],t,'127.0.0.1') for t in protocols(s)]
        if s['engine']!='gost':
            out += [(s['control'],'tcp','127.0.0.1')]
            if s['transport']=='udp': out += [(s['control'],'udp','127.0.0.1')]
        if s['sniffer']: out += [(s['monitor'],'tcp','0.0.0.0')]
        return out
    out = [(s['health_f'],t,'0.0.0.0' if simple_gost(s) else '127.0.0.1') for t in ('tcp','udp')]
    if not simple_gost(s): out += [(s['front'],'tcp','0.0.0.0')]
    if s['engine']!='gost':
        out += [(s['bridge'],'tcp','127.0.0.1')]
        if s['transport']=='udp': out += [(s['bridge'],'udp','127.0.0.1')]
    return out
def available(items, own=()):
    seen = set(); own = {(p,t) for p,t,_ in own}
    for p,t,address in items:
        if (p,t) in seen: raise ValueError(f'Local port collision: {p}/{t}')
        seen.add((p,t))
        if (p,t) in own: continue
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if t=='udp' else socket.SOCK_STREAM) as sock: sock.bind((address,p))
        except OSError as e: raise RuntimeError(f'Port {address}:{p}/{t} is busy.') from e
def free_port(excluded):
    reserved = {p for m in all_manifests() for p,_,_ in m['claims']} | set(excluded)
    for _ in range(200):
        p = 20000+secrets.randbelow(30000)
        if p in reserved: continue
        try: available([(p,'tcp','0.0.0.0'),(p,'udp','0.0.0.0')]); return p
        except RuntimeError: pass
    raise RuntimeError('No free internal port found.')
def firewall_rules(s):
    if s['role']=='iran': return [[p,t,'any'] for p,_ in s['maps'] for t in protocols(s)]
    if simple_gost(s): return [[q,s['transport'],'any'] for _,q in s['maps']]+[[s['health_f'],t,'any'] for t in ('tcp','udp')]
    return [[s['front'],'tcp','any']]
def rule_key(args):
    args = args[:args.index('comment')] if 'comment' in args else list(args)
    if args[:1]!=['allow'] or 'out' in args or 'on' in args: return set()
    if args[1:2]==['in']: args.pop(1)
    source = args[args.index('from')+1] if 'from' in args else 'any'
    if 'to' in args and args[args.index('to')+1]!='any': return set()
    number = args[args.index('port')+1] if 'port' in args else args[1]
    proto = args[args.index('proto')+1] if 'proto' in args else 'both'
    if '/' in number: number,proto = number.split('/',1)
    return {(int(number),t,source) for t in (('tcp','udp') if proto=='both' else (proto,))} if number.isdigit() else set()
def firewall():
    desired = {tuple(x) for m in all_manifests() for x in m['rules']}
    existing = []; present = set()
    for line in run(['ufw','show','added']).splitlines():
        args = shlex.split(line)
        if args[:1]!=['ufw']: continue
        args = args[1:]; keys = rule_key(args); present |= keys
        owned = 'comment' in args and args[args.index('comment')+1]=='multi-v2'
        existing.append((args,keys,owned))
    for p,t,source in sorted(desired-present): run(['ufw','allow','proto',t,'from',source,'to','any','port',str(p),'comment','multi-v2'])
    for args,keys,owned in existing:
        if owned and not keys & desired: run(['ufw','--force','delete']+args)
def monitor_guard(s, enabled):
    if s['role']!='iran' or not s['sniffer']: return
    rule = ['!','-i','lo','-p','tcp','--dport',str(s['monitor']),'-m','comment','--comment','multi-v2-'+s['id'],'-j','DROP']
    for binary in ('iptables','ip6tables'):
        present = subprocess.run([binary,'-C','INPUT']+rule,capture_output=True).returncode==0
        if enabled and not present: run([binary,'-I','INPUT','1']+rule)
        elif not enabled and present: run([binary,'-D','INPUT']+rule)
def unit_names(s):
    names = ['gost'] if s['engine']=='gost' else ['gost',s['engine']]
    if s['role']=='foreign':
        if simple_gost(s): names = []
        names += ['echo']
    return names
def service(s,name): return 'multi-'+s['id']+'-'+name+'.service'
def unit_text(s,name):
    base = ROOT/s['id']
    if name=='echo': cmd = f'/usr/bin/python3 {SCRIPT} echo {base}/spec.json'
    else:
        binary = install_binary(name)
        cmd = f'{binary} -C {base}/gost.json' if name=='gost' else f'{binary} -c {base}/engine.toml' if name=='backhaul' else f'{binary} {base}/engine.toml'
    guard = ''
    if name=='backhaul' and s['role']=='iran' and s['sniffer']: guard = f'ExecStartPre=/usr/bin/python3 {SCRIPT} guard-on {base}/spec.json\nExecStopPost=/usr/bin/python3 {SCRIPT} guard-off {base}/spec.json\n'
    return f'[Unit]\nDescription=Multi Tunnel {s["id"]} {name}\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=0\n[Service]\nType=simple\n{guard}ExecStart={cmd}\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=read-only\nProtectSystem=full\nReadWritePaths={base}\n[Install]\nWantedBy=multi-user.target\n'
def validate_local_directory(base):
    if not base.exists(): return
    s,m = read(base/'spec.json'),read(base/'manifest.json')
    if not isinstance(s,dict) or not isinstance(m,dict) or m.get('schema_version')!=2: raise ValueError('Missing or incompatible local manifest: '+base.name)
    validate_shared({k:s[k] for k in SHARED})
    if s.get('role') not in ('iran','foreign') or type(s.get('sniffer'))!=bool: raise ValueError('Invalid local role/settings.')
    if 'peer_id' in s:
        valid_id(s['peer_id'])
        if s['role']!='iran': raise ValueError('Only Iran may have a separate local tunnel name.')
    if m.get('id')!=s['id'] or m.get('role')!=s['role']: raise ValueError('Local identity mismatch.')
    if m.get('units')!=[service(s,n) for n in unit_names(s)]: raise ValueError('Local service manifest mismatch.')
    if s['role']=='iran':
        for key in ('control','health_i','monitor'): integer(s[key],1,65535,key)
    if {tuple(x) for x in m['claims']}!=set(claims(s)): raise ValueError('Local port manifest mismatch.')
def stop_directory(base):
    m = read(base/'manifest.json')
    if not m: return
    for name in m['units']:
        if (UNITS/name).exists():
            run(['systemctl','stop',name]); run(['systemctl','disable',name]); (UNITS/name).unlink()
    run(['systemctl','daemon-reload'])
def start_directory(base):
    m = read(base/'manifest.json')
    for name in m['units']: write(UNITS/name,(base/name).read_text())
    run(['systemctl','daemon-reload']); firewall()
    for name in m['units']: run(['systemctl','enable','--now',name])
    time.sleep(1)
    for name in m['units']:
        if run(['systemctl','is-active',name],check=False)!='active': raise RuntimeError('Service did not stay active: '+name)
def pending_path(ident): return ROOT/('.pending-'+valid_id(ident)+'.json')
def recover(ident):
    valid_id(ident)
    base = ROOT/ident; stage = ROOT/('.stage-'+ident); backup = ROOT/('.backup-'+ident); discard = ROOT/('.discard-'+ident)
    pending = read(pending_path(ident))
    if not pending: raise RuntimeError('No pending local operation.')
    phase = pending['phase']
    if phase not in ('apply','commit','delete'): raise ValueError('Invalid local recovery phase.')
    validate_local_directory(base)
    if phase=='commit':
        if not base.exists(): raise RuntimeError('Committed configuration is missing.')
        (base/'.uncommitted').unlink(missing_ok=True)
        if backup.exists(): shutil.rmtree(backup)
    elif phase=='delete':
        if base.exists():
            stop_directory(base)
            if discard.exists(): shutil.rmtree(discard)
            base.rename(discard)
        firewall()
    else:
        validate_local_directory(backup)
        if backup.exists() or (base/'.uncommitted').exists():
            if base.exists():
                stop_directory(base)
                if discard.exists(): shutil.rmtree(discard)
                base.rename(discard)
            if backup.exists():
                backup.rename(base); start_directory(base); (base/'.needs-restart').unlink(missing_ok=True)
            else: firewall()
        elif (base/'.needs-restart').exists():
            start_directory(base); (base/'.needs-restart').unlink(missing_ok=True)
    if phase=='apply': firewall()
    if stage.exists(): shutil.rmtree(stage)
    if discard.exists(): shutil.rmtree(discard)
    pending_path(ident).unlink(missing_ok=True)
def deploy(s,tls,require_probe=False):
    if require_probe and s['role']!='iran': raise ValueError('The authenticated connection test must run on Iran.')
    verified = None
    ident = valid_id(s['id']); base = ROOT/ident; stage = ROOT/('.stage-'+ident); backup = ROOT/('.backup-'+ident)
    if pending_path(ident).exists() or backup.exists(): raise RuntimeError('Recover the pending local change first.')
    validate_local_directory(base)
    validate_shared({k:s[k] for k in SHARED})
    if s['role']=='foreign' and s['cdn']: validate_origin(s)
    own = read(base/'manifest.json',{'claims':[]})
    wanted = claims(s)
    for m in all_manifests():
        if m['id']!=ident and {(p,t) for p,t,_ in wanted}&{(p,t) for p,t,_ in m['claims']}: raise RuntimeError('Port reserved by another local tunnel.')
    available(wanted,own['claims'])
    write(pending_path(ident),json.dumps({'phase':'apply'}))
    try:
        shutil.rmtree(stage,ignore_errors=True); stage.mkdir(mode=0o700)
        files = compile_spec(s,s['role'],str(base)) | tls
        for name in unit_names(s): files[service(s,name)] = unit_text(s,name)
        files['spec.json'] = json.dumps(s)
        files['manifest.json'] = json.dumps({'schema_version':2,'id':ident,'role':s['role'],'claims':wanted,'rules':firewall_rules(s),'units':[service(s,n) for n in unit_names(s)]})
        if s['role']=='foreign': files['connection.txt'] = encode_pair(s,tls.get('ca.pem',''))+'\n'
        for name,data in files.items(): write(stage/name,data)
        write(stage/'.uncommitted','true')
        if base.exists(): write(base/'.needs-restart','true')
        stop_directory(base)
        if base.exists(): base.rename(backup)
        stage.rename(base); start_directory(base)
        if require_probe: verified = probe(s,attempts=6)
    except BaseException:
        recover(ident)
        raise
    write(pending_path(ident),json.dumps({'phase':'commit'})); recover(ident)
    print('Saved on this '+s['role']+' server. UFW rules added; UFW was not enabled or reset.')
    print('Provider firewall inbound ports:',', '.join(sorted({str(p)+'/'+t for p,t,_ in firewall_rules(s)})))
    if s['role']=='foreign': print('This side is ready. Configure Iran with the connection code; tunnel traffic is not verified yet.'); show_code(s)
    elif verified is not None:
        print('Tunnel connection successful.')
        print(verified)
    else:
        if not run_connection_test(s): print('Configuration saved. Configure/check Foreign, then use test tunnel connection.')
    if s['sniffer']: print('Local sniffer: http://127.0.0.1:'+str(s['monitor']))
def validate_origin(s):
    for key in ('origin_cert','origin_key'):
        if not isinstance(s.get(key),str) or not Path(s[key]).is_absolute() or not Path(s[key]).is_file(): raise ValueError('Missing local Foreign '+key+' file.')
    cert,key = s['origin_cert'],s['origin_key']
    match = run(['openssl','x509','-in',cert,'-noout','-checkhost',s['endpoint']])
    if 'does match certificate' not in match: raise ValueError('Certificate does not cover the tunnel domain.')
    run(['openssl','x509','-in',cert,'-noout','-checkend','86400'])
    public = run(['openssl','x509','-in',cert,'-pubkey','-noout'])
    private = run(['openssl','pkey','-in',key,'-pubout','-passin','pass:'])
    if public!=private: raise ValueError('Certificate and unencrypted private key do not match.')
def tls_foreign(s,old=None):
    if simple_gost(s):
        s.pop('origin_cert',None); s.pop('origin_key',None); return {}
    if s['cdn']:
        print('Use the existing certificate and key ON THIS FOREIGN SERVER. Cloudflare must use Full (strict).')
        s['origin_cert'] = str(Path(ask('Origin certificate/fullchain PEM path on Foreign',s.get('origin_cert',''))).expanduser().absolute())
        s['origin_key'] = str(Path(ask('Origin private key PEM path on Foreign',s.get('origin_key',''))).expanduser().absolute())
        validate_origin(s); return {}
    s.pop('origin_cert',None); s.pop('origin_key',None)
    with tempfile.TemporaryDirectory() as d:
        try: ipaddress.IPv4Address(s['endpoint']); san='IP:'+s['endpoint']
        except ValueError: san='DNS:'+s['endpoint']
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','825','-subj','/CN=multi-'+s['id'],'-addext','subjectAltName='+san,'-addext','basicConstraints=critical,CA:TRUE','-keyout',d+'/key','-out',d+'/cert'])
        cert = Path(d+'/cert').read_text()
        return {'cert.pem':cert,'key.pem':Path(d+'/key').read_text(),'ca.pem':cert}
def health_key(s): return hmac.digest(bytes.fromhex(s['token']),b'multi-health-v2','sha256')
def health_request(s):
    nonce = secrets.token_bytes(32)
    return nonce+hmac.digest(health_key(s),b'request'+nonce,'sha256')
def health_reply(s,data):
    if len(data)!=64 or not hmac.compare_digest(data[32:],hmac.digest(health_key(s),b'request'+data[:32],'sha256')): return None
    return data[:32]+hmac.digest(health_key(s),b'response'+data[:32],'sha256')
def recv_exact(conn,n):
    data = b''
    while len(data)<n:
        piece = conn.recv(n-len(data))
        if not piece: break
        data += piece
    return data
def echo_service(s):
    address = '0.0.0.0' if simple_gost(s) else '127.0.0.1'
    tcp = socket.socket(); udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    tcp.bind((address,s['health_f'])); tcp.listen(32); udp.bind((address,s['health_f']))
    stamp_lock = threading.Lock()
    def seen():
        with stamp_lock: write(ROOT/s['id']/'health-seen.json',json.dumps({'at':int(time.time()),'revision':s['revision']}))
    def serve_tcp():
        while True:
            conn,_ = tcp.accept()
            with conn:
                conn.settimeout(2)
                try:
                    answer = health_reply(s,recv_exact(conn,64))
                    if answer: conn.sendall(answer); seen()
                except OSError: pass
    threading.Thread(target=serve_tcp,daemon=True).start()
    while True:
        data,addr = udp.recvfrom(1024); answer = health_reply(s,data)
        if answer: udp.sendto(answer,addr); seen()
def probe(s,attempts=1):
    last = ''
    for attempt in range(attempts):
        try:
            for proto in protocols(s):
                request = health_request(s)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM) as sock:
                    sock.settimeout(3); sock.connect(('127.0.0.1',s['health_i'])); sock.sendall(request)
                    reply = sock.recv(1024) if proto=='udp' else recv_exact(sock,64)
                expected = request[:32]+hmac.digest(health_key(s),b'response'+request[:32],'sha256')
                if not hmac.compare_digest(reply,expected): raise RuntimeError('Authenticated response mismatch.')
            write(ROOT/s['id']/'health-result.json',json.dumps({'at':int(time.time()),'revision':s['revision']}))
            return 'PASS: authenticated end-to-end '+', '.join(protocols(s))+' probe. Application services must be checked separately.'
        except (OSError,RuntimeError) as e:
            last = str(e)
            if attempt+1<attempts: time.sleep(1)
    raise RuntimeError(last or 'No response from the other server.')
def run_connection_test(s):
    if s['role']!='iran':
        status(s)
        print('A current tunnel connection cannot be verified from this menu on Foreign. Run test tunnel connection on Iran.')
        return None
    try: result = probe(s,attempts=6)
    except Exception as e:
        print('Tunnel connection unsuccessful.')
        print('Reason:',str(e))
        return False
    print('Tunnel connection successful.')
    print(result)
    return True
def show_code(s):
    print('CONFIDENTIAL CONNECTION CODE: copy to Iran; do not publish it in GitHub or logs.')
    print()
    print((ROOT/s['id']/'connection.txt').read_text().strip())
    print()
def detect_public_ipv4():
    """Return this server's observed IPv4, or a local public IPv4 as fallback."""
    def public_address(value):
        try:
            address = ipaddress.IPv4Address(value.strip())
        except (ValueError, AttributeError):
            return ''
        if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
            return ''
        return str(address)
    # Ignore HTTP proxy environment variables: the default must belong to this
    # server's outbound connection, not to a configured web proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def lookup(endpoint, found):
        try:
            request = urllib.request.Request(endpoint, headers={'User-Agent': 'multi-tunnel/2'})
            with opener.open(request, timeout=2) as response:
                if not response.geturl().startswith('https://'):
                    return
                candidate = public_address(response.read(65).decode('ascii').strip())
                if candidate:
                    found.append(candidate)
        except (OSError, ValueError, UnicodeError, urllib.error.URLError):
            pass
    for endpoint in ('https://api4.ipify.org', 'https://ipv4.icanhazip.com'):
        found = []
        # Socket timeouts do not cover every resolver implementation. A daemon
        # worker also bounds how long a stalled DNS lookup can delay the menu.
        worker = threading.Thread(target=lookup, args=(endpoint, found), daemon=True)
        worker.start()
        worker.join(timeout=2)
        if found:
            return found[0]
    # Route inspection sends no packet. Private addresses are never offered as
    # public defaults, including on VPSes with provider-managed NAT.
    try:
        routes = json.loads(run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'], timeout=0.5))
        for route in routes:
            for key in ('prefsrc', 'src'):
                candidate = public_address(route.get(key, ''))
                if candidate:
                    return candidate
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, subprocess.TimeoutExpired):
        pass
    try:
        interfaces = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'up'], timeout=0.5))
        for interface in interfaces:
            for address in interface.get('addr_info', []):
                if address.get('family') == 'inet' and address.get('scope') == 'global':
                    candidate = public_address(address.get('local', ''))
                    if candidate:
                        return candidate
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, subprocess.TimeoutExpired):
        pass
    return ''
CERT_ROOT = Path('/etc/letsencrypt/live')
def get_cert(default_domain=''):
    try:
        default_domain = host(default_domain)
        try: ipaddress.ip_address(default_domain)
        except ValueError: pass
        else: default_domain = ''
    except ValueError: default_domain = ''
    domain = host(ask('Enter your sub domain',default_domain))
    try: ipaddress.ip_address(domain)
    except ValueError: pass
    else: raise ValueError('Enter a sub domain, not an IP address.')
    print('Standalone certificate validation needs this domain to reach THIS server on TCP port 80.')
    print('Allow port 80 in the provider firewall. Cloudflare must pass /.well-known/acme-challenge/ without challenges or conflicting redirects.')
    try: available([(80,'tcp','0.0.0.0')])
    except RuntimeError as e: raise RuntimeError('TCP port 80 is busy. Free it before requesting a standalone certificate; running services were not stopped.') from e
    print('Installing Certbot...')
    try: subprocess.run(['apt-get','install','certbot','-y'],check=True,timeout=900)
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as e: raise RuntimeError('Certbot installation failed. Check the package manager output above.') from e
    allowed = set()
    for line in run(['ufw','show','added']).splitlines():
        args = shlex.split(line)
        if args[:1]==['ufw']: allowed |= rule_key(args[1:])
    if (80,'tcp','any') not in allowed:
        run(['ufw','allow','80/tcp','comment','multi-certbot'])
        print('Added UFW allow 80/tcp for certificate validation and renewal.')
    print('Requesting certificate for '+domain+'...')
    command = ['certbot','certonly','--standalone','--agree-tos','--register-unsafely-without-email','-d',domain,'--cert-name',domain]
    try: subprocess.run(command,check=True,timeout=900)
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as e: raise RuntimeError('Certificate request failed. Check the Certbot output above.') from e
    cert = CERT_ROOT/domain/'fullchain.pem'
    key = CERT_ROOT/domain/'privkey.pem'
    if not cert.is_file() or not key.is_file(): raise RuntimeError('Certbot finished, but the expected certificate files were not found. Check its reported certificate paths.')
    validate_origin({'endpoint':domain,'origin_cert':str(cert),'origin_key':str(key)})
    print('\nCertificate obtained successfully.\n'+str(cert)+'\n'+str(key)+'\n')
    return str(cert),str(key)
def build_foreign(old=None):
    s = dict(old or {})
    if not old:
        s['id'] = valid_id(ask('Tunnel name','mytunnel'))
        if (ROOT/s['id']).exists(): raise ValueError('Tunnel name already exists here.')
    s.update(schema_version=2,role='foreign',revision=secrets.token_hex(16),token=secrets.token_hex(32),sniffer=False)
    s['engine'] = choose('Tunnel engine',tuple(TRANSPORTS),s.get('engine','backhaul'))
    previous = s.get('transport','tcp'); choices = TRANSPORTS[s['engine']]
    s['transport'] = choose('Transport Type',choices,previous if previous in choices else 'tcp')
    endpoint_default = s.get('endpoint','')
    if not old:
        print('Detecting this Foreign server public IPv4...')
        endpoint_default = detect_public_ipv4()
        if not endpoint_default: print('Public IPv4 could not be detected. Enter your Foreign domain or IP manually.')
    s['endpoint'] = host(ask('enter your foriegn domain or ip',endpoint_default))
    try: ipaddress.ip_address(s['endpoint'])
    except ValueError: s['cdn'] = yes('Is this domain behind Cloudflare orange proxy',s.get('cdn',False))
    else: s['cdn'] = False
    if s['engine']!='gost': print('The Foreign endpoint uses a GOST TLS/WSS carrier. Backhaul UDP is carried over a reliable outer stream.')
    defaults = ','.join(str(p) if p==q else f'{p}:{q}' for p,q in s.get('maps',[])) or DEFAULT_PORTS
    s['maps'] = parse_maps(ask('Iran ports; comma-separated, optional IRAN:FOREIGN maps',defaults))
    s['front'] = port(ask('Foreign transport port',s.get('front',8443)))
    s['keepalive'] = int(ask('Keepalive seconds',s.get('keepalive',30)))
    s['udp_over_tcp'] = s['engine']=='backhaul' and s['transport']=='tcp' and yes('Also forward UDP over TCP',s.get('udp_over_tcp',False))
    for key,default in [('mux_con',8),('mux_version',1),('mux_stream',65536),('mux_buffer',4194304)]: s.setdefault(key,default)
    if s['engine']=='backhaul' and s['transport'] in ('tcpmux','wsmux'):
        for key,label in [('mux_con','Mux connections'),('mux_version','Mux version (1 or 2)'),('mux_stream','Mux stream buffer bytes'),('mux_buffer','Mux receive buffer bytes')]: s[key] = int(ask(label,s[key]))
    excluded = {p for pair in s['maps'] for p in pair}|{s['front']}
    for key in ('bridge','health_f'):
        if key not in s or s[key] in excluded: s[key] = free_port(excluded)
        excluded.add(s[key])
    validate_shared({k:s[k] for k in SHARED})
    return s,tls_foreign(s,old)
def prepare_iran(shared,ca,old=None,local_id=None,public_ports=None):
    s = json.loads(json.dumps(shared))
    foreign_id = valid_id(s['id'])
    if old and foreign_id!=old.get('peer_id',old['id']):
        if local_id is None: raise ValueError('The code belongs to another tunnel name.')
    s['id'] = valid_id(local_id or (old['id'] if old else foreign_id))
    if s['id']!=foreign_id: s['peer_id'] = foreign_id
    else: s.pop('peer_id',None)
    s.update(role='iran',sniffer=bool(old.get('sniffer',False)) if old and s['engine']=='backhaul' else False)
    if public_ports is not None:
        if not isinstance(public_ports,list) or len(public_ports)!=len(s['maps']): raise ValueError('Invalid Iran listening ports.')
        s['maps'] = [[integer(p,1,65535,'Iran port'),q] for p,(_,q) in zip(public_ports,s['maps'])]
    elif old and old.get('peer_id') and [q for _,q in old['maps']]==[q for _,q in s['maps']]:
        s['maps'] = [[p,q] for (p,_),(_,q) in zip(old['maps'],s['maps'])]
    validate_shared({key:s[key] for key in SHARED})
    excluded = {p for pair in s['maps'] for p in pair}|{s[k] for k in ('front','bridge','health_f')}
    owned = claims(old) if old else []
    occupied = {p for m in all_manifests() if not old or m['id']!=old['id'] for p,_,_ in m['claims']}
    for key in ('control','health_i','monitor'):
        previous = old.get(key) if old else None
        reuse = bool(previous and previous not in excluded and previous not in occupied)
        if reuse:
            try: available([(previous,'tcp','127.0.0.1'),(previous,'udp','127.0.0.1')],owned)
            except RuntimeError: reuse = False
        s[key] = previous if reuse else free_port(excluded)
        excluded.add(s[key])
    return s,{'ca.pem':ca} if ca else {}
def build_iran(old=None):
    print('First create this tunnel on Foreign, then paste its MULTI2 connection code here.')
    value = ask('Connection code, or @/path/to/connection.txt (empty = cancel)')
    if not value: return None
    if value.startswith('@'):
        with Path(value[1:]).expanduser().open() as f: value = f.read(65537).strip()
    s,ca = decode_pair(value)
    if old and s['id']!=old.get('peer_id',old['id']): raise ValueError('The code belongs to another tunnel name.')
    if not old and (ROOT/s['id']).exists(): raise ValueError('Tunnel already exists; use Edit.')
    s,tls = prepare_iran(s,ca,old)
    print('Imported:',s['id'],s['engine'],s['transport'],s['endpoint'],'ports',s['maps'],'revision',s['revision'][:8])
    if s['engine']=='backhaul': s['sniffer'] = yes('Enable local traffic sniffer',old.get('sniffer',False) if old else False)
    return s,tls
def create():
    role = choose('This server is Iran or Foreign',('iran','foreign'),'foreign')
    result = build_foreign() if role=='foreign' else build_iran()
    if result:
        deploy(*result)
        if role=='foreign' and confirm_yn('Set up the Iran side of this tunnel from this server now?'): setup_iran_from_foreign(result[0])
def status(s,logs=False):
    m = read(ROOT/s['id']/'manifest.json')
    print('Role:',s['role'],'Revision:',s['revision'][:8],'Endpoint:',s['endpoint'])
    for name in m['units']:
        args = ['journalctl','-u',name,'-n','15','--no-pager'] if logs else ['systemctl','show',name,'-p','ActiveState','-p','SubState','-p','NRestarts']
        print(name+'\n'+run(args,check=False).replace(s['token'],'[redacted]'))
    proof = read(ROOT/s['id']/('health-seen.json' if s['role']=='foreign' else 'health-result.json'))
    if proof: print('Last authenticated probe:',datetime.datetime.fromtimestamp(proof['at'],datetime.timezone.utc).isoformat(), '(historical; not a current connectivity guarantee)')
def manage():
    files = sorted(ROOT.glob('[a-z0-9]*/spec.json'))
    for i,p in enumerate(files,1):
        s = read(p); print(i,s['id'],s['role'],s['engine'],s['transport'])
    if not files: print('No local tunnels.'); return
    index = integer(int(ask('Tunnel number')),1,len(files),'Tunnel number')-1
    s = read(files[index]); ident=s['id']
    validate_local_directory(ROOT/ident)
    if pending_path(ident).exists(): raise RuntimeError('Recover this local operation first.')
    choices = ('status','test','edit','delete','restart','logs','code','cert','ssh') if s['role']=='foreign' else ('status','test','edit','delete','restart','logs','cert')
    action = choose('Local action',choices,'status')
    if action=='code': show_code(s)
    elif action=='test': run_connection_test(s)
    elif action=='cert': get_cert(s['endpoint'] if s['role']=='foreign' else '')
    elif action=='ssh': setup_iran_from_foreign(s)
    elif action=='edit':
        if s['role']=='foreign':
            print('Editing rotates the connection credentials. Re-import the new code with Edit on Iran.')
            deploy(*build_foreign(s))
        else:
            result = build_iran(s)
            if result: deploy(*result)
    elif action=='delete':
        print('This removes this server side only. Remove the other side separately.')
        if yes('Delete local tunnel '+ident,False):
            write(pending_path(ident),json.dumps({'phase':'delete'})); recover(ident); print('Local tunnel deleted.')
    elif action=='restart':
        if s['role']=='foreign' and s['cdn']: validate_origin(s)
        for name in read(ROOT/ident/'manifest.json')['units']: run(['systemctl','restart',name])
        print('Local services restarted.')
    else: status(s,logs=action=='logs')
import signal
def ensure_ssh_dependencies():
    packages = [package for command, package in (('ssh', 'openssh-client'), ('sshpass', 'sshpass')) if not shutil.which(command)]
    if not packages:
        return
    print('Installing SSH tools on this Foreign server...')
    env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    try:
        subprocess.run(['apt-get', 'update'], check=True, timeout=600, env=env)
        subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', *packages], check=True, timeout=600, env=env)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError('SSH tool installation failed. Check the package manager output above.') from None
class SSHSession:
    """One password-authenticated root connection; subsequent commands reuse its socket."""
    def __init__(self, ip, port, password):
        self.ip = str(ipaddress.IPv4Address(ip))
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            raise ValueError('SSH port must be between 1 and 65535.')
        if not isinstance(password, str) or not password or any(char in password for char in '\r\n\x00') or len(password.encode()) > 4094:
            raise ValueError('Enter a nonempty single-line root password, at most 4094 bytes.')
        self._password = password
        self._directory = None
        self._master = None
        self._socket = None
        self._connected = False
    def _redact(self, output):
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        output = str(output or '')
        if self._password:
            output = output.replace(self._password, '[REDACTED]')
        return re.sub(r'MULTI2\.[A-Za-z0-9_+/=-]+', '[REDACTED CONNECTION CODE]', output)
    def _base(self):
        return ['ssh', '-F', '/dev/null', '-4', '-T', '-p', str(self.port), '-S', self._socket,
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15',
                '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'LogLevel=ERROR']
    def __enter__(self):
        if self._directory is not None:
            raise RuntimeError('SSH session is already open.')
        ensure_ssh_dependencies()
        self._directory = tempfile.TemporaryDirectory(prefix='multi-ssh-')
        self._socket = str(Path(self._directory.name) / 'control')
        read_fd = write_fd = None
        try:
            read_fd, write_fd = os.pipe()
            os.write(write_fd, self._password.encode() + b'\n')
            os.close(write_fd)
            write_fd = None
            args = ['sshpass', '-d', str(read_fd), *self._base(), '-M', '-N',
                    '-o', 'ControlPersist=no', '-o', 'BatchMode=no', '-o', 'NumberOfPasswordPrompts=1',
                    '-o', 'PreferredAuthentications=password,keyboard-interactive',
                    '-o', 'PubkeyAuthentication=no', '-o', 'PasswordAuthentication=yes',
                    '-o', 'KbdInteractiveAuthentication=yes', 'root@' + self.ip]
            self._master = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, pass_fds=(read_fd,), start_new_session=True,
                                            env={**os.environ, 'LC_ALL': 'C'})
            os.close(read_fd)
            read_fd = None
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if self._master.poll() is not None:
                    _, error = self._master.communicate(timeout=2)
                    raise RuntimeError('SSH login failed: ' + self._redact(error).strip())
                if Path(self._socket).exists():
                    check = subprocess.run([*self._base(), '-o', 'BatchMode=yes', '-O', 'check', 'root@' + self.ip],
                                           capture_output=True, timeout=3)
                    if check.returncode == 0:
                        self._connected = True
                        return self
                time.sleep(0.1)
            raise RuntimeError('SSH login timed out. Check the IP, SSH port and root password login settings.')
        except BaseException:
            self.close()
            raise
        finally:
            if read_fd is not None:
                os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
    def run(self, argv, input_bytes=None, timeout=180):
        if not self._connected or self._master is None or self._master.poll() is not None:
            raise RuntimeError('SSH session is not connected.')
        if not isinstance(argv, (tuple, list)) or not argv or any(not isinstance(arg, str) or '\x00' in arg for arg in argv):
            raise ValueError('Remote command must be a nonempty list of strings.')
        if input_bytes is not None and not isinstance(input_bytes, bytes):
            raise ValueError('SSH input must be bytes.')
        command = [*self._base(), '-o', 'ControlMaster=no', '-o', 'BatchMode=yes',
                   '-o', 'ProxyCommand=false', 'root@' + self.ip, shlex.join(argv)]
        try:
            result = subprocess.run(command, input=input_bytes if input_bytes is not None else b'',
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.close()
            raise RuntimeError('Remote command timed out; the SSH connection was closed. Check the Iran server before retrying.') from None
        except OSError as error:
            raise RuntimeError('SSH command could not run: ' + self._redact(error)) from None
        if result.returncode:
            detail = self._redact((result.stderr or b'') + b'\n' + (result.stdout or b''))
            raise RuntimeError('Remote command failed (exit ' + str(result.returncode) + '): ' + detail.strip()[-6000:])
        return (result.stdout or b'').decode('utf-8', errors='replace')
    def upload(self, local_path, remote_path):
        path = Path(local_path)
        if not path.is_file():
            raise ValueError('Upload source must be a regular file.')
        if not isinstance(remote_path, str) or not remote_path.startswith('/') or '\x00' in remote_path or '\n' in remote_path:
            raise ValueError('Upload destination must be an absolute path.')
        # The destination directory is a private remote staging directory created by the caller.
        self.run(['sh', '-c', 'umask 077; cat > "$1"', 'multi-upload', remote_path], path.read_bytes(), timeout=600)
    def close(self):
        master = self._master
        self._connected = False
        try:
            if master is not None:
                # sshpass puts its ssh child into a separate session. Track it before stopping sshpass.
                children = []
                try:
                    child_ids = Path('/proc') / str(master.pid) / 'task' / str(master.pid) / 'children'
                    for value in child_ids.read_text().split():
                        try:
                            children.append(os.pidfd_open(int(value)))
                        except (OSError, ValueError):
                            pass
                except OSError:
                    pass
                try:
                    if self._socket and Path(self._socket).exists():
                        try:
                            subprocess.run([*self._base(), '-o', 'BatchMode=yes', '-O', 'exit', 'root@' + self.ip],
                                           capture_output=True, timeout=5)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                    if master.poll() is None:
                        for descriptor in children:
                            try:
                                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                            except OSError:
                                pass
                        master.terminate()
                    try:
                        master.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        for descriptor in children:
                            try:
                                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                            except OSError:
                                pass
                        master.kill()
                        master.communicate(timeout=5)
                finally:
                    for descriptor in children:
                        os.close(descriptor)
        finally:
            self._master = None
            if self._directory is not None:
                self._directory.cleanup()
            self._directory = None
            self._socket = None
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        self._password = ''
        return False
# Remote JSON endpoint; stdin contains the pairing code, never command-line arguments.
REMOTE_RESULT_PREFIX = 'MULTI_REMOTE_RESULT:'
REMOTE_INPUT_LIMIT = 131072
LAUNCHER = Path('/usr/local/bin/multi-tunnel')
def remote_local_state():
    if legacy_ids(): raise RuntimeError('Legacy tunnels found on Iran. Migrate them with their original manager first.')
    for pattern in ('.pending-*','.backup-*','.stage-*','.discard-*'):
        if next(ROOT.glob(pattern),None) is not None: raise RuntimeError('Iran has an interrupted local change. Use Recover on Iran before remote setup.')
    state = {}
    for base in sorted(ROOT.iterdir()):
        if base.name.startswith('.') or not base.is_dir(): continue
        valid_id(base.name)
        if base.is_symlink(): raise ValueError('Refusing a symbolic link in the Iran tunnel directory.')
        validate_local_directory(base)
        s = read(base/'spec.json')
        if s['id']!=base.name: raise ValueError('Local tunnel directory identity mismatch.')
        if (base/'.uncommitted').exists() or (base/'.needs-restart').exists(): raise RuntimeError('Iran has an interrupted local change. Use Recover on Iran first.')
        state[base.name] = s
    return state
def remote_new_id(ident, existing):
    valid_id(ident)
    for number in range(2,10000):
        suffix = '-'+str(number)
        candidate = ident[:24-len(suffix)]+suffix
        if candidate not in existing and not (ROOT/candidate).exists(): return candidate
    raise RuntimeError('No unused local tunnel name is available on Iran.')
def remote_public_ports(shared, old=None):
    own = claims(old) if old else []
    other = {(p,t) for manifest in all_manifests() if not old or manifest['id']!=old['id'] for p,t,_ in manifest['claims']}
    chosen = []
    excluded = {p for p,_ in shared['maps']} | {p for p,_ in other}
    for requested,_ in shared['maps']:
        candidate = requested
        wanted = [(candidate,t,'0.0.0.0') for t in protocols(shared)]
        try:
            if candidate in chosen or any((candidate,t) in other for t in protocols(shared)): raise RuntimeError('Port already reserved.')
            available(wanted,own)
        except RuntimeError:
            candidate = free_port(excluded | set(chosen))
        chosen.append(candidate)
        excluded.add(candidate)
    return chosen
def remote_verify_binaries(shared, directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir(): raise ValueError('Missing transferred binary directory.')
    verified = []
    for engine in ('gost',) if shared['engine']=='gost' else ('gost',shared['engine']):
        version,_,_,expected = THIRD_PARTY_RELEASES[engine]
        source = directory/(engine+'-'+version)
        if source.is_symlink() or not source.is_file(): raise RuntimeError('Transferred binary is missing: '+engine)
        with source.open('rb') as handle: data = handle.read(128*1024*1024+1)
        if len(data)>128*1024*1024 or hashlib.sha256(data).hexdigest()!=expected: raise RuntimeError('Transferred binary SHA256 mismatch: '+engine)
        verified.append((source.name,data))
    return verified
def remote_install_binaries(verified):
    directory = SCRIPT.parent/'bin'
    directory.mkdir(parents=True,exist_ok=True,mode=0o755)
    for name,data in verified:
        descriptor,temporary = tempfile.mkstemp(prefix='.'+name+'-',dir=directory)
        try:
            with os.fdopen(descriptor,'wb') as output:
                output.write(data); output.flush(); os.fsync(output.fileno()); os.fchmod(output.fileno(),0o755)
            os.replace(temporary,directory/name)
        finally: Path(temporary).unlink(missing_ok=True)
def remote_apply(request, state):
    if set(request)!={'action','code','mode','expected_revision','binary_dir'}: raise ValueError('Invalid remote apply fields.')
    if not isinstance(request['code'],str) or not isinstance(request['binary_dir'],str): raise ValueError('Invalid remote apply values.')
    mode = request['mode']
    if mode not in ('create','replace','append'): raise ValueError('Invalid remote apply mode.')
    shared,ca = decode_pair(request['code'])
    ident = shared['id']; existing = state.get(ident)
    expected = request['expected_revision']
    if expected is not None and (not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{32}',expected)): raise ValueError('Invalid expected Iran revision.')
    if (existing['revision'] if existing else None)!=expected: raise RuntimeError('Iran tunnel changed since inspection. Retry remote setup before replacing anything.')
    if mode=='create' and ((ROOT/ident).exists() or existing): raise RuntimeError('Iran tunnel name appeared after inspection. Retry remote setup.')
    if mode in ('replace','append') and not existing: raise RuntimeError('The inspected Iran tunnel no longer exists. Retry remote setup.')
    if mode=='replace' and existing['role']!='iran': raise RuntimeError('Cannot replace a Foreign-role tunnel on Iran. Choose a new local tunnel instead.')
    old = existing if mode=='replace' else None
    local_id = remote_new_id(ident,state) if mode=='append' else ident
    verified = remote_verify_binaries(shared,request['binary_dir'])
    public_ports = remote_public_ports(shared,old)
    s,tls = prepare_iran(shared,ca,old=old,local_id=local_id,public_ports=public_ports)
    ensure_dependencies()
    remote_install_binaries(verified)
    if Path(__file__).resolve()!=SCRIPT.resolve(): write(SCRIPT,Path(__file__).read_text())
    write(LAUNCHER,'#!/bin/sh\nexec /usr/bin/python3 '+shlex.quote(str(SCRIPT))+' "$@"\n')
    LAUNCHER.chmod(0o755)
    deploy(s,tls,require_probe=True)
    return {'ok':True,'id':s['id'],'maps':s['maps'],'connection_ok':True}
def remote_dispatch(request):
    if os.geteuid()!=0: raise RuntimeError('Remote setup requires root on Iran.')
    if not isinstance(request,dict): raise ValueError('Remote input must be a JSON object.')
    if request.get('action') not in ('inspect','apply'): raise ValueError('Unknown remote action.')
    if request['action']=='inspect':
        if set(request)!={'action','id'}: raise ValueError('Invalid remote inspect fields.')
        valid_id(request['id'])
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'.local-v2.lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as error: raise RuntimeError('Another Multi operation is running on Iran. Try again after it finishes.') from error
        state = remote_local_state()
        if request['action']=='apply': return remote_apply(request,state)
        existing = state.get(request['id'])
        return {'ok':True,'existing':existing is not None,'existing_revision':existing['revision'] if existing else None,'existing_role':existing['role'] if existing else None,'ids':sorted(state)}
def remote_main():
    request = None
    try:
        value = sys.stdin.read(REMOTE_INPUT_LIMIT+1)
        if len(value)>REMOTE_INPUT_LIMIT: raise ValueError('Remote input exceeds the size limit.')
        request = json.loads(value)
        result = remote_dispatch(request)
    except (Exception,KeyboardInterrupt) as error:
        message = str(error) or 'Remote setup interrupted.'
        if isinstance(request,dict) and isinstance(request.get('code'),str):
            code = request['code']; message = message.replace(code,'[redacted]')
            try:
                token = json.loads(base64.b64decode(code[7:],altchars=b'-_',validate=True))['spec']['token']
                if isinstance(token,str) and token: message = message.replace(token,'[redacted]')
            except (ValueError,KeyError,TypeError,UnicodeError,binascii.Error): pass
        message = re.sub(r'MULTI2\.[A-Za-z0-9_=-]+','[redacted]',message)
        result = {'ok':False,'error':message[-1500:]}
    print(REMOTE_RESULT_PREFIX+json.dumps(result,separators=(',',':')),flush=True)
    return 0 if result['ok'] else 1
REMOTE_BOOTSTRAP = r'''set -eu
test "$(id -u)" = 0 || { echo 'SSH must log in as root on Iran.' >&2; exit 1; }
. /etc/os-release
test "$ID" = ubuntu && dpkg --compare-versions "$VERSION_ID" ge 22.04 || { echo 'Iran must run Ubuntu 22.04 or newer.' >&2; exit 1; }
test "$(uname -m)" = x86_64 || { echo 'Iran must use the amd64 architecture.' >&2; exit 1; }
test -d /run/systemd/system || { echo 'Iran must use systemd as its service manager.' >&2; exit 1; }
missing=0
for package in python3 openssl ufw iproute2 ca-certificates iptables; do
  installed=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)
  test "$installed" = installed || missing=1
done
if test "$missing" = 1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends python3 openssl ufw iproute2 ca-certificates iptables
fi
'''
def remote_request(session,script,request,timeout=180):
    command = shlex.join(['/usr/bin/python3',script,'remote'])+' || [ "$?" -eq 1 ]'
    output = session.run(['sh','-c',command],input_bytes=json.dumps(request,separators=(',',':')).encode(),timeout=timeout)
    lines = output.splitlines()
    if not lines or not lines[-1].startswith(REMOTE_RESULT_PREFIX): raise RuntimeError('Iran did not return a complete setup result. Check its tunnel status before retrying.')
    try: result = json.loads(lines[-1][len(REMOTE_RESULT_PREFIX):])
    except ValueError: raise RuntimeError('Invalid setup response from Iran.') from None
    if not isinstance(result,dict) or result.get('ok') is not True:
        message = result.get('error','Remote operation failed.') if isinstance(result,dict) else 'Invalid remote result.'
        raise RuntimeError(str(message))
    return result
def ask_iran_address():
    while True:
        value = ask('Iran server IPv4')
        try:
            address = ipaddress.IPv4Address(value)
            if address.is_unspecified or address.is_multicast: raise ValueError()
            return str(address)
        except ValueError: print('Enter a valid Iran server IPv4 address.')
def ask_ssh_port():
    while True:
        try: return port(ask('Iran SSH port',22))
        except ValueError: print('Enter a port number from 1 to 65535.')
def ask_ssh_password():
    while True:
        print()
        try: password = getpass.getpass('Iran root SSH password: ')
        finally: print()
        if password and not any(c in password for c in '\n\r\x00') and len(password.encode())<=4094: return password
        print('Enter a nonempty SSH password without line breaks.')
def setup_iran_from_foreign(s):
    if s['role']!='foreign': raise ValueError('Start SSH setup from the Foreign server.')
    validate_local_directory(ROOT/s['id'])
    code = (ROOT/s['id']/'connection.txt').read_text().strip()
    paired,_ = decode_pair(code)
    if {k:s[k] for k in SHARED}!=paired: raise ValueError('The saved connection code does not match this Foreign tunnel.')
    address = ask_iran_address()
    ssh_port = ask_ssh_port()
    password = ask_ssh_password()
    try:
        ensure_ssh_dependencies()
        print('Connecting to Iran as root...')
        with SSHSession(address,ssh_port,password) as session:
            password = ''
            print('Checking and installing Ubuntu prerequisites on Iran...')
            session.run(['sh','-c',REMOTE_BOOTSTRAP],timeout=1500)
            stage = session.run(['mktemp','-d','/root/.multi-setup.XXXXXXXX']).strip()
            if not re.fullmatch(r'/root/\.multi-setup\.[A-Za-z0-9]{8}',stage): raise RuntimeError('Iran returned an unexpected staging directory.')
            try:
                remote_script = stage+'/multi-tunnel.py'
                local_script = Path(__file__).resolve()
                script_sha = hashlib.sha256(local_script.read_bytes()).hexdigest()
                session.upload(local_script,remote_script)
                transferred = session.run(['sha256sum','--',remote_script]).split()
                if not transferred or transferred[0]!=script_sha: raise RuntimeError('Transferred manager SHA256 mismatch.')
                state = remote_request(session,remote_script,{'action':'inspect','id':s['id']})
                if type(state.get('existing')) is not bool: raise RuntimeError('Invalid tunnel inventory from Iran.')
                mode = 'create'
                if state['existing']:
                    replace = confirm_yn('Iran already has a tunnel named '+s['id']+'. Replace that tunnel?')
                    mode = 'replace' if replace else 'append'
                    if replace and state.get('existing_role')!='iran': raise RuntimeError('That existing tunnel has the Foreign role. Choose n to add a separate Iran tunnel.')
                print('Preparing and sending tunnel engine files to Iran...')
                session.run(['mkdir','-m','700',stage+'/bin'])
                engines = ('gost',) if s['engine']=='gost' else ('gost',s['engine'])
                for engine in engines:
                    binary = Path(install_binary(engine))
                    version,_,_,expected = THIRD_PARTY_RELEASES[engine]
                    if hashlib.sha256(binary.read_bytes()).hexdigest()!=expected: raise RuntimeError('Local executable SHA256 mismatch: '+engine)
                    session.upload(binary,stage+'/bin/'+engine+'-'+version)
                print('Creating the Iran tunnel and testing the connection...')
                result = remote_request(session,remote_script,{'action':'apply','code':code,'mode':mode,'expected_revision':state.get('existing_revision'),'binary_dir':stage+'/bin'},timeout=1200)
                if result.get('connection_ok') is not True: raise RuntimeError('Iran has not verified a successful tunnel connection.')
                print('\nIran tunnel name: '+valid_id(result['id']))
                print('Iran listening port -> Foreign service port')
                for public,target in result['maps']: print(str(port(public))+' -> '+str(port(target)))
                if result['maps']!=s['maps']: print('Busy Iran ports were replaced with free ports. Use the Iran listening ports shown above.')
                print('Tunnel connection successful. Application services must be checked separately.\n')
                return result
            finally:
                try: session.run(['rm','-rf','--',stage],timeout=30)
                except Exception: print('The SSH staging directory could not be removed from Iran: '+stage)
    except Exception as error:
        message = str(error).replace(code,'[redacted]').replace(s['token'],'[redacted]')
        if password: message = message.replace(password,'[redacted]')
        print('Iran setup was not completed: '+message)
        print('The Foreign tunnel is saved. Check Iran status, then use Set up Iran via SSH in tunnel management to retry.')
        return None
    finally: password = ''
def main():
    if len(sys.argv)>1 and sys.argv[1]=='remote': sys.exit(remote_main())
    if len(sys.argv)>1 and sys.argv[1] in ('echo','guard-on','guard-off'):
        s = read(sys.argv[2])
        if s.get('schema_version')!=2: raise ValueError('Unsupported local configuration.')
        if sys.argv[1]=='echo': echo_service(s)
        else: monitor_guard(s,sys.argv[1]=='guard-on')
        return
    if len(sys.argv)>1:
        if sys.argv[1] in ('--version','--help','-h'): print('Multi Tunnel '+VERSION+'\nRun: sudo python3 multi-tunnel.py\nCreate on Foreign first; use automatic Iran setup via SSH or import the connection code on Iran.'); return
        raise ValueError('Unknown argument.')
    if os.geteuid()!=0: raise RuntimeError('Run: sudo python3 multi-tunnel.py')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if legacy_ids(): raise RuntimeError('Legacy SSH-managed tunnels found: '+', '.join(legacy_ids())+'. Use the previous script to remove/migrate them before installing v2.')
    ensure_dependencies()
    with (ROOT/'.local-v2.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if Path(__file__).resolve()!=SCRIPT: write(SCRIPT,Path(__file__).read_text())
        while True:
            try:
                print('\nMULTI TUNNEL '+VERSION+'\n1) Create tunnel\n2) Manage local tunnels\n3) Recover interrupted local change\n4) get cert for sub domain\n0) Exit')
                choice = ask('Select','0')
                if choice=='0': return
                if choice=='1': create()
                elif choice=='2': manage()
                elif choice=='3':
                    files = sorted(ROOT.glob('.pending-*.json'))
                    for i,p in enumerate(files,1): print(i,p.name)
                    if files:
                        index=integer(int(ask('Number')),1,len(files),'Number')-1
                        recover(files[index].name[len('.pending-'):-len('.json')]); print('Local recovery finished.')
                elif choice=='4': get_cert()
                else: raise ValueError('Invalid selection. Enter an option number.')
            except EOFError: return
            except (Exception,KeyboardInterrupt) as e: print('ERROR:',str(e) or 'Interrupted. Use Recover if needed.')
if __name__=='__main__':
    try: main()
    except (Exception,KeyboardInterrupt) as e: print('ERROR:',str(e),file=sys.stderr); sys.exit(1)
