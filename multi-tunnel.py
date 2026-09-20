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
    run_interactive(["apt-get", "update"], timeout=600, env=env)
    run_interactive(["apt-get", "-o", "DPkg::Lock::Timeout=300", "install", "-y", "--no-install-recommends", *packages], timeout=900, env=env)
def format_bytes(value):
    value = max(0, float(value))
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if value < 1024 or unit == 'GiB': return f'{value:.1f} {unit}'
        value /= 1024
class Progress:
    """Progress is capped below 100 until the caller acknowledges success."""
    def __init__(self, label, total=None):
        self.label = label
        self.total = total if isinstance(total, (int, float)) and total > 0 else None
        self.done = 0
        self.stream = sys.stderr
        self.tty = self.stream.isatty()
        self.last_time = 0
        self.last_bucket = -1
        self.closed = False
        self.width = 0
        self.override = None
    def _render(self, ending=None):
        if self.closed: return
        now = time.monotonic()
        pct = self.override if self.override is not None else (self.done * 100 / self.total if self.total else None)
        pct = min(99, max(0, pct)) if pct is not None else None
        if ending == 'done': pct = 100
        bucket = int(pct // 5) if pct is not None else -1
        if ending is None and self.last_time:
            if self.tty and now - self.last_time < 0.15: return
            if not self.tty and bucket == self.last_bucket and now - self.last_time < 10: return
        fill = int(pct / 5) if pct is not None else 0
        bar = '[' + '#' * fill + '-' * (20 - fill) + ']'
        amount = ''
        if self.total: amount = f'  {format_bytes(self.done)} / {format_bytes(self.total)}'
        elif self.done: amount = '  ' + format_bytes(self.done)
        percent = f'{pct:5.1f}%' if pct is not None else '  --%'
        line = f'{self.label} {bar} {percent}{amount}'
        if ending: line += '  ' + ending
        self.stream.write(('\r' if self.tty else '') + line + (' ' * max(0, self.width-len(line)) if self.tty else '') + ('\n' if ending or not self.tty else ''))
        self.stream.flush()
        self.width = len(line)
        self.last_time, self.last_bucket = now, bucket
        self.closed = ending is not None
    def update(self, done):
        self.done = max(0, done)
        self._render()
    def percent(self, value):
        self.override = min(100, max(0, float(value)))
        self._render()
    def finish(self):
        if self.total: self.done = self.total
        self._render('done')
    def fail(self): self._render('stopped')
class AptProgress:
    def __init__(self, label): self.progress = Progress(label)
    def feed(self, line):
        # APT emits both acquisition and dpkg status records on Status-Fd.
        match = re.match(r'^dlstatus:[^:]*:([0-9.]+):', line)
        if not match: match = re.match(r'^pmstatus:.*?:([0-9.]+):', line)
        if match:
            try: self.progress.percent(float(match[1]))
            except ValueError: pass
        elif line.startswith(('E:', 'W:', 'Err:', 'pmerror:', 'pmconffile:')):
            print('\n' + line, file=sys.stderr, flush=True)
        else: self.progress._render()
    def finish(self): self.progress.finish()
    def fail(self): self.progress.fail()
def _release_download(url, label='Downloading file'):
    request = urllib.request.Request(url, headers={"User-Agent": "multi-tunnel/2.3"})
    for attempt in range(3):
        progress = None
        try:
            with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=45) as response:
                if not response.geturl().startswith("https://"):
                    raise RuntimeError("Refusing an insecure download redirect")
                header = response.headers.get('Content-Length', '')
                total = int(header) if header.isdigit() else None
                if total and total > 128 * 1024 * 1024: raise RuntimeError('Release archive exceeds size limit')
                progress = Progress(label + (f' (retry {attempt})' if attempt else ''), total)
                data = bytearray()
                progress.update(0)
                while True:
                    chunk = response.read(65536)
                    if not chunk: break
                    data.extend(chunk)
                    if len(data) > 128 * 1024 * 1024: raise RuntimeError('Release archive exceeds size limit')
                    progress.update(len(data))
                if total is not None and len(data) != total: raise RuntimeError('Incomplete download; received size differs from Content-Length')
                progress.finish()
                return bytes(data)
        except urllib.error.HTTPError as error:
            if attempt == 2 or error.code not in {408, 429, 500, 502, 503, 504}:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        finally:
            if progress is not None and not progress.closed: progress.fail()
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
    directory = SCRIPT.parent / 'bin'
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination = directory / f"{engine}-{version}"
    if destination.is_file() and not destination.is_symlink():
        if hashlib.sha256(destination.read_bytes()).hexdigest() == executable_sha:
            destination.chmod(0o755)
            return str(destination)
    archive = _release_download(url, 'Downloading ' + engine.upper())
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
def native_reverse(s):
    """Schema 2 keeps its original GOST carrier; schema 3 uses the selected core."""
    return s.get('schema_version') == 3 and s['engine'] in ('backhaul', 'rathole')
def control_protocols(s):
    return ('tcp', 'udp') if s['engine'] == 'backhaul' and s['transport'] == 'udp' else ('tcp',)
def required_engines(s, role='iran'):
    if s['engine'] == 'gost':
        return () if role == 'foreign' and simple_gost(s) else ('gost',)
    return (s['engine'],) if native_reverse(s) else ('gost', s['engine'])
def engine_path(engine):
    return SCRIPT.parent / 'bin' / (engine + '-' + THIRD_PARTY_RELEASES[engine][0])
def valid_cached_binary(engine):
    path = engine_path(engine)
    if path.is_symlink() or not path.is_file(): return False
    try:
        if path.stat().st_size > 128 * 1024 * 1024: return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == THIRD_PARTY_RELEASES[engine][3]
    except OSError: return False
def binary_inventory(engines):
    return {engine: {'version': THIRD_PARTY_RELEASES[engine][0], 'valid': valid_cached_binary(engine)} for engine in engines}
def compile_backhaul(s,role,base):
    transport=s['transport']
    d={'transport':transport,'token':s['token'],'keepalive_period':int(s['keepalive']),'nodelay':True,'sniffer':bool(s['sniffer'] and role=='iran'),'web_port':int(s.get('monitor',0)) if s['sniffer'] and role=='iran' else 0,'sniffer_log':base+'/usage.json','log_level':'info','skip_optz':True}
    if transport in ('tcpmux','wsmux'):
        d.update(mux_version=int(s['mux_version']),mux_framesize=32768,mux_recievebuffer=int(s['mux_buffer']),mux_streambuffer=int(s['mux_stream']))
    if role=='iran':
        section='server'
        bind = '0.0.0.0:'+str(s['front']) if native_reverse(s) else '127.0.0.1:'+str(s['control'])
        d.update(bind_addr=bind,heartbeat=int(s.get('heartbeat',20)),channel_size=2048,ports=[str(p)+'=127.0.0.1:'+str(q) for p,q in s['maps']]+['127.0.0.1:'+str(s['health_i'])+'=127.0.0.1:'+str(s['health_f'])])
        if transport=='tcp': d['accept_udp']=bool(s.get('udp_over_tcp',False))
        if transport in ('tcpmux','wsmux'): d['mux_con']=int(s['mux_con'])
    else:
        section='client'
        remote = _gost_addr(s['endpoint'],s['front']) if native_reverse(s) else '127.0.0.1:'+str(s['bridge'])
        d.update(remote_addr=remote,connection_pool=int(s.get('pool',8)),retry_interval=3,dial_timeout=10,aggressive_pool=False)
    return '['+section+']\n'+'\n'.join(k+' = '+json.dumps(v) for k,v in d.items())+'\n'
def compile_rathole(s, role, base):
    side = 'server' if role == 'iran' else 'client'
    lines = [f'[{side}]']
    remote = _gost_addr(s['endpoint'],s['front']) if native_reverse(s) else '127.0.0.1:'+str(s['bridge'])
    if side == 'server':
        bind = '0.0.0.0:'+str(s['front']) if native_reverse(s) else '127.0.0.1:'+str(s['control'])
        lines.append('bind_addr = '+json.dumps(bind))
    else:
        lines.append('remote_addr = '+json.dumps(remote))
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
        if native_reverse(s):
            files['engine.toml'] = compile_backhaul(s, role, base) if engine == 'backhaul' else compile_rathole(s, role, base)
            return files
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
import contextlib
VERSION = '3.1.0'
ROOT = Path('/etc/multi-tunnel')
SCRIPT = Path('/usr/local/lib/multi-tunnel/multi-tunnel.py')
UNITS = Path('/etc/systemd/system')
DEFAULT_PORTS = '443,2083,2053,1115,1117'
TRANSPORTS = {'backhaul':('tcp','udp','ws','wsmux','tcpmux'),'rathole':('tcp','ws'),'gost':('tcp','udp','ws','grpc','tcpmux')}
SHARED = ('schema_version','id','revision','engine','transport','endpoint','cdn','maps','front','bridge','health_f','token','keepalive','udp_over_tcp','mux_con','mux_version','mux_stream','mux_buffer')
@contextlib.contextmanager
def ignore_interrupts():
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): previous[sig] = signal.signal(sig, signal.SIG_IGN)
    try: yield
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)
def run(args, check=True, timeout=180):
    p = subprocess.Popen([str(x) for x in args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try: stdout, stderr = p.communicate(timeout=timeout)
    except BaseException:
        cancel_process_group(p)
        raise
    if check and p.returncode: raise RuntimeError((stderr or stdout or 'Command failed')[-1500:])
    return stdout.strip()
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
    if type(s['schema_version'])!=int or s['schema_version'] not in (2,3): raise ValueError('Unsupported pairing version. Update the manager on both servers.')
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
    bound = {s['health_f']} if native_reverse(s) else {s['health_f']} | ({s['front']} if not simple_gost(s) else set()) | ({s['bridge']} if s['engine']!='gost' else set())
    if bound & {q for _,q in maps}: raise ValueError('Foreign service/transport port collision.')
    if native_reverse(s) and s['front'] in {p for p,_ in maps}: raise ValueError('Iran control port conflicts with an Iran user port.')
    if native_reverse(s) and s['cdn']: raise ValueError('Native reverse tunnels connect to Iran directly. Use a directly reachable Iran address; the Foreign Cloudflare proxy is not on this path.')
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
    return 'MULTI'+str(s['schema_version'])+'.'+base64.urlsafe_b64encode(payload).decode()
def decode_pair(value):
    if not value.startswith(('MULTI2.','MULTI3.')) or len(value)>65536: raise ValueError('Invalid connection code.')
    try:
        payload = base64.b64decode(value[7:],altchars=b'-_',validate=True)
        data = json.loads(payload)
    except (ValueError,UnicodeError,binascii.Error) as e: raise ValueError('Invalid connection code encoding.') from e
    if not isinstance(data,dict) or set(data)!= {'spec','ca'}: raise ValueError('Invalid connection envelope.')
    s = validate_shared(data['spec'])
    if int(value[5]) != s['schema_version']: raise ValueError('Connection code version mismatch.')
    ca = data['ca']
    if not isinstance(ca,str) or len(ca)>16384: raise ValueError('Invalid public certificate.')
    if not simple_gost(s) and not native_reverse(s) and not s['cdn']:
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
    labels = {'iran':'Iran','foreign':'Foreign','gost':'GOST','backhaul':'Backhaul','rathole':'Rathole','tcp':'TCP','udp':'UDP','ws':'WS','grpc':'gRPC','tcpmux':'TCPMux','wsmux':'WSMux','y':'Yes','n':'No','status':'Status','test':'test tunnel connection','edit':'Edit','delete':'Delete this tunnel','restart':'Restart','logs':'Logs','code':'Show connection code','cert':'get cert for sub domain','ssh':'Set up Iran via SSH'}
    labels.update({'automatic':'Automatic', 'manual':'Manual'})
    print()
    for number, option in enumerate(options,1): print(str(number)+') '+labels.get(option,option))
    value = ask(label,options.index(default)+1)
    try: number = int(value)
    except ValueError: raise ValueError('Invalid selection. Enter an option number.') from None
    if not 1<=number<=len(options): raise ValueError('Invalid selection. Enter an option number.')
    return options[number-1]
def yes(label, default=False): return choose(label,('y','n'),'y' if default else 'n')=='y'
class MenuExit(KeyboardInterrupt): pass
def menu_input(label, default=''):
    try: return ask(label, default)
    except (EOFError,KeyboardInterrupt): raise MenuExit from None
def menu_choose(label, options, default):
    try: return choose(label, options, default)
    except (EOFError,KeyboardInterrupt): raise MenuExit from None
def confirm_yn(label):
    while True:
        value = ask(label+' (y/n)')
        if value in ('y','n'): return value=='y'
        print('Please enter y or n.')
def confirm_yn_default(label, default='y'):
    if default not in ('y','n'): raise ValueError('Invalid confirmation default.')
    while True:
        value = ask(label+' (y/n)', default)
        if value in ('y','n'): return value=='y'
        print('Please enter y or n.')
def all_manifests():
    return [read(p) for p in ROOT.glob('[a-z0-9]*/manifest.json') if read(p,{}).get('schema_version') in (2,3)]
def legacy_ids():
    return [p.parent.name for p in ROOT.glob('[a-z0-9]*/spec.json') if read(p,{}).get('schema_version') not in (2,3)]
def protocols(s):
    if s['udp_over_tcp']: return ('tcp','udp')
    return ('udp',) if s['transport']=='udp' else ('tcp',)
def claims(s):
    if s['role']=='iran':
        out = [(p,t,'0.0.0.0') for p,_ in s['maps'] for t in protocols(s)]
        out += [(s['health_i'],t,'127.0.0.1') for t in protocols(s)]
        if s['engine']!='gost':
            out += [(s['front'] if native_reverse(s) else s['control'],t,'0.0.0.0' if native_reverse(s) else '127.0.0.1') for t in control_protocols(s)]
        if s['sniffer']: out += [(s['monitor'],'tcp','0.0.0.0')]
        return out
    out = [(s['health_f'],t,'0.0.0.0' if simple_gost(s) else '127.0.0.1') for t in ('tcp','udp')]
    if not simple_gost(s) and not native_reverse(s): out += [(s['front'],'tcp','0.0.0.0')]
    if s['engine']!='gost' and not native_reverse(s):
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
    if s['role']=='iran':
        return [[p,t,'any'] for p,_ in s['maps'] for t in protocols(s)] + ([[s['front'],t,'any'] for t in control_protocols(s)] if native_reverse(s) else [])
    if native_reverse(s): return []
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
    names = list(required_engines(s,s['role']))
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
        cmd = f'{binary} -C {base}/gost.json' if name=='gost' else f'{binary} -c {base}/engine.toml' if name=='backhaul' else f'{binary} '+('-s' if s['role']=='iran' else '-c')+f' {base}/engine.toml'
    guard = ''
    if name=='backhaul' and s['role']=='iran' and s['sniffer']: guard = f'ExecStartPre=/usr/bin/python3 {SCRIPT} guard-on {base}/spec.json\nExecStopPost=/usr/bin/python3 {SCRIPT} guard-off {base}/spec.json\n'
    return f'[Unit]\nDescription=Multi Tunnel {s["id"]} {name}\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=0\n[Service]\nType=simple\n{guard}ExecStart={cmd}\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=read-only\nProtectSystem=full\nReadWritePaths={base}\n[Install]\nWantedBy=multi-user.target\n'
def validate_local_directory(base):
    if not base.exists(): return
    s,m = read(base/'spec.json'),read(base/'manifest.json')
    if not isinstance(s,dict) or not isinstance(m,dict) or m.get('schema_version') not in (2,3): raise ValueError('Missing or incompatible local manifest: '+base.name)
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
    with ignore_interrupts(): return _recover(ident)
def _recover(ident):
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
        files['manifest.json'] = json.dumps({'schema_version':s['schema_version'],'id':ident,'role':s['role'],'claims':wanted,'rules':firewall_rules(s),'units':[service(s,n) for n in unit_names(s)]})
        if s['role']=='foreign': files['connection.txt'] = encode_pair(s,tls.get('ca.pem',''))+'\n'
        for name,data in files.items(): write(stage/name,data)
        write(stage/'.uncommitted','true')
        if base.exists(): write(base/'.needs-restart','true')
        stop_directory(base)
        if base.exists(): base.rename(backup)
        stage.rename(base); start_directory(base)
        if require_probe: verified = probe(s,attempts=60,budget=60)
    except BaseException:
        recover(ident)
        raise
    write(pending_path(ident),json.dumps({'phase':'commit'})); recover(ident)
    print('Saved on this '+s['role']+' server. UFW rules added; UFW was not enabled or reset.')
    print('Provider firewall inbound ports:',', '.join(sorted({str(p)+'/'+t for p,t,_ in firewall_rules(s)})) or 'None required for this tunnel on Foreign (outbound connection to Iran).')
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
    if simple_gost(s) or native_reverse(s):
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
def probe(s,attempts=1,budget=20):
    last = ''
    deadline = time.monotonic()+budget
    for attempt in range(attempts):
        try:
            for proto in protocols(s):
                request = health_request(s)
                target = '127.0.0.1:'+str(s['health_i'])
                stage = 'local health listener'
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise TimeoutError('Health-test deadline reached')
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM) as sock:
                    sock.settimeout(min(3,remaining)); sock.connect(('127.0.0.1',s['health_i'])); sock.sendall(request)
                    stage = 'authenticated end-to-end reply'
                    reply = sock.recv(1024) if proto=='udp' else recv_exact(sock,64)
                expected = request[:32]+hmac.digest(health_key(s),b'response'+request[:32],'sha256')
                if not hmac.compare_digest(reply,expected): raise RuntimeError('Authenticated response mismatch.')
            write(ROOT/s['id']/'health-result.json',json.dumps({'at':int(time.time()),'revision':s['revision']}))
            return 'PASS: authenticated end-to-end '+', '.join(protocols(s))+' probe. Application services must be checked separately.'
        except (OSError,RuntimeError) as e:
            last = proto.upper()+' '+target+' | '+stage+': '+str(e)
            remaining = deadline-time.monotonic()
            if remaining <= 0: break
            if attempt+1<attempts: time.sleep(min(1,remaining))
    raise RuntimeError(last or 'No response from the other server.')
def transport_diagnostic(s):
    if simple_gost(s): return 'GOST forwards directly to the Foreign service ports; check each service separately.'
    address = _gost_addr(s['endpoint'],s['front'])
    direction = 'Foreign -> Iran' if native_reverse(s) else 'Iran -> Foreign'
    if native_reverse(s) and s['role']=='iran':
        return 'Control endpoint: '+address+' ('+direction+'). Check the Foreign client logs and inbound Iran firewall for '+str(s['front'])+'.'
    if not native_reverse(s) and s['role']=='foreign': return 'Control endpoint: '+address+' ('+direction+'). Run the TCP reachability check on Iran.'
    try:
        with socket.create_connection((s['endpoint'],s['front']),timeout=3): pass
        return 'TCP to '+address+' is reachable. Check authentication, transport settings and the peer service.'
    except OSError as error:
        return 'TCP to '+address+' failed ('+direction+'): '+str(error)
def run_connection_test(s):
    if s['role']!='iran':
        status(s)
        print('A current tunnel connection cannot be verified from this menu on Foreign. Run test tunnel connection on Iran.')
        return None
    print('Testing the authenticated tunnel path (up to 30 seconds)...',flush=True)
    try: result = probe(s,attempts=30,budget=30)
    except Exception as e:
        print('Tunnel connection unsuccessful.')
        print('Reason:',str(e))
        print(transport_diagnostic(s))
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
def get_cert(default_domain='', *, interactive=True):
    try:
        default_domain = host(default_domain)
        try: ipaddress.ip_address(default_domain)
        except ValueError: pass
        else: default_domain = ''
    except ValueError: default_domain = ''
    domain = host(ask('Enter your sub domain',default_domain) if interactive else default_domain)
    try: ipaddress.ip_address(domain)
    except ValueError: pass
    else: raise ValueError('Enter a sub domain, not an IP address.')
    print('Standalone certificate validation needs this domain to reach THIS server on TCP port 80.')
    print('Allow port 80 in the provider firewall. Cloudflare must pass /.well-known/acme-challenge/ without challenges or conflicting redirects.')
    try: available([(80,'tcp','0.0.0.0')])
    except RuntimeError as e: raise RuntimeError('TCP port 80 is busy. Free it before requesting a standalone certificate; running services were not stopped.') from e
    print('Installing Certbot...')
    try:
        if interactive: run_interactive(['apt-get','-o','DPkg::Lock::Timeout=300','install','certbot','-y'],check=True,timeout=1200)
        else:
            env = {**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'}
            run_interactive(['apt-get','update'],check=True,timeout=900,env=env)
            run_interactive(['apt-get','-o','DPkg::Lock::Timeout=300','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold','install','certbot','-y'],check=True,timeout=1200,env=env)
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
    if not interactive: command += ['--non-interactive','--force-renewal']
    try: run_interactive(command,check=True,timeout=900)
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
    s.update(schema_version=old.get('schema_version',2) if old else 3,role='foreign',revision=secrets.token_hex(16),token=secrets.token_hex(32),sniffer=False)
    s['engine'] = choose('Tunnel engine',tuple(TRANSPORTS),s.get('engine','backhaul'))
    if old and s['engine']!=old['engine']: s['schema_version'] = 3
    previous = s.get('transport','tcp')
    endpoint_default = s.get('endpoint','')
    if old and native_reverse(s)!=native_reverse(old): endpoint_default = ''
    if native_reverse(s):
        s['endpoint'] = host(ask('Iran public IPv4 or direct DNS name',endpoint_default))
        s['cdn'] = False
        print('Native '+s['engine'].capitalize()+': Foreign connects to Iran. Only the selected engine is required.')
        print('TCP/UDP/WS here are native transports without the old GOST TLS layer. Use encrypted application traffic.')
    elif not old:
        print('Detecting this Foreign server public IPv4...')
        endpoint_default = detect_public_ipv4()
        if not endpoint_default: print('Public IPv4 could not be detected. Enter your Foreign domain or IP manually.')
    if not native_reverse(s):
        s['endpoint'] = host(ask('Enter your Foreign domain or IP',endpoint_default))
        try: ipaddress.ip_address(s['endpoint'])
        except ValueError: s['cdn'] = yes('Is this domain behind Cloudflare orange proxy',True)
        else: s['cdn'] = False
    s['transport'],s['endpoint'],s['cdn'] = choose_transport(s['engine'],s['endpoint'],s['cdn'],previous,endpoint_default)
    if s['engine']!='gost' and not native_reverse(s): print('Existing schema-2 tunnel: keeping its GOST TLS/WSS carrier. Create a new tunnel to use a native engine.')
    if s['engine']=='backhaul' and s['cdn']: print('Backhaul TCP/WS is the inner transport; the Cloudflare connection uses WSS in either case. TCP is the default inner transport.')
    defaults = ','.join(str(p) if p==q else f'{p}:{q}' for p,q in s.get('maps',[])) or DEFAULT_PORTS
    s['maps'] = parse_maps(ask('Iran ports; comma-separated, optional IRAN:FOREIGN maps',defaults))
    front_default = s.get('front',8443)
    if s['cdn'] and front_default not in (443,2053,2083,2087,2096,8443): front_default = 8443
    s['front'] = port(ask('Iran control port' if native_reverse(s) else 'Foreign transport port',front_default))
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
    elif old:
        s['maps'] = preserve_public_maps(s['maps'],old['maps'])
    validate_shared({key:s[key] for key in SHARED})
    excluded = {p for pair in s['maps'] for p in pair}|{s[k] for k in ('front','bridge','health_f')}
    owned = claims(old) if old else []
    occupied = {p for m in all_manifests() if not old or m['id']!=old['id'] for p,_,_ in m['claims']}
    for key in ('control','health_i','monitor'):
        if key=='control' and native_reverse(s):
            s[key] = s['front']
            continue
        previous = old.get(key) if old else None
        reuse = bool(previous and previous not in excluded and previous not in occupied)
        if reuse:
            try: available([(previous,'tcp','127.0.0.1'),(previous,'udp','127.0.0.1')],owned)
            except RuntimeError: reuse = False
        s[key] = previous if reuse else free_port(excluded)
        excluded.add(s[key])
    return s,{'ca.pem':ca} if ca else {}
def build_iran(old=None):
    print('First create this tunnel on Foreign, then paste its MULTI2 or MULTI3 connection code here.')
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
def ask_automatic_settings():
    print('\nAutomatic mode uses the default tunnel settings and configures both servers.\n')
    while True:
        try:
            engine = choose('Tunnel engine',tuple(TRANSPORTS),'backhaul')
            break
        except ValueError as error: print(str(error))
    iran_ip = ask_iran_address()
    endpoint_default = ''
    if engine=='gost':
        print('Detecting this Foreign server public IPv4...')
        endpoint_default = detect_public_ipv4()
        if not endpoint_default: print('Public IPv4 could not be detected. Enter your Foreign domain or IP manually.')
        while True:
            try:
                endpoint = host(ask('Enter your Foreign domain or IP',endpoint_default))
                break
            except ValueError as error: print(str(error))
        try: ipaddress.ip_address(endpoint)
        except ValueError: cdn = yes('Is this domain behind Cloudflare orange proxy',True)
        else: cdn = False
    else:
        endpoint,cdn = iran_ip,False
        print('Native '+engine.capitalize()+': Foreign connects directly to Iran. Only '+engine.upper()+' will be installed.')
        print('The control port must be reachable on Iran. The Foreign Cloudflare proxy is not used.')
        print('Native TCP/UDP/WS do not add TLS encryption; use encrypted application traffic.')
    transport,endpoint,cdn = choose_transport(engine,endpoint,cdn,direct_ip=endpoint_default)
    via_foreign_apt = confirm_yn_default('Download Ubuntu packages through this Foreign server over SSH?',default='y')
    return {'endpoint':endpoint,'cdn':cdn,'iran_ip':iran_ip,'engine':engine,'transport':transport,'via_foreign_apt':via_foreign_apt}
def choose_transport(engine, endpoint, cdn, previous='tcp', direct_ip=''):
    transport_default = 'ws' if cdn and engine=='gost' else previous if previous in TRANSPORTS[engine] else 'tcp'
    try: direct_ip = str(ipaddress.IPv4Address(direct_ip))
    except ValueError: direct_ip = ''
    if cdn and engine=='gost': print('GOST with the Cloudflare orange proxy requires WS. Other transports need a direct connection to the Foreign IP.')
    while True:
        try:
            transport = choose('Transport Type',TRANSPORTS[engine],transport_default)
            if cdn and engine=='gost' and transport!='ws':
                if direct_ip: print('Direct connection target: '+direct_ip)
                if not confirm_yn_default('GOST '+transport.upper()+' cannot use the orange proxy. Connect directly to this Foreign server instead?',default='n'): continue
                direct = direct_ip
                while True:
                    try:
                        if not direct: direct = ask('Foreign IPv4 for the direct connection')
                        address = ipaddress.IPv4Address(direct)
                        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local: raise ValueError('Enter a reachable Foreign IPv4 address.')
                        break
                    except ValueError as error:
                        print(str(error)); direct = ''
                endpoint,cdn = str(address),False
                print('Selected GOST '+transport.upper()+' using Foreign IP '+endpoint+'. Cloudflare will not be used for this tunnel.')
            return transport,endpoint,cdn
        except ValueError as error: print(str(error))
def _automatic_tunnel_id():
    for number in range(1,10001):
        ident = 'mytunnel' if number==1 else 'mytunnel-'+str(number)
        paths = [ROOT/ident,pending_path(ident),*(ROOT/(prefix+ident) for prefix in ('.stage-','.backup-','.discard-'))]
        if not any(path.exists() or path.is_symlink() for path in paths): return ident
    raise RuntimeError('No unused automatic tunnel name is available. Manage existing tunnels first.')
def _automatic_foreign_target():
    ident = 'mytunnel'
    base = ROOT/ident
    remnants = [pending_path(ident),*(ROOT/(prefix+ident) for prefix in ('.stage-','.backup-','.discard-')),base/'.uncommitted',base/'.needs-restart']
    if any(path.exists() or path.is_symlink() for path in remnants): raise RuntimeError('Recover the interrupted mytunnel operation on Foreign before creating another tunnel.')
    if base.is_symlink(): raise ValueError('Refusing a symbolic link in the Foreign tunnel directory.')
    if not base.exists(): return ident,None
    validate_local_directory(base)
    old = read(base/'spec.json')
    if old['id']!=ident or old['role']!='foreign': raise ValueError('The existing mytunnel is not a Foreign tunnel. Use manual mode with a new name.')
    print('Foreign already has '+ident+'. Replacing it will stop its old connection and remove its old tunnel configuration.')
    if confirm_yn_default('Foreign already has a tunnel named '+ident+'. Delete it and create the new tunnel?',default='y'):
        return ident,old
    return _automatic_tunnel_id(),None
def _automatic_front(cdn,excluded,old=None):
    reserved = {p for manifest in all_manifests() if not old or manifest['id']!=old['id'] for p,_,_ in manifest['claims']} | set(excluded)
    for candidate in ((8443,2087,2096,443,2053,2083) if cdn else (8443,)):
        if candidate in reserved: continue
        try:
            wanted = [(candidate,'tcp','0.0.0.0')]
            if old: available(wanted,claims(old))
            else: available(wanted)
        except RuntimeError: continue
        return candidate
    if cdn: raise RuntimeError('No free Cloudflare HTTPS tunnel port is available. Free 8443, 2087 or 2096, or use manual mode with different service ports.')
    return free_port(reserved)
def _automatic_tls_foreign(s):
    if not s['cdn']: return tls_foreign(s)
    print('Cloudflare mode uses WebSocket over TLS. The domain must point to this Foreign server and Cloudflare SSL must use Full (strict).')
    s['origin_cert'] = str(CERT_ROOT/s['endpoint']/'fullchain.pem')
    s['origin_key'] = str(CERT_ROOT/s['endpoint']/'privkey.pem')
    try: validate_origin(s)
    except (ValueError,RuntimeError,OSError):
        print('A valid existing domain certificate was not found. Requesting one automatically...')
        cert,key = get_cert(s['endpoint'],interactive=False)
        s['origin_cert'],s['origin_key'] = str(cert),str(key)
        validate_origin(s)
    else: print('Using the existing certificate for '+s['endpoint']+'.')
    return {}
def build_foreign_automatic(settings):
    expected = {'endpoint','cdn','iran_ip','engine','transport','via_foreign_apt'}
    if not isinstance(settings,dict) or set(settings)!=expected: raise ValueError('Invalid automatic setup settings.')
    if settings['engine'] not in TRANSPORTS or type(settings['cdn']) is not bool or type(settings['via_foreign_apt']) is not bool: raise ValueError('Invalid automatic tunnel choice.')
    if settings['transport'] not in TRANSPORTS[settings['engine']]: raise ValueError('Invalid automatic transport choice.')
    if settings['cdn'] and settings['engine']=='gost' and settings['transport']!='ws': raise ValueError('GOST Cloudflare mode requires WS.')
    endpoint = host(settings['endpoint'])
    if endpoint!=settings['endpoint']: raise ValueError('Automatic endpoint is not canonical.')
    address = ipaddress.IPv4Address(settings['iran_ip'])
    if address.is_unspecified or address.is_multicast: raise ValueError('Invalid Iran server IPv4 address.')
    ident,old = _automatic_foreign_target()
    s = dict(schema_version=3,id=ident,role='foreign',revision=secrets.token_hex(16),token=secrets.token_hex(32),engine=settings['engine'],transport=settings['transport'],endpoint=endpoint,cdn=settings['cdn'],maps=parse_maps(DEFAULT_PORTS),keepalive=30,udp_over_tcp=False,mux_con=8,mux_version=1,mux_stream=65536,mux_buffer=4194304,sniffer=False)
    excluded = {p for pair in s['maps'] for p in pair}
    s['front'] = 8443 if native_reverse(s) else _automatic_front(s['cdn'],excluded,old=old)
    excluded.add(s['front'])
    for key in ('bridge','health_f'):
        s[key] = free_port(excluded)
        excluded.add(s[key])
    validate_shared({key:s[key] for key in SHARED})
    if old: available(claims(s),claims(old))
    else: available(claims(s))
    print('\nAutomatic Foreign tunnel: '+s['id']+' | '+s['engine']+' | '+s['transport'].upper())
    print('Default Iran listening ports -> Foreign service ports: '+', '.join(str(p)+' -> '+str(q) for p,q in s['maps']))
    if not simple_gost(s): print(('Iran control port (checked on Iran before setup): ' if native_reverse(s) else 'Foreign transport port: ')+str(s['front']))
    if s['cdn']: print('WebSocket over TLS was selected automatically for the outer Cloudflare connection.')
    if native_reverse(s): print('Required engine: '+s['engine'].upper()+'; direction: Foreign -> Iran.')
    return s,_automatic_tls_foreign(s)
def create():
    role = choose('This server is Iran or Foreign',('iran','foreign'),'foreign')
    if role=='foreign':
        mode = choose('Creation mode',('automatic','manual'),'automatic')
        if mode=='automatic': return create_automatic_foreign()
    result = build_foreign() if role=='foreign' else build_iran()
    if result:
        deploy(*result)
        if role=='foreign' and confirm_yn('Set up the Iran side of this tunnel from this server now?'): setup_iran_from_foreign(result[0])
def status(s,logs=False):
    m = read(ROOT/s['id']/'manifest.json')
    print('Role:',s['role'],'Revision:',s['revision'][:8],'Endpoint:',s['endpoint'])
    print('Engine:',s['engine'],'Transport:',s['transport'],'Schema:',s['schema_version'])
    if native_reverse(s):
        print('Connection: Foreign -> Iran | Iran control endpoint:',_gost_addr(s['endpoint'],s['front']))
    elif simple_gost(s):
        print('Connection: Iran -> Foreign service ports (direct GOST forwarding)')
    else:
        print('Connection: Iran -> Foreign | Foreign transport endpoint:',_gost_addr(s['endpoint'],s['front']))
        if s['engine']!='gost': print('Legacy GOST carrier | Foreign local bridge:',s['bridge'])
    print('Iran user port -> Foreign service port:',', '.join(str(p)+' -> '+str(q) for p,q in s['maps']))
    if s['role']=='iran': print('Local health-test port:',s['health_i'])
    else: print('Local health-responder port:',s['health_f'])
    print('Running processes do not prove that the tunnel is connected. Use test tunnel connection on Iran.')
    for name in m['units']:
        args = ['journalctl','--utc','-o','short-iso','-u',name,'-n','60','--no-pager'] if logs else ['systemctl','show',name,'-p','ActiveState','-p','SubState','-p','NRestarts']
        print(name+'\n'+run(args,check=False).replace(s['token'],'[redacted]'))
    proof = read(ROOT/s['id']/('health-seen.json' if s['role']=='foreign' else 'health-result.json'))
    if proof and proof.get('revision')==s['revision']: print('Last authenticated probe:',datetime.datetime.fromtimestamp(proof['at'],datetime.timezone.utc).isoformat(), '(historical; not a current connectivity guarantee)')
def manage():
    engine_order = {engine:number for number,engine in enumerate(TRANSPORTS)}
    files = sorted(ROOT.glob('[a-z0-9]*/spec.json'),key=lambda path:(engine_order.get(read(path,{}).get('engine'),len(engine_order)),path.parent.name))
    for i,p in enumerate(files,1):
        s = read(p); print(i,s['id'],s['role'],s['engine'],s['transport'])
    if not files: print('No local tunnels.'); return
    index = integer(int(menu_input('Tunnel number')),1,len(files),'Tunnel number')-1
    s = read(files[index]); ident=s['id']
    validate_local_directory(ROOT/ident)
    if pending_path(ident).exists(): raise RuntimeError('Recover this local operation first.')
    choices = ('status','test','edit','delete','restart','logs','code','cert','ssh') if s['role']=='foreign' else ('status','test','edit','delete','restart','logs','cert')
    action = menu_choose('Local action',choices,'status')
    if action=='code': show_code(s)
    elif action=='test': run_connection_test(s)
    elif action=='cert': get_cert(s['endpoint'] if s['role']=='foreign' and not native_reverse(s) else '')
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
    print('If Ubuntu is installing updates, APT will wait up to 300 seconds for its package lock.')
    env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    try:
        run_interactive(['apt-get', 'update'], timeout=600, env=env)
        run_interactive(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'install', '-y', '--no-install-recommends', *packages], timeout=900, env=env)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError('SSH tool installation failed on this Foreign server. Check the package manager output above. If Ubuntu updates still hold the lock, let them finish and retry Set up Iran via SSH.') from None
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
        self._apt_proxy = None
    def _redact(self, output):
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        output = str(output or '')
        if self._password:
            output = output.replace(self._password, '[REDACTED]')
        return re.sub(r'MULTI[23]\.[A-Za-z0-9_+/=-]+', '[REDACTED CONNECTION CODE]', output)
    def _base(self, forwarding=False):
        return ['ssh', '-F', '/dev/null', '-4', '-T', '-p', str(self.port), '-S', self._socket,
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15',
                '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=' + ('no' if forwarding else 'yes'), '-o', 'LogLevel=ERROR']
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
    def _command(self, argv):
        if not self._connected or self._master is None or self._master.poll() is not None:
            raise RuntimeError('SSH session is not connected.')
        if not isinstance(argv, (tuple, list)) or not argv or any(not isinstance(arg, str) or '\x00' in arg for arg in argv):
            raise ValueError('Remote command must be a nonempty list of strings.')
        return [*self._base(), '-o', 'ControlMaster=no', '-o', 'BatchMode=yes',
                '-o', 'ProxyCommand=false', 'root@' + self.ip, shlex.join(argv)]
    def run(self, argv, input_bytes=None, timeout=180):
        command = self._command(argv)
        if input_bytes is not None and not isinstance(input_bytes, bytes):
            raise ValueError('SSH input must be bytes.')
        try:
            result = subprocess.run(command, input=input_bytes if input_bytes is not None else b'',
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Remote command timed out. Check the Iran server before retrying.') from None
        except OSError as error:
            raise RuntimeError('SSH command could not run: ' + self._redact(error)) from None
        if result.returncode:
            detail = self._redact((result.stderr or b'') + b'\n' + (result.stdout or b''))
            raise RuntimeError('Remote command failed (exit ' + str(result.returncode) + '): ' + detail.strip()[-6000:])
        return (result.stdout or b'').decode('utf-8', errors='replace')
    def open_apt_proxy(self):
        self._command(['true'])
        if self._apt_proxy is not None:
            raise RuntimeError('The temporary APT proxy is already open.')
        command = [*self._base(forwarding=True), '-o', 'BatchMode=yes', '-o', 'ProxyCommand=false',
                   '-o', 'ExitOnForwardFailure=yes', '-O', 'forward', '-R', '127.0.0.1:0', 'root@' + self.ip]
        try:
            result = subprocess.run(command, capture_output=True, timeout=20)
            value = (result.stdout or b'').decode('ascii', errors='replace').strip()
            if result.returncode or not value.isdecimal() or not 1 <= int(value) <= 65535:
                detail = self._redact(result.stderr or b'').strip()[-2000:]
                raise RuntimeError('SSH could not open the temporary APT proxy. Enable remote TCP forwarding on Iran. ' + detail)
            self._apt_proxy = int(value)
            # GatewayPorts=yes on sshd can override the requested loopback address.
            verify = '$4 == "0A" && substr($2,length($2)-3) == port { found=1; if ($2 != "0100007F:" port) bad=1 } END { exit (!found || bad) }'
            check = 'port=$1; expression=$2; set -- /proc/net/tcp; if [ -r /proc/net/tcp6 ]; then set -- "$@" /proc/net/tcp6; fi; awk -v port="$port" "$expression" "$@"'
            self.run(['sh', '-c', check, 'multi-proxy-check', format(self._apt_proxy, '04X'), verify], timeout=10)
            return self._apt_proxy
        except BaseException:
            self.close()
            raise
    def close_apt_proxy(self, port):
        if self._apt_proxy is None:
            return
        if type(port) is not int or port != self._apt_proxy:
            raise ValueError('Unexpected temporary APT proxy port.')
        command = [*self._base(forwarding=True), '-o', 'BatchMode=yes', '-o', 'ProxyCommand=false',
                   '-O', 'cancel', '-R', '127.0.0.1:0', 'root@' + self.ip]
        try:
            result = subprocess.run(command, capture_output=True, timeout=10)
            if result.returncode:
                raise RuntimeError('SSH could not remove the temporary APT proxy; the SSH connection was closed.')
            self._apt_proxy = None
        except BaseException:
            self.close()
            raise
    @staticmethod
    def _stop_child(process):
        with ignore_interrupts():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    def _stream(self, command, source, on_line, timeout, on_bytes=None):
        import selectors
        process = None
        output = bytearray()
        safe_tail = ''
        line = bytearray()
        oversized = False
        sent = 0
        pending = memoryview(b'')
        deadline = time.monotonic() + timeout
        def emit(data):
            nonlocal safe_tail
            raw = data.decode('utf-8', errors='replace') if isinstance(data, bytes) else str(data)
            record = re.fullmatch(r'(dlstatus):[0-9]+:([0-9]+(?:\.[0-9]+)?):[^\r\n]*', raw)
            if record is None:
                record = re.fullmatch(r'(pmstatus):[A-Za-z0-9+_.-]+(?::[a-z][a-z0-9-]*)?:([0-9]+(?:\.[0-9]+)?):[^\r\n]*', raw)
            percent = float(record[2]) if record is not None else -1
            if record is not None and 0 <= percent <= 100:
                # Normalize only typed numeric status; never forward its package or detail text.
                message = record[1] + ':0:' + format(percent, '.4f') + ':APT progress'
            else:
                message = self._redact(raw)
            safe_tail = (safe_tail + message + '\n')[-6000:]
            if on_line is not None:
                on_line(message)
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE if source is not None else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ, 'output')
                if source is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, mask in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                        if key.data == 'input':
                            if not pending:
                                pending = memoryview(source.read(65536))
                            if not pending:
                                selector.unregister(process.stdin)
                                process.stdin.close()
                                continue
                            try:
                                count = os.write(process.stdin.fileno(), pending)
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                selector.unregister(process.stdin)
                                process.stdin.close()
                                continue
                            pending = pending[count:]
                            sent += count
                            if on_bytes is not None:
                                on_bytes(sent)
                        else:
                            try:
                                chunk = os.read(process.stdout.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(process.stdout)
                                if oversized:
                                    emit('[Long output line omitted]')
                                elif line:
                                    emit(bytes(line))
                                continue
                            output.extend(chunk)
                            if len(output) > 1048576:
                                del output[:-1048576]
                            for segment in chunk.splitlines(keepends=True):
                                if not oversized:
                                    line.extend(segment)
                                    if len(line) > 65536:
                                        line.clear()
                                        oversized = True
                                if segment.endswith((b'\n', b'\r')):
                                    emit('[Long output line omitted]' if oversized else bytes(line).rstrip(b'\r\n'))
                                    line.clear()
                                    oversized = False
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if process.returncode:
                raise RuntimeError('Remote command failed (exit ' + str(process.returncode) + '): ' + safe_tail.strip())
            return bytes(output).decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            if process is not None:
                self._stop_child(process)
            raise RuntimeError('Remote command timed out. Check the Iran server before retrying.') from None
        except OSError as error:
            raise RuntimeError('SSH command could not run: ' + self._redact(error)) from None
        finally:
            if process is not None:
                self._stop_child(process)
                for stream in (process.stdin, process.stdout):
                    if stream is not None and not stream.closed:
                        stream.close()
    def run_stream(self, argv, on_line, timeout=180, input_bytes=None):
        command = self._command(argv)
        if input_bytes is not None and not isinstance(input_bytes, bytes):
            raise ValueError('SSH input must be bytes.')
        if not callable(on_line):
            raise ValueError('SSH output callback must be callable.')
        return self._stream(command, io.BytesIO(input_bytes) if input_bytes is not None else None, on_line, timeout)
    def upload(self, local_path, remote_path):
        path = Path(local_path)
        if not path.is_file():
            raise ValueError('Upload source must be a regular file.')
        if not isinstance(remote_path, str) or not remote_path.startswith('/') or '\x00' in remote_path or '\n' in remote_path:
            raise ValueError('Upload destination must be an absolute path.')
        # Success is acknowledged only after the remote file matches the streamed bytes.
        command = self._command(['sh', '-c', 'umask 077; cat > "$1" && sha256sum -- "$1"', 'multi-upload', remote_path])
        size = path.stat().st_size
        progress = Progress('Upload ' + path.name, size)
        uploaded = 0
        def report(count):
            nonlocal uploaded
            uploaded = count
            progress.update(count)
        digest = hashlib.sha256()
        class HashedSource:
            def __init__(self, stream):
                self.stream = stream
            def read(self, size):
                chunk = self.stream.read(size)
                digest.update(chunk)
                return chunk
        try:
            with path.open('rb') as stream:
                result = self._stream(command, HashedSource(stream), None, 600, report)
            checksum = result.split(maxsplit=1)
            if uploaded != size or not checksum or checksum[0] != digest.hexdigest():
                raise RuntimeError('Upload checksum verification failed for ' + path.name + '.')
            progress.finish()
        except BaseException:
            progress.fail()
            raise
    def close(self):
        with ignore_interrupts():
            self._close()
    def _close(self):
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
            self._apt_proxy = None
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
    if (ROOT/'.uninstalling.json').exists(): raise RuntimeError('Uninstall is incomplete on Iran. Run sudo multi-tunnel --uninstall on Iran to finish it first.')
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
def preserve_public_maps(requested, existing):
    """Keep Iran ports by destination, including same-name automatic remaps."""
    by_target = {}
    for public,target in existing: by_target.setdefault(target,[]).append(public)
    result = []
    for public,target in requested:
        candidates = by_target.get(target,[])
        result.append([candidates.pop(0) if candidates else public,target])
    return result
def remote_public_ports(shared, old=None):
    own = claims(old) if old else []
    other = {(p,t) for manifest in all_manifests() if not old or manifest['id']!=old['id'] for p,t,_ in manifest['claims']}
    chosen = []
    requested_maps = preserve_public_maps(shared['maps'],old['maps']) if old else shared['maps']
    excluded = {p for p,_ in shared['maps']} | {p for p,_ in requested_maps} | {p for p,_ in other}
    if native_reverse(shared): excluded.add(shared['front'])
    for requested,_ in requested_maps:
        candidate = requested
        wanted = [(candidate,t,'0.0.0.0') for t in protocols(shared)]
        try:
            if candidate in chosen or (native_reverse(shared) and candidate==shared['front']) or any((candidate,t) in other for t in protocols(shared)): raise RuntimeError('Port already reserved.')
            available(wanted,own)
        except RuntimeError:
            candidate = free_port(excluded | set(chosen))
        chosen.append(candidate)
        excluded.add(candidate)
    return chosen
def remote_native_front(shared, old=None):
    if not native_reverse(shared): return shared['front']
    owned = claims(old) if old else []
    reserved = {p for manifest in all_manifests() if not old or manifest['id']!=old['id'] for p,_,_ in manifest['claims']}
    maps = preserve_public_maps(shared['maps'],old['maps']) if old else shared['maps']
    excluded = reserved | {p for p,_ in maps} | {p for p,_ in shared['maps']} | {shared['bridge'],shared['health_f']}
    preferred = ([old['front']] if old and native_reverse(old) else [])+[shared['front'],8443,2087,2096]
    for candidate in dict.fromkeys(preferred):
        if candidate in excluded: continue
        try: available([(candidate,t,'0.0.0.0') for t in control_protocols(shared)],owned)
        except RuntimeError: continue
        return candidate
    return free_port(excluded)
def remote_verify_binaries(shared, directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir(): raise ValueError('Missing transferred binary directory.')
    verified = []
    for engine in required_engines(shared,'iran'):
        if valid_cached_binary(engine):
            engine_path(engine).chmod(0o755)
            continue
        version,_,_,expected = THIRD_PARTY_RELEASES[engine]
        source = directory/(engine+'-'+version)
        if source.is_symlink() or not source.is_file(): raise RuntimeError('Required '+engine+' binary is missing or changed since inspection. Retry SSH setup to transfer it.')
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
    if mode=='replace': s['sniffer'] = False
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
    if request.get('action') not in ('inspect','plan','apply'): raise ValueError('Unknown remote action.')
    if request['action']=='inspect':
        if set(request) not in ({'action','id'},{'action','id','engines'}): raise ValueError('Invalid remote inspect fields.')
        valid_id(request['id'])
        engines = request.get('engines',[])
        if not isinstance(engines,list) or len(engines)>3 or any(not isinstance(engine,str) or engine not in THIRD_PARTY_RELEASES for engine in engines) or len(set(engines))!=len(engines): raise ValueError('Invalid engine inventory request.')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'.local-v2.lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as error: raise RuntimeError('Another Multi operation is running on Iran. Try again after it finishes.') from error
        state = remote_local_state()
        if request['action']=='apply': return remote_apply(request,state)
        if request['action']=='plan':
            if set(request)!={'action','code','mode','expected_revision'}: raise ValueError('Invalid planning request.')
            shared,_ = decode_pair(request['code'])
            existing = state.get(shared['id'])
            if request['mode'] not in ('create','replace','append'): raise ValueError('Invalid planned mode.')
            if (existing['revision'] if existing else None)!=request['expected_revision']: raise RuntimeError('Iran tunnel changed during setup. Retry setup.')
            if request['mode']=='replace' and (not existing or existing['role']!='iran'): raise ValueError('Only an Iran tunnel may be replaced.')
            old = existing if request['mode']=='replace' else None
            return {'ok':True,'front':remote_native_front(shared,old)}
        existing = state.get(request['id'])
        return {'ok':True,'existing':existing is not None,'existing_revision':existing['revision'] if existing else None,'existing_role':existing['role'] if existing else None,'ids':sorted(state),'binaries':binary_inventory(engines)}
def remote_main():
    previous = {}
    def interrupted(signum, frame): raise KeyboardInterrupt
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT): previous[sig] = signal.signal(sig, interrupted)
    try: return _remote_main()
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)
def _remote_main():
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
        message = re.sub(r'MULTI[23]\.[A-Za-z0-9_=-]+','[redacted]',message)
        result = {'ok':False,'error':message[-1500:]}
    print(REMOTE_RESULT_PREFIX+json.dumps(result,separators=(',',':')),flush=True)
    return 0 if result['ok'] else 1
IRAN_APT_PACKAGES = ('python3','openssl','ufw','iproute2','ca-certificates','iptables')
REMOTE_APT_INSPECT = r'''set -eu
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
test "$(id -u)" = 0 || { echo 'SSH must log in as root on Iran.' >&2; exit 1; }
. /etc/os-release
test "$ID" = ubuntu && dpkg --compare-versions "$VERSION_ID" ge 22.04 || { echo 'Iran must run Ubuntu 22.04 or newer.' >&2; exit 1; }
test "$(uname -m)" = x86_64 || { echo 'Iran must use the amd64 architecture.' >&2; exit 1; }
test -d /run/systemd/system || { echo 'Iran must use systemd as its service manager.' >&2; exit 1; }
for multi_package in python3 openssl ufw iproute2 ca-certificates iptables; do
  multi_installed=$(dpkg-query -W -f='${db:Status-Status}' "$multi_package" 2>/dev/null || true)
  if test "$multi_installed" != installed; then printf 'MULTI_APT_MISSING:%s\n' "$multi_package"; fi
done
printf 'MULTI_APT_INSPECT_OK\n'
'''
REMOTE_APT_STAGE = r'''set -eu
umask 077
multi_stage=$(mktemp -d /var/tmp/multi-apt.XXXXXXXX)
chmod 711 "$multi_stage"
printf '%s\n' "$multi_stage"
'''
REMOTE_APT_JOB = r'''set -eu
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
unset APT_CONFIG http_proxy https_proxy all_proxy no_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY || true
multi_stage=$1
multi_phase=$2
multi_seconds=$3
shift 3
case "$multi_stage" in /var/tmp/multi-apt.????????) ;; *) echo 'Invalid APT staging directory.' >&2; exit 1;; esac
test -d "$multi_stage" && test ! -L "$multi_stage" && test "$(stat -c %u "$multi_stage")" = 0
multi_pid=
multi_stop() {
  if test -n "$multi_pid"; then
    /bin/kill -TERM -- "-$multi_pid" 2>/dev/null || true
    multi_attempt=0
    while test "$multi_attempt" -lt 20 && /bin/kill -0 -- "-$multi_pid" 2>/dev/null; do sleep 0.1; multi_attempt=$((multi_attempt+1)); done
    /bin/kill -KILL -- "-$multi_pid" 2>/dev/null || true
    wait "$multi_pid" 2>/dev/null || true
    multi_pid=
  fi
  rm -f "$multi_stage/job"
}
trap 'multi_stop; exit 130' INT
trap 'multi_stop; exit 143' TERM HUP
trap 'multi_stop' EXIT
multi_run() {
  setsid timeout --foreground --signal=TERM --kill-after=10s "$multi_seconds" "$@" &
  multi_pid=$!
  multi_start=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
  if test -z "$multi_start" && /bin/kill -0 "$multi_pid" 2>/dev/null; then echo 'Cannot safely track the remote job. Check the Iran /proc mount.' >&2; multi_stop; exit 1; fi
  printf '%s %s\n' "$multi_pid" "$multi_start" > "$multi_stage/job"
  multi_rc=0
  wait "$multi_pid" || multi_rc=$?
  if test "$multi_rc" != 0; then multi_stop; return "$multi_rc"; fi
  multi_pid=
  rm -f "$multi_stage/job"
}
multi_apt() {
  multi_run /usr/bin/apt-get -c "$multi_stage/apt.conf" -o APT::Status-Fd=1 -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=60 "$@"
}
case "$multi_phase" in
  configure)
    multi_proxy=$1
    shift
    printf '%s\n' "$@" > "$multi_stage/requested"
    mkdir -m 755 "$multi_stage/methods"
    for multi_method in http https file copy store gpgv sqv rred; do
      if test -x "/usr/lib/apt/methods/$multi_method"; then ln -s "/usr/lib/apt/methods/$multi_method" "$multi_stage/methods/$multi_method"; fi
    done
    cat > "$multi_stage/apt.conf" <<EOF
#clear Acquire::http;
#clear Acquire::https;
#clear Acquire::ftp;
Acquire::http::Proxy "$multi_proxy";
Acquire::https::Proxy "$multi_proxy";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
Acquire::Retries "2";
Acquire::Languages "none";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT::Get::allow-downgrades "false";
APT::Get::allow-remove-essential "false";
APT::Get::allow-change-held-packages "false";
APT::Get::force-yes "false";
APT::Get::AutomaticRemove "false";
APT::Update::Error-Mode "any";
Dpkg::Options:: "--force-confdef";
Dpkg::Options:: "--force-confold";
Binary::apt-get::APT::Keep-Downloaded-Packages "true";
APT::Keep-Downloaded-Packages "true";
Dir::Bin::Methods "$multi_stage/methods";
EOF
    chmod 600 "$multi_stage/apt.conf" "$multi_stage/requested"
    ;;
  update)
    multi_apt update --error-on=any
    ;;
  plan)
    set -- $(cat "$multi_stage/requested")
    multi_apt --simulate --no-install-recommends --no-remove install "$@" > "$multi_stage/simulation"
    awk '/^Remv / {exit 2} /^Inst / {line=$0; sub(/^Inst /,"",line); split(line,a," "); name=a[1]; sub(/^[^(]*\(/,"",line); split(line,b," "); version=b[1]; if (name !~ /^[a-z0-9][a-z0-9+.:~-]*$/ || version !~ /^[a-zA-Z0-9.+:~_-]+$/) exit 3; print name "=" version}' "$multi_stage/simulation" > "$multi_stage/pinned"
    test -s "$multi_stage/pinned" || { echo 'APT did not produce an install plan for the missing packages.' >&2; exit 1; }
    set -- $(cat "$multi_stage/pinned")
    multi_apt --simulate --no-install-recommends --no-remove install "$@" > "$multi_stage/expected"
    awk '/^(Inst|Remv|Conf) / {print}' "$multi_stage/expected" > "$multi_stage/expected.operations"
    multi_apt --print-uris --download-only --assume-yes --no-install-recommends --no-remove install "$@"
    ;;
  download|install)
    set -- $(cat "$multi_stage/pinned")
    multi_apt --simulate --no-install-recommends --no-remove install "$@" > "$multi_stage/current"
    awk '/^(Inst|Remv|Conf) / {print}' "$multi_stage/current" > "$multi_stage/current.operations"
    cmp -s "$multi_stage/expected.operations" "$multi_stage/current.operations" || { echo 'The APT installation plan changed. Restart Iran setup to review the new download size.' >&2; exit 1; }
    if test "$multi_phase" = download; then
      multi_apt --download-only --assume-yes --no-install-recommends --no-remove install "$@"
    else
      multi_run /usr/bin/apt-mark -c "$multi_stage/apt.conf" showmanual > "$multi_stage/manual.before"
      multi_apt --no-download --assume-yes --no-install-recommends --no-remove --mark-auto install "$@"
      awk 'FNR==NR {old[$1]=1;next} {sub(/=.*/,"",$0);base=$0;sub(/:.*/,"",base);if(old[$0] || old[base]) print $0}' "$multi_stage/manual.before" "$multi_stage/pinned" > "$multi_stage/manual.restore"
      cat "$multi_stage/requested" >> "$multi_stage/manual.restore"
      set -- $(sort -u "$multi_stage/manual.restore")
      multi_run /usr/bin/apt-mark -c "$multi_stage/apt.conf" manual "$@"
    fi
    ;;
  *) echo 'Invalid APT operation.' >&2; exit 1;;
esac
'''
REMOTE_APT_CLEANUP = r'''set -eu
multi_stage=$1
case "$multi_stage" in /var/tmp/multi-apt.????????) ;; *) exit 1;; esac
test -d "$multi_stage" && test ! -L "$multi_stage" && test "$(stat -c %u "$multi_stage")" = 0 || exit 1
if test -f "$multi_stage/job"; then
  read -r multi_pid multi_start < "$multi_stage/job" || true
  case "${multi_pid:-}:${multi_start:-}" in *[!0-9:]*|:|*:|:*) ;; *)
    multi_current=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
    multi_group=$(ps -o pgid= -p "$multi_pid" 2>/dev/null | tr -d ' ' || true)
    if test "$multi_current" = "$multi_start" && test "$multi_group" = "$multi_pid"; then
      /bin/kill -TERM -- "-$multi_pid" 2>/dev/null || true
      multi_attempt=0
      while test "$multi_attempt" -lt 20 && /bin/kill -0 -- "-$multi_pid" 2>/dev/null; do sleep 0.1; multi_attempt=$((multi_attempt+1)); done
      multi_current=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
      if test "$multi_current" = "$multi_start"; then /bin/kill -KILL -- "-$multi_pid" 2>/dev/null || true; fi
    fi
    ;;
  esac
fi
rm -rf -- "$multi_stage"
'''
def _apt_missing(output):
    lines = output.splitlines()
    if not lines or lines[-1]!='MULTI_APT_INSPECT_OK': raise RuntimeError('Iran did not return a complete prerequisite check.')
    missing = []
    for line in lines[:-1]:
        if not line.startswith('MULTI_APT_MISSING:'): raise RuntimeError('Unexpected prerequisite check response from Iran.')
        package = line.split(':',1)[1]
        if package not in IRAN_APT_PACKAGES or package in missing: raise RuntimeError('Invalid prerequisite list from Iran.')
        missing.append(package)
    return missing
def _apt_download_bytes(output):
    total = 0
    files = set()
    for line in output.splitlines():
        if not line.startswith("'"): continue
        try: fields = shlex.split(line)
        except ValueError: raise RuntimeError('APT returned an invalid download plan.') from None
        if len(fields)!=4 or not fields[2].isdigit() or fields[1] in files: raise RuntimeError('APT returned an invalid download plan.')
        if not fields[0].startswith(('http://','https://','file:','copy:')): raise RuntimeError('The APT plan uses an unsupported repository transport.')
        files.add(fields[1])
        if fields[0].startswith(('http://','https://')): total += int(fields[2])
    if not files and 'Need to get ' in output:
        match = re.search(r'Need to get ([^\n]+)',output)
        if match and not re.match(r'0(?:\s+B|/)',match.group(1)): raise RuntimeError('APT did not report a complete package download size.')
    return total
def install_iran_dependencies(session, via_foreign, *, automatic=False):
    missing = _apt_missing(session.run(['sh','-c',REMOTE_APT_INSPECT],timeout=60))
    if not missing:
        print('\nUbuntu package download: 0 bytes. All six prerequisites are already installed.\n')
        if via_foreign and not automatic and not confirm_yn_default('Continue Iran setup?',default='y'):
            print('Iran setup cancelled. The Foreign tunnel is saved.')
            return False
        return True
    proxy_port = stage = None
    try:
        if via_foreign:
            proxy_port = session.open_apt_proxy()
            if type(proxy_port) is not int or not 1<=proxy_port<=65535: raise RuntimeError('SSH returned an invalid APT proxy port.')
        stage = session.run(['sh','-c',REMOTE_APT_STAGE],timeout=30).strip()
        if not re.fullmatch(r'/var/tmp/multi-apt\.[A-Za-z0-9]{8}',stage): raise RuntimeError('Iran returned an unexpected APT staging directory.')
        def command(phase,seconds=1200,*args):
            return ['sh','-c',REMOTE_APT_JOB,'multi-apt',stage,phase,str(seconds),*args]
        proxy = 'socks5h://127.0.0.1:'+str(proxy_port) if via_foreign else 'DIRECT'
        session.run(command('configure',30,proxy,*missing),timeout=45)
        if via_foreign: print('\nRefreshing Ubuntu repository indexes through Foreign before calculating the package download size.\n')
        else: print('\nRefreshing Ubuntu repository indexes using Iran internet.\n')
        def streamed(phase,label,seconds):
            progress = AptProgress(label)
            try: session.run_stream(command(phase,seconds),on_line=progress.feed,timeout=seconds+30)
            except BaseException:
                progress.fail()
                raise
            progress.finish()
        streamed('update','Ubuntu repository indexes',900)
        print('\nCalculating missing packages and their dependencies...\n')
        plan = session.run(command('plan',120),timeout=150)
        total = _apt_download_bytes(plan)
        print('\nUbuntu packages to download: '+format(total,',')+' bytes ('+format(total/(1024*1024),'.2f')+' MiB).')
        print('Already cached complete packages are excluded; repository indexes and SSH overhead are separate.\n')
        if automatic: print('Automatic mode: proceeding with the displayed package download size (default: y).')
        if via_foreign and not automatic and not confirm_yn_default('Download these packages through Foreign and install them on Iran?',default='y'):
            print('Iran setup cancelled. No Ubuntu packages were installed; the Foreign tunnel is saved.')
            return False
        if total: streamed('download','Downloading Ubuntu packages',1200)
        else:
            print('All required package archives are already available on Iran.')
            streamed('download','Checking cached Ubuntu packages',120)
        streamed('install','Installing Ubuntu packages on Iran',1200)
        remaining = _apt_missing(session.run(['sh','-c',REMOTE_APT_INSPECT],timeout=60))
        if remaining: raise RuntimeError('Ubuntu prerequisites remain missing: '+', '.join(remaining))
        return True
    finally:
        with ignore_interrupts():
            errors = []
            if stage and re.fullmatch(r'/var/tmp/multi-apt\.[A-Za-z0-9]{8}',stage):
                try: session.run(['sh','-c',REMOTE_APT_CLEANUP,'multi-apt-cleanup',stage],timeout=30)
                except Exception as error: errors.append('APT temporary files or job could not be cleaned on Iran ('+stage+'): '+str(error))
            if proxy_port is not None:
                try: session.close_apt_proxy(proxy_port)
                except Exception as error: errors.append('The temporary SSH APT proxy could not be closed: '+str(error))
            if errors:
                message = ' '.join(errors)
                if sys.exc_info()[0] is None: raise RuntimeError(message)
                print(message)
REMOTE_MANAGED_JOB = r'''set -eu
umask 077
multi_stage=$1
multi_seconds=$2
shift 2
case "$multi_stage" in /root/.multi-setup.????????) ;; *) echo 'Invalid remote job directory.' >&2; exit 1;; esac
test -d "$multi_stage" && test ! -L "$multi_stage" && test "$(stat -c %u "$multi_stage")" = 0
multi_pid=
multi_stop() {
  if test -n "$multi_pid"; then
    /bin/kill -INT -- "-$multi_pid" 2>/dev/null || true
    multi_attempt=0
    while test "$multi_attempt" -lt 100 && /bin/kill -0 -- "-$multi_pid" 2>/dev/null; do sleep 0.2; multi_attempt=$((multi_attempt+1)); done
    /bin/kill -KILL -- "-$multi_pid" 2>/dev/null || true
    wait "$multi_pid" 2>/dev/null || true
    multi_pid=
  fi
  rm -f "$multi_stage/job"
}
trap 'multi_stop; exit 130' INT
trap 'multi_stop; exit 143' TERM HUP
trap 'multi_stop' EXIT
exec 3<&0
setsid timeout --foreground --signal=INT --kill-after=30s "$multi_seconds" "$@" <&3 &
multi_pid=$!
multi_start=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
if test -z "$multi_start" && /bin/kill -0 "$multi_pid" 2>/dev/null; then echo 'Cannot safely track the remote job. Check the Iran /proc mount.' >&2; multi_stop; exit 1; fi
printf '%s %s\n' "$multi_pid" "$multi_start" > "$multi_stage/job"
multi_rc=0
wait "$multi_pid" || multi_rc=$?
if test "$multi_rc" != 0; then multi_stop; exit "$multi_rc"; fi
multi_pid=
rm -f "$multi_stage/job"
'''
REMOTE_MANAGED_CANCEL = r'''set -eu
multi_stage=$1
case "$multi_stage" in /root/.multi-setup.????????) ;; *) exit 1;; esac
test -d "$multi_stage" && test ! -L "$multi_stage" && test "$(stat -c %u "$multi_stage")" = 0 || exit 1
if test -f "$multi_stage/job"; then
  read -r multi_pid multi_start < "$multi_stage/job" || true
  case "${multi_pid:-}:${multi_start:-}" in *[!0-9:]*|:|*:|:*) ;; *)
    multi_current=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
    multi_group=$(ps -o pgid= -p "$multi_pid" 2>/dev/null | tr -d ' ' || true)
    if test "$multi_current" = "$multi_start" && test "$multi_group" = "$multi_pid"; then
      /bin/kill -INT -- "-$multi_pid" 2>/dev/null || true
      multi_attempt=0
      while test "$multi_attempt" -lt 100 && /bin/kill -0 -- "-$multi_pid" 2>/dev/null; do sleep 0.2; multi_attempt=$((multi_attempt+1)); done
      multi_current=$(awk '{print $22}' "/proc/$multi_pid/stat" 2>/dev/null || true)
      if test "$multi_current" = "$multi_start"; then /bin/kill -KILL -- "-$multi_pid" 2>/dev/null || true; fi
    fi
    ;;
  esac
fi
'''
def managed_remote_command(stage, argv, timeout):
    if not isinstance(stage,str) or not re.fullmatch(r'/root/\.multi-setup\.[A-Za-z0-9]{8}',stage): raise ValueError('Invalid remote job directory.')
    if not isinstance(argv,(list,tuple)) or not argv or any(not isinstance(arg,str) or '\x00' in arg for arg in argv): raise ValueError('Invalid remote job command.')
    if type(timeout) is not int or not 1<=timeout<=3600: raise ValueError('Invalid remote job timeout.')
    return ['sh','-c',REMOTE_MANAGED_JOB,'multi-job',stage,str(timeout),*argv]
def cancel_managed_remote_job(session, stage):
    if not isinstance(stage,str) or not re.fullmatch(r'/root/\.multi-setup\.[A-Za-z0-9]{8}',stage): raise ValueError('Invalid remote job directory.')
    session.run(['sh','-c',REMOTE_MANAGED_CANCEL,'multi-job-cancel',stage],timeout=35)
def remote_request(session,script,request,timeout=180):
    command = shlex.join(['/usr/bin/python3',script,'remote'])+' || [ "$?" -eq 1 ]'
    stage = str(Path(script).parent)
    try:
        output = session.run(managed_remote_command(stage,['sh','-c',command],timeout),input_bytes=json.dumps(request,separators=(',',':')).encode(),timeout=timeout+35)
    finally:
        active_error = sys.exc_info()[0]
        with ignore_interrupts():
            try: cancel_managed_remote_job(session,stage)
            except Exception as error:
                session._retain_stage = stage
                print('Could not confirm remote job cleanup; check Iran status. Temporary files retained at '+stage)
                if active_error is None: raise RuntimeError('Remote job cleanup failed: '+str(error)) from error
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
def foreign_connection_code(s):
    if s['role']!='foreign': raise ValueError('Start SSH setup from the Foreign server.')
    validate_local_directory(ROOT/s['id'])
    code = (ROOT/s['id']/'connection.txt').read_text().strip()
    paired,_ = decode_pair(code)
    if {k:s[k] for k in SHARED}!=paired: raise ValueError('The saved connection code does not match this Foreign tunnel.')
    return code
def configure_iran_session(s, session, *, via_foreign=False, automatic=False, dependencies_ready=False):
    code = foreign_connection_code(s)
    if not dependencies_ready:
        ready = install_iran_dependencies(session,via_foreign,automatic=True) if automatic else install_iran_dependencies(session,via_foreign)
        if not ready:
            print('Iran setup cancelled. The Foreign tunnel is saved.')
            return None
    stage = session.run(['mktemp','-d','/root/.multi-setup.XXXXXXXX']).strip()
    if not re.fullmatch(r'/root/\.multi-setup\.[A-Za-z0-9]{8}',stage): raise RuntimeError('Iran returned an unexpected staging directory.')
    try:
        remote_script = stage+'/multi-tunnel.py'
        local_script = Path(__file__).resolve()
        script_sha = hashlib.sha256(local_script.read_bytes()).hexdigest()
        session.upload(local_script,remote_script)
        transferred = session.run(['sha256sum','--',remote_script]).split()
        if not transferred or transferred[0]!=script_sha: raise RuntimeError('Transferred manager SHA256 mismatch.')
        engines = required_engines(s,'iran')
        state = remote_request(session,remote_script,{'action':'inspect','id':s['id'],'engines':list(engines)})
        if type(state.get('existing')) is not bool: raise RuntimeError('Invalid tunnel inventory from Iran.')
        mode = 'create'
        if state['existing']:
            if automatic:
                replace = confirm_yn_default('Iran already has a tunnel named '+s['id']+'. Delete it and create the new tunnel?',default='y')
            else: replace = confirm_yn('Iran already has a tunnel named '+s['id']+'. Replace that tunnel?')
            mode = 'replace' if replace else 'append'
            if replace and state.get('existing_role')!='iran': raise RuntimeError('That existing tunnel has the Foreign role. Choose n to add a separate Iran tunnel.')
        if native_reverse(s):
            planned = remote_request(session,remote_script,{'action':'plan','code':code,'mode':mode,'expected_revision':state.get('existing_revision')})
            selected = integer(planned.get('front'),1,65535,'Iran control port')
            if selected!=s['front']:
                print('Iran control port '+str(s['front'])+' is unavailable or an existing control port is being reused. Using '+str(selected)+'.')
                s = dict(s,front=selected)
                deploy(s,{})
                code = foreign_connection_code(s)
            print('Foreign -> Iran control endpoint: '+_gost_addr(s['endpoint'],s['front']))
        print('Checking the required engine cache on Iran: '+', '.join(engines))
        session.run(['mkdir','-m','700',stage+'/bin'])
        inventory = state.get('binaries',{})
        for engine in engines:
            version,_,_,expected = THIRD_PARTY_RELEASES[engine]
            cached = inventory.get(engine,{})
            if cached.get('valid') is True and cached.get('version')==version:
                print(engine.upper()+' '+version+' is already installed on Iran and its SHA256 matches; skipping upload.')
                continue
            print('Sending required engine: '+engine.upper()+' '+version)
            binary = Path(install_binary(engine))
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
        with ignore_interrupts():
            if getattr(session,'_retain_stage',None)!=stage:
                try: session.run(['rm','-rf','--',stage],timeout=30)
                except Exception: print('The SSH staging directory could not be removed from Iran: '+stage)
def setup_iran_from_foreign(s):
    code = foreign_connection_code(s)
    via_foreign = confirm_yn('Download Ubuntu packages through this Foreign server over SSH?')
    address = ask_iran_address()
    ssh_port = ask_ssh_port()
    password = ask_ssh_password()
    try:
        ensure_ssh_dependencies()
        print('Connecting to Iran as root...')
        with SSHSession(address,ssh_port,password) as session:
            password = ''
            return configure_iran_session(s,session,via_foreign=via_foreign)
    except Exception as error:
        message = str(error).replace(code,'[redacted]').replace(s['token'],'[redacted]')
        if password: message = message.replace(password,'[redacted]')
        print('Iran setup was not completed: '+message)
        print('The Foreign tunnel is saved. Check Iran status, then use Set up Iran via SSH in tunnel management to retry.')
        return None
    finally: password = ''
def verify_distinct_iran(session):
    # A second SSH address can still point to this very same machine.
    local = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    remote = session.run(['cat','/proc/sys/kernel/random/boot_id'],timeout=20).strip()
    pattern = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if not re.fullmatch(pattern,local) or not re.fullmatch(pattern,remote): raise RuntimeError('Could not verify that Iran and Foreign are separate servers.')
    if hmac.compare_digest(local,remote): raise ValueError('The Iran SSH address points to this Foreign server. Enter a different server.')
def create_automatic_foreign():
    settings = ask_automatic_settings()
    ssh_port = ask_ssh_port()
    password = ask_ssh_password()
    s = None
    foreign_ready = False
    try:
        ensure_ssh_dependencies()
        print('\n[1/5] Connecting to Iran and checking server requirements...')
        with SSHSession(settings['iran_ip'],ssh_port,password) as session:
            password = ''
            verify_distinct_iran(session)
            _apt_missing(session.run(['sh','-c',REMOTE_APT_INSPECT],timeout=60))
            print('\n[2/5] Preparing Foreign defaults and certificates...')
            s,tls = build_foreign_automatic(settings)
            print('\n[3/5] Preparing Ubuntu dependencies on Iran...')
            if not install_iran_dependencies(session,settings['via_foreign_apt'],automatic=True):
                raise RuntimeError('Iran prerequisites were not completed.')
            print('\n[4/5] Creating the Foreign tunnel...')
            deploy(s,tls)
            foreign_ready = True
            print('\n[5/5] Sending files, creating Iran tunnel and testing the connection...')
            result = configure_iran_session(s,session,automatic=True,dependencies_ready=True)
            if not result or result.get('connection_ok') is not True: raise RuntimeError('Iran did not confirm the tunnel connection.')
            print('Automatic setup completed on both servers.')
            return result
    except KeyboardInterrupt:
        if foreign_ready: print('\nThe Foreign tunnel is saved. Resume Iran setup from Manage -> Set up Iran via SSH.')
        raise
    except Exception as error:
        message = str(error)
        if password: message = message.replace(password,'[redacted]')
        if s: message = message.replace(s['token'],'[redacted]')
        message = re.sub(r'MULTI[23]\.[A-Za-z0-9_+/=-]+','[redacted]',message)
        print('Automatic setup was not completed: '+message)
        if foreign_ready: print('The Foreign tunnel is saved. Check Iran, then use Manage -> Set up Iran via SSH to retry.')
        return None
    finally: password = ''
PANEL_INSTALLERS = {
    '3x-ui': ('mhsanaei/3x-ui', 'https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh'),
    'x-ui': ('alireza0/x-ui', 'https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh'),
}
def cancel_process_group(process):
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        for sig, grace in ((signal.SIGINT, 1.5), (signal.SIGTERM, 0.5), (signal.SIGKILL, 0)):
            try: os.killpg(process.pid, sig)
            except ProcessLookupError: break
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: break
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    finally: signal.signal(signal.SIGINT, previous)
def run_interactive(args, check=True, timeout=None, env=None, cwd=None):
    """Keep terminal input/output visible; cancel this command's process group."""
    command = [str(value) for value in args]
    process = subprocess.Popen(command, env=env, cwd=cwd, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout)
        if returncode in (-signal.SIGINT, 128 + signal.SIGINT): raise KeyboardInterrupt
    except BaseException:
        cancel_process_group(process)
        raise
    if check and returncode: raise subprocess.CalledProcessError(returncode, command)
    return subprocess.CompletedProcess(command, returncode)
def panel_dependencies():
    packages = ['curl', 'ca-certificates']
    result = subprocess.run(['dpkg-query', '-W', '-f=${binary:Package} ${db:Status-Status}\\n', *packages], capture_output=True, text=True)
    installed = set(result.stdout.splitlines())
    missing = [name for name in packages if name + ' installed' not in installed]
    if not missing: return
    print('Installing panel download prerequisites on this server...')
    env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    run_interactive(['apt-get', 'update'], timeout=900, env=env)
    run_interactive(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'install', '-y', '--no-install-recommends', *missing], timeout=1200, env=env)
def install_panel(panel, role=None):
    if panel not in PANEL_INSTALLERS: raise ValueError('Unknown panel installer.')
    if os.geteuid() != 0: raise RuntimeError('Run this manager as root to install a panel.')
    project, url = PANEL_INSTALLERS[panel]
    location = role.capitalize() + ' server' if role in ('iran', 'foreign') else 'server'
    print('\nInstalling ' + project + ' on THIS ' + location + ' (' + socket.gethostname() + ').')
    print('The official installer selects its latest stable release and asks for panel settings here.')
    existing = shutil.which('x-ui') or any(Path(path).exists() for path in ('/usr/local/x-ui', '/etc/x-ui', '/etc/systemd/system/x-ui.service', '/usr/lib/systemd/system/x-ui.service'))
    if existing:
        print('An x-ui installation already exists here. These two panels share x-ui.service and installation files.')
        print('Running this installer can update or replace the existing panel. Keep a panel backup before continuing.')
        if not yes('Continue with the ' + project + ' installer on this server', False):
            print('Panel installation cancelled.')
            return False
    panel_dependencies()
    payload = _release_download(url, label='Download ' + project + ' installer')
    if not isinstance(payload, bytes) or not payload or len(payload) > 2 * 1024 * 1024 or b'\x00' in payload:
        raise ValueError('The downloaded panel installer is empty, invalid or too large.')
    first_line = payload.splitlines()[0]
    if not first_line.startswith(b'#!') or b'bash' not in first_line:
        raise ValueError('The downloaded panel installer is not a Bash script.')
    with tempfile.TemporaryDirectory(prefix='multi-panel-') as directory:
        script = Path(directory) / 'install.sh'
        write(script, payload.decode('utf-8'))
        run_interactive(['bash', '-n', str(script)], timeout=30)
        print('\nStarting the official ' + project + ' installer. Its output and questions follow.\n')
        try: run_interactive(['bash', str(script)])
        except KeyboardInterrupt:
            print('\nPanel installation cancelled. Changes already made by the official installer may remain.')
            raise
        except subprocess.CalledProcessError as error:
            raise RuntimeError('The official panel installer failed. Review its output above; partial installation changes may remain.') from error
    print('\nOfficial panel installer finished. Use the address and settings shown in its output.\n')
    return True
def uninstall_path_check():
    for directory in (ROOT,SCRIPT.parent):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError('Refusing an unexpected installation directory: '+str(directory))
        if directory.exists():
            for base,dirs,_ in os.walk(directory,followlinks=False):
                for candidate in (Path(base),*(Path(base)/name for name in dirs)):
                    if not candidate.is_symlink() and os.path.ismount(candidate):
                        raise RuntimeError('Unmount this path before uninstalling: '+str(candidate))
    if LAUNCHER.exists() and not LAUNCHER.is_file() and not LAUNCHER.is_symlink():
        raise RuntimeError('Unexpected launcher path: '+str(LAUNCHER))
    if LAUNCHER.is_file() and not LAUNCHER.is_symlink() and str(SCRIPT) not in LAUNCHER.read_text():
        raise RuntimeError('The launcher is not owned by this installation: '+str(LAUNCHER))
def managed_unit_name(name):
    return bool(re.fullmatch(r'multi-[a-z0-9][a-z0-9-]{0,23}-(?:gost|backhaul|rathole|echo)\.service',name))
def uninstall_unit_names():
    """Find owned services even after an interrupted change or a lost manifest."""
    names = set()
    for path in [*UNITS.glob('multi-*.service'),*ROOT.rglob('multi-*.service')]:
        if not managed_unit_name(path.name) or path.is_symlink() or not path.is_file(): continue
        content = path.read_text(errors='replace')
        if 'Description=Multi Tunnel ' in content and (str(ROOT)+'/' in content or str(SCRIPT.parent)+'/' in content): names.add(path.name)
    marker = read(ROOT/'.uninstalling.json',{})
    if not isinstance(marker,dict) or not isinstance(marker.get('units',[]),list): raise ValueError('Invalid uninstall checkpoint.')
    for name in marker.get('units',[]):
        if not isinstance(name,str) or not managed_unit_name(name): raise ValueError('Invalid unit in uninstall checkpoint.')
        names.add(name)
    candidates = set()
    for command in (['systemctl','list-unit-files','--no-legend','--no-pager','multi-*.service'],['systemctl','list-units','--all','--plain','--no-legend','--no-pager','multi-*.service']):
        for line in run(command).splitlines():
            fields = line.split()
            if fields and managed_unit_name(fields[0]): candidates.add(fields[0])
    for name in candidates-names:
        command = run(['systemctl','show',name,'--property=ExecStart','--value'])
        if str(SCRIPT.parent)+'/' in command: names.add(name)
    return sorted(names)
def uninstall_firewall():
    if shutil.which('ufw'):
        for line in run(['ufw','show','added']).splitlines():
            args = shlex.split(line)
            if args[:2]!=['ufw','allow'] or 'comment' not in args: continue
            index = args.index('comment')+1
            if index<len(args) and args[index] in ('multi-v2','multi-certbot'):
                run(['ufw','--force','delete']+args[1:])
    for binary in ('iptables','ip6tables'):
        if not shutil.which(binary): continue
        for line in run([binary,'-w','5','-S','INPUT']).splitlines():
            args = shlex.split(line)
            if args[:2]!=['-A','INPUT'] or '--comment' not in args: continue
            index = args.index('--comment')+1
            if index<len(args) and re.fullmatch(r'multi-v2-[a-z0-9][a-z0-9-]{0,23}',args[index]):
                run([binary,'-w','5','-D',*args[1:]])
def remove_owned_path(path):
    # rmtree does not follow symlink entries; a top-level link is unlinked only.
    if path.is_symlink() or path.is_file(): path.unlink()
    elif path.exists(): shutil.rmtree(path)
def uninstall_all():
    if os.geteuid()!=0: raise RuntimeError('Run: sudo multi-tunnel --uninstall')
    uninstall_path_check()
    names = uninstall_unit_names()
    print('\nUninstall Multi Tunnel from THIS server ('+socket.gethostname()+').')
    print('This permanently removes every local Multi Tunnel, its services, all cached engines and the installed manager.')
    print('Services found:',len(names))
    print('Remove:',str(ROOT),str(SCRIPT.parent),str(LAUNCHER))
    print('Other servers, panels, system packages and external certificates are kept. Manager-owned firewall rules are removed.')
    if not confirm_yn_default('Permanently uninstall Multi Tunnel and ALL local tunnels?',default='n'):
        print('Uninstall cancelled.'); return False
    installed = SCRIPT.is_file()
    launcher_present = LAUNCHER.exists() or LAUNCHER.is_symlink()
    manager_source = Path(__file__).read_text() if installed else ''
    write(ROOT/'.uninstalling.json',json.dumps({'units':names}))
    try:
        print('Stopping all local tunnel services...',flush=True)
        for name in names:
            try: run(['systemctl','stop',name])
            except RuntimeError:
                if run(['systemctl','show',name,'--property=LoadState','--value'])!='not-found': raise
            state = run(['systemctl','show',name,'--property=ActiveState','--value'])
            if state not in ('inactive','failed',''): raise RuntimeError('Service is still running: '+name)
            run(['systemctl','disable',name],check=False)
        print('Removing managed firewall rules and service files...',flush=True)
        uninstall_firewall()
        for name in names:
            (UNITS/name).unlink(missing_ok=True)
            remove_owned_path(UNITS/(name+'.d'))
            for directory in [*UNITS.glob('*.wants'),*UNITS.glob('*.requires')]:
                if directory.is_symlink() or not directory.is_dir(): continue
                link = directory/name
                if link.is_symlink(): link.unlink()
        run(['systemctl','daemon-reload'])
        for name in names: run(['systemctl','reset-failed',name],check=False)
        print('Removing all configurations, backups and cached engines...',flush=True)
        # Keep the manager until service, firewall and data cleanup has succeeded.
        if SCRIPT.parent.exists():
            for path in SCRIPT.parent.iterdir():
                if path!=SCRIPT: remove_owned_path(path)
        remove_owned_path(ROOT)
        LAUNCHER.unlink(missing_ok=True)
        SCRIPT.unlink(missing_ok=True)
        if SCRIPT.parent.exists(): SCRIPT.parent.rmdir()
    except BaseException:
        try:
            # A late filesystem error must not strand the user without a cleanup command.
            if installed and not SCRIPT.exists(): write(SCRIPT,manager_source)
            if launcher_present and not LAUNCHER.exists():
                write(LAUNCHER,'#!/bin/sh\nexec /usr/bin/python3 '+shlex.quote(str(SCRIPT))+' "$@"\n')
                LAUNCHER.chmod(0o755)
            if not (ROOT/'.uninstalling.json').exists(): write(ROOT/'.uninstalling.json',json.dumps({'units':names}))
        except OSError as error: print('Could not restore the uninstall checkpoint: '+str(error),file=sys.stderr)
        print('Uninstall did not finish. Some services may already be stopped. Run this manager with --uninstall again to finish cleanup.',file=sys.stderr)
        raise
    print('Multi Tunnel, all local tunnels and all managed engines have been removed. Exiting.')
    return True
def main():
    if len(sys.argv)>1 and sys.argv[1]=='remote': sys.exit(remote_main())
    if len(sys.argv)>1 and sys.argv[1] in ('echo','guard-on','guard-off'):
        s = read(sys.argv[2])
        if s.get('schema_version') not in (2,3): raise ValueError('Unsupported local configuration.')
        if sys.argv[1]=='echo': echo_service(s)
        else: monitor_guard(s,sys.argv[1]=='guard-on')
        return
    if len(sys.argv)>1:
        if sys.argv[1] in ('--version','--help','-h'): print('Multi Tunnel '+VERSION+'\nRun: sudo python3 multi-tunnel.py\nCreate on Foreign first; use automatic Iran setup via SSH or import the connection code on Iran.\nUninstall ALL local tunnels and engines: sudo multi-tunnel --uninstall (asks for confirmation).'); return
        if sys.argv[1:] == ['--uninstall']:
            if os.geteuid()!=0: raise RuntimeError('Run: sudo multi-tunnel --uninstall')
            uninstall_path_check()
            ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
            with (ROOT/'.local-v2.lock').open('w') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                uninstall_all()
            return
        raise ValueError('Unknown argument.')
    if os.geteuid()!=0: raise RuntimeError('Run: sudo python3 multi-tunnel.py')
    if ROOT.is_symlink(): raise RuntimeError('Refusing a symbolic link in the configuration directory: '+str(ROOT))
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'.local-v2.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        while True:
            try:
                print('\nMULTI TUNNEL '+VERSION+'\n1) Create tunnel\n2) Manage local tunnels\n3) Recover interrupted local change\n4) get cert for sub domain\n5) Install the latest mhsanaei/3x-ui panel\n6) Install the latest alireza0/x-ui panel\n7) Uninstall Multi Tunnel (ALL local tunnels and engines)\n0) Exit')
                choice = menu_input('Select','0')
            except MenuExit:
                print('\nGoodbye.')
                return
            try:
                if choice=='0': return
                if choice=='7':
                    if uninstall_all(): return
                    continue
                if (ROOT/'.uninstalling.json').exists(): raise RuntimeError('Uninstall is incomplete. Select 7 to finish cleanup first.')
                if choice in ('1','2','3'):
                    if legacy_ids(): raise RuntimeError('Unsupported legacy tunnels found: '+', '.join(legacy_ids())+'. Use their previous manager to remove/migrate them first.')
                    ensure_dependencies()
                    if Path(__file__).resolve()!=SCRIPT: write(SCRIPT,Path(__file__).read_text())
                elif choice=='4': ensure_dependencies()
                if choice=='1': create()
                elif choice=='2': manage()
                elif choice=='3':
                    files = sorted(ROOT.glob('.pending-*.json'))
                    for i,p in enumerate(files,1): print(i,p.name)
                    if files:
                        index=integer(int(menu_input('Number')),1,len(files),'Number')-1
                        recover(files[index].name[len('.pending-'):-len('.json')]); print('Local recovery finished.')
                elif choice=='4': get_cert()
                elif choice in ('5','6'): install_panel('3x-ui' if choice=='5' else 'x-ui')
                else: raise ValueError('Invalid selection. Enter an option number.')
            except EOFError: return
            except MenuExit:
                print('\nGoodbye.')
                return
            except KeyboardInterrupt: print('\nOperation cancelled. Returning to the menu.')
            except Exception as e: print('ERROR:',str(e))
if __name__=='__main__':
    try: main()
    except KeyboardInterrupt: print('\nOperation cancelled.',file=sys.stderr); sys.exit(130)
    except Exception as e: print('ERROR:',str(e),file=sys.stderr); sys.exit(1)
