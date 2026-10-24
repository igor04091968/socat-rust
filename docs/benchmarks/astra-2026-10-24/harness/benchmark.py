#!/usr/bin/env python3
"""Bounded localhost comparison. Synthetic bytes only; never opens production configs."""
import argparse,asyncio,concurrent.futures,contextlib,json,os,resource,signal,socket,ssl,statistics,subprocess,sys,threading,time
from pathlib import Path

RUST='/usr/local/sbin/socat-rust'
SOCAT='/usr/bin/socat'
ROOT=Path(__file__).resolve().parent
CREATED=[]


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


def receive(s,size):
    data=bytearray(size);view=memoryview(data);offset=0
    while offset<size:
        got=s.recv_into(view[offset:])
        if not got:raise AssertionError('unexpected EOF')
        offset+=got
    return data


def connect(p):
    s=socket.create_connection(('127.0.0.1',p),timeout=8)
    s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    return s


def guard():
    memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemAvailable'].split()[0])<768*1024:raise RuntimeError('memory headroom guard')
    if os.getloadavg()[0]>4.0:raise RuntimeError('host load guard')


def spawn(args,name):
    f=(ROOT/(name+'.log')).open('ab')
    p=subprocess.Popen([str(a) for a in args],stdout=f,stderr=f,start_new_session=True,env={**os.environ,'RUST_LOG':'warn','PYTHONDONTWRITEBYTECODE':'1'})
    f.close();CREATED.append(p);return p


def stop(p):
    if p is None:return
    try:os.killpg(p.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        p.wait(timeout=3)


def listening(p):
    target=f'0100007F:{p:04X}'
    return any(line.split()[1]==target and line.split()[3]=='0A' for line in Path('/proc/net/tcp').read_text().splitlines()[1:])


def wait_listener(p,process):
    until=time.monotonic()+8
    while time.monotonic()<until:
        if process.poll() is not None:raise RuntimeError('relay exited; see logs')
        if listening(p):return
        time.sleep(.02)
    raise TimeoutError('listener startup timeout')


def family(pid):
    result=[];pending=[pid]
    while pending:
        current=pending.pop()
        try:
            parts=Path(f'/proc/{current}/stat').read_text().rsplit(')',1)[1].split()
            children=Path(f'/proc/{current}/task/{current}/children').read_text().split()
            result.append((current,parts));pending.extend(map(int,children))
        except (FileNotFoundError,ProcessLookupError):pass
    return result


def usage(pid,pss=False):
    members=family(pid);ticks=os.sysconf('SC_CLK_TCK');pages=os.sysconf('SC_PAGE_SIZE')
    data={'processes':len(members),'threads':0,'rss_mib':0.,'pss_mib':0.,'cpu_seconds':0.,'fds':0}
    for current,p in members:
        data['cpu_seconds']+=sum(int(p[i]) for i in (11,12,13,14))/ticks
        data['threads']+=int(p[17]);data['rss_mib']+=int(p[21])*pages/1048576
        try:data['fds']+=len(list(Path(f'/proc/{current}/fd').iterdir()))
        except (FileNotFoundError,PermissionError):pass
        if pss:
            try:
                rollup=Path(f'/proc/{current}/smaps_rollup').read_text().splitlines()
                data['pss_mib']+=sum(int(line.split()[1]) for line in rollup if line.startswith('Pss:'))/1024
            except (FileNotFoundError,PermissionError):pass
    return data


def quota_stat():
    group=Path('/proc/self/cgroup').read_text().strip().split('::')[-1]
    p=Path('/sys/fs/cgroup')/group.lstrip('/')/'cpu.stat'
    return {k:int(v) for k,v in (line.split() for line in p.read_text().splitlines())}


def percentile(values,q):
    data=sorted(values);return data[min(len(data)-1,int((len(data)-1)*q))]


def start_relay(implementation,upstream,mode='tcp',name='case',allow='127.0.0.1/32',hostname='localhost'):
    listen=port();prefix=f'{name}-{implementation}-{listen}'
    if implementation=='rust':
        config=ROOT/(prefix+'.toml')
        text=f'''[[relay]]
name = "bench-{listen}"
listen = "127.0.0.1:{listen}"
upstream = "127.0.0.1:{upstream}"
allow = ["{allow}"]
max_connections = 32
backlog = 64
connect_timeout_seconds = 1
eof_grace_seconds = 1
verbose_payload_logging = false
pid_file = "{ROOT}/{prefix}.lock"
[relay.client_keepalive]
enabled = true
idle_seconds = 60
interval_seconds = 15
count = 8
[relay.upstream_keepalive]
enabled = true
idle_seconds = 60
interval_seconds = 15
count = 8
'''
        if mode!='tcp':text+=f'''\n[relay.outbound_tls]
mode = "tls"
ca_file = "{ROOT}/pki/server.pem"
server_name = "{hostname}"
handshake_timeout_seconds = 2
'''
        config.write_text(text)
        command=[RUST,'--config',config,'--relay',f'bench-{listen}']
    else:
        left=f'TCP4-LISTEN:{listen},bind=127.0.0.1,reuseaddr,fork,max-children=32,backlog=64,range={allow},keepalive,keepidle=60,keepintvl=15,keepcnt=8'
        if mode=='tcp':right=f'TCP4:127.0.0.1:{upstream},connect-timeout=1,forever,interval=1,keepalive,keepidle=60,keepintvl=15,keepcnt=8'
        else:
            version='TLS1.2' if mode=='tls12' else 'TLS1.3'
            right=f'OPENSSL:127.0.0.1:{upstream},verify=1,cafile={ROOT}/pki/server.pem,cn={hostname},snihost={hostname},min-version={version},max-version={version},connect-timeout=1'
        command=[SOCAT,'-t','1','-b','16384',left,right]
    process=spawn(command,prefix);wait_listener(listen,process)
    return process,listen


async def backend(ready,mode):
    seen=set()
    async def echo(reader,writer):
        try:
            tls=writer.get_extra_info('ssl_object')
            if tls:
                negotiated=(tls.version(),tls.cipher()[0])
                if negotiated not in seen:seen.add(negotiated);print('NEGOTIATED',*negotiated,flush=True)
            while data:=await reader.read(65536):
                writer.write(data);await writer.drain()
        except (OSError,ConnectionError):pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):await writer.wait_closed()
    context=None
    if mode!='tcp':
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT/'pki/server.pem',ROOT/'pki/server.key')
        version=ssl.TLSVersion.TLSv1_2 if mode=='tls12' else ssl.TLSVersion.TLSv1_3
        context.minimum_version=context.maximum_version=version
        if mode=='tls12':context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    server=await asyncio.start_server(echo,'127.0.0.1',0,ssl=context,backlog=128)
    ready.write_text(json.dumps({'port':server.sockets[0].getsockname()[1]}))
    async with server:await server.serve_forever()


def start_backend(mode):
    ready=ROOT/f'backend-{mode}-{os.getpid()}.json'
    assert not ready.exists()
    process=spawn([sys.executable,__file__,'backend',str(ready),mode],f'backend-{mode}')
    until=time.monotonic()+10
    while not ready.exists():
        if process.poll() is not None:raise RuntimeError('backend startup failed')
        if time.monotonic()>until:raise TimeoutError('backend ready')
        time.sleep(.02)
    return process,json.loads(ready.read_text())['port']


def functional(implementation,upstream,mode):
    process,p=start_relay(implementation,upstream,mode,'functional')
    checks=[]
    try:
        with connect(p) as s:
            payload=bytes(range(256))*256;s.sendall(payload);assert receive(s,len(payload))==payload
            s.shutdown(socket.SHUT_WR);assert s.recv(1)==b''
        checks.append('binary payload / half-close / EOF')
        sockets=[connect(p) for _ in range(32)]
        try:
            for s in sockets:s.sendall(b'hold');assert receive(s,4)==b'hold'
            time.sleep(.1);memory=usage(process.pid,pss=True)
            extra=connect(p);extra.settimeout(.25);extra.sendall(b'queued')
            status='queued'
            try:
                got=extra.recv(6)
                if got:
                    assert got==b'queued'
                    status='extra_admitted'
                else:status='rejected'
            except socket.timeout:pass
            sockets.pop().close()
            if status=='queued':
                extra.settimeout(5);assert receive(extra,6)==b'queued'
            elif status=='rejected':
                time.sleep(.2)
                with connect(p) as recovered:recovered.sendall(b'free');assert receive(recovered,4)==b'free'
            extra.close()
            checks.append('32-session limit: '+status+'; slot recovery checked')
            print('CAPACITY',implementation,mode,status,json.dumps(memory),flush=True)
        finally:
            for s in sockets:s.close()
    finally:stop(process)
    rejected,rp=start_relay(implementation,upstream,mode,'acl',allow='127.0.0.2/32')
    try:
        with connect(rp) as s:
            s.sendall(b'deny');assert not s.recv(4)
        checks.append('source ACL denies localhost outside allowed range')
    except ConnectionResetError:checks.append('source ACL denies localhost outside allowed range')
    finally:stop(rejected)
    if mode!='tcp':
        rejected,rp=start_relay(implementation,upstream,mode,'wrong-san',hostname='wrong.invalid')
        try:
            with connect(rp) as s:s.sendall(b'deny');assert not s.recv(4)
            checks.append('wrong server identity rejected')
        except ConnectionResetError:checks.append('wrong server identity rejected')
        finally:stop(rejected)
    return {'implementation':implementation,'mode':mode,'checks':checks,'idle_32_connections':memory}


def workload(p,kind,pilot=False):
    start=time.perf_counter();latencies=[];payload_bytes=0
    if kind=='rtt128':
        payload=b'R'*128
        with connect(p) as s:
            for _ in range(30):s.sendall(payload);assert receive(s,len(payload))==payload
            for _ in range(100 if pilot else 1500):
                begin=time.perf_counter_ns();s.sendall(payload);assert receive(s,len(payload))==payload
                latencies.append((time.perf_counter_ns()-begin)/1000)
        payload_bytes=len(payload)*len(latencies)
    elif kind=='connect128':
        payload=b'C'*128
        for _ in range(5 if pilot else 150):
            begin=time.perf_counter_ns()
            with connect(p) as s:s.sendall(payload);assert receive(s,len(payload))==payload
            latencies.append((time.perf_counter_ns()-begin)/1000)
        payload_bytes=len(payload)*len(latencies)
    else:
        concurrency=1 if kind=='bulk1' else 16
        per_client=1 if pilot else (64 if concurrency==1 else 8)
        payload=bytes(range(256))*256
        barrier=threading.Barrier(concurrency)
        def transfer():
            with connect(p) as s:
                barrier.wait(timeout=8)
                count=per_client*16
                errors=[]
                def send_stream():
                    try:
                        for _ in range(count):s.sendall(payload)
                    except BaseException as error:errors.append(error)
                sender=threading.Thread(target=send_stream,daemon=True);sender.start()
                try:
                    for _ in range(count):assert receive(s,len(payload))==payload
                finally:
                    sender.join(timeout=10)
                assert not sender.is_alive() and not errors, errors
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            for result in pool.map(lambda _:transfer(),range(concurrency)):pass
        payload_bytes=concurrency*per_client*1048576
    elapsed=time.perf_counter()-start
    result={'wall_seconds':elapsed,'payload_bytes_one_direction':payload_bytes,'mib_s_one_direction':payload_bytes/1048576/elapsed}
    if latencies:result.update({'samples':len(latencies),'rtt_median_us':statistics.median(latencies),'rtt_p95_us':percentile(latencies,.95),'rtt_p99_us':percentile(latencies,.99)})
    return result


def main():
    pilot='--pilot' in sys.argv
    trials=1 if pilot else 3
    guard();output={'host':socket.gethostname(),'pilot':pilot,'scope':'loopback synthetic; total CPUQuota100% MemoryMax512M; no production endpoints',
                  'cpu_count':os.cpu_count(),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'functional':[],'measurements':[]}
    (ROOT/'pki').mkdir(exist_ok=True)
    for cmd in [[RUST,'pki','keygen','--out',ROOT/'pki/server.key'],[RUST,'pki','self-signed','--key',ROOT/'pki/server.key','--out',ROOT/'pki/server.pem','--cn','localhost','--dns','localhost','--ip','127.0.0.1','--usage','both','--days','1']]:
        subprocess.run([str(x) for x in cmd],check=True,capture_output=True,timeout=15)
    modes=['tcp'] if pilot and '--all-modes' not in sys.argv else ['tcp','tls12','tls13']
    for mode in modes:
        backend_process,upstream=start_backend(mode)
        try:
            for implementation in ['rust','socat']:
                output['functional'].append(functional(implementation,upstream,mode));print('FUNCTIONAL',mode,implementation,flush=True)
            for trial in range(trials):
                implementations=['rust','socat'] if trial%2==0 else ['socat','rust']
                if mode=='tcp':implementations=(['direct']+implementations if trial%2==0 else implementations+['direct'])
                for implementation in implementations:
                    guard();process=None
                    if implementation=='direct':p=upstream;pid=backend_process.pid
                    else:process,p=start_relay(implementation,upstream,mode,f'trial{trial}');pid=process.pid
                    try:
                        for kind in ['rtt128','connect128','bulk1','bulk16']:
                            guard();before=usage(pid);qbefore=quota_stat()
                            result=workload(p,kind,pilot)
                            time.sleep(.08)
                            after=usage(pid);qafter=quota_stat()
                            result.update({'implementation':implementation,'mode':mode,'trial':trial,'workload':kind,'cpu_seconds_relay_family':max(0,after['cpu_seconds']-before['cpu_seconds']),
                                           'cgroup_throttled_usec':qafter.get('throttled_usec',0)-qbefore.get('throttled_usec',0),'cgroup_nr_throttled':qafter.get('nr_throttled',0)-qbefore.get('nr_throttled',0)})
                            output['measurements'].append(result)
                            (ROOT/'results.partial.json').write_text(json.dumps(output,indent=2))
                            print('MEASURE',mode,trial,implementation,kind,round(result['wall_seconds'],3),flush=True)
                    finally:stop(process)
        finally:stop(backend_process)
    output['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    (ROOT/('pilot.json' if pilot else 'results.json')).write_text(json.dumps(output,indent=2)+'\n')
    print('COMPLETED',len(output['functional']),len(output['measurements']),flush=True)


if __name__=='__main__':
    try:
        if len(sys.argv)>1 and sys.argv[1]=='backend':asyncio.run(backend(Path(sys.argv[2]),sys.argv[3]))
        else:main()
    finally:
        for process in reversed(CREATED):stop(process)
