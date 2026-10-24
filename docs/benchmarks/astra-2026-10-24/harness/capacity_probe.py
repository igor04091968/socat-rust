import contextlib,json,os,signal,socket,socketserver,subprocess,threading,time
from pathlib import Path
ROOT=Path(__file__).parent
active=0
lock=threading.Lock()
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        global active
        with lock:active+=1
        try:
            while data:=self.request.recv(65536):self.request.sendall(data)
        except OSError:pass
        finally:
            with lock:active-=1
class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=True

def connect(port):return socket.create_connection(('127.0.0.1',port),timeout=3)
def unused():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def sample(implementation,limit,warm,upstream):
    listener=unused();name=f'capacity-{implementation}-{limit}-{warm}'
    if implementation=='rust':
        cfg=ROOT/(name+'.toml')
        cfg.write_text(f'[[relay]]\nname="{name}"\nlisten="127.0.0.1:{listener}"\nupstream="127.0.0.1:{upstream}"\nmax_connections={limit}\nbacklog=64\nverbose_payload_logging=false\neof_grace_seconds=1\npid_file="{ROOT}/{name}.lock"\n')
        args=['/usr/local/sbin/socat-rust','--config',str(cfg),'--relay',name]
    else:args=['/usr/bin/socat','-t','1','TCP4-LISTEN:'+str(listener)+',bind=127.0.0.1,reuseaddr,fork,max-children='+str(limit),'TCP4:127.0.0.1:'+str(upstream)]
    with (ROOT/(name+'.log')).open('wb') as log:
        process=subprocess.Popen(args,stdout=log,stderr=log,start_new_session=True,env={**os.environ,'RUST_LOG':'warn'})
    clients=[]
    try:
        until=time.monotonic()+5
        while not any(line.split()[1]==f'0100007F:{listener:04X}' and line.split()[3]=='0A' for line in Path('/proc/net/tcp').read_text().splitlines()[1:]):
            assert process.poll() is None
            if time.monotonic()>until:raise TimeoutError('listener')
            time.sleep(.02)
        if warm:
            with connect(listener) as s:s.sendall(b'warm');assert s.recv(4)==b'warm';s.shutdown(socket.SHUT_WR);assert s.recv(1)==b''
        for _ in range(limit):
            s=connect(listener);s.sendall(b'held');assert s.recv(4)==b'held';clients.append(s)
        time.sleep(.1)
        with lock:before=active
        statuses=[]
        for _ in range(3):
            s=connect(listener);clients.append(s);s.settimeout(.2);s.sendall(b'EXTRA')
            try:statuses.append('admitted' if s.recv(5)==b'EXTRA' else 'closed')
            except socket.timeout:statuses.append('queued')
            except ConnectionResetError:statuses.append('closed')
        with lock:after=active
        return {'implementation':implementation,'configured_limit':limit,'warm_half_close':warm,'backend_sessions_before':before,'backend_sessions_after':after,'three_extra_connections':statuses}
    finally:
        for s in clients:s.close()
        time.sleep(.1)
        with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGKILL)
            process.wait(3)

server=Server(('127.0.0.1',0),Echo);threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    results=[]
    for implementation in ['rust','socat']:
        for limit in [1,2,32]:
            for warm in [False,True]:
                result=sample(implementation,limit,warm,server.server_address[1]);results.append(result);print(json.dumps(result),flush=True)
    (ROOT/'capacity.json').write_text(json.dumps(results,indent=2)+'\n')
finally:server.shutdown();server.server_close()
# Probe configured system socat GOST support without changing OpenSSL configuration.
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0));listener.listen(4)
    command=['/usr/bin/socat','-u','/dev/null',f'OPENSSL:127.0.0.1:{listener.getsockname()[1]},verify=0,ciphers=GOST2012-KUZNYECHIK-KUZNYECHIKOMAC,connect-timeout=1']
    try:
        result=subprocess.run(command,capture_output=True,timeout=3)
        capability={'command':command,'returncode':result.returncode,'stderr':result.stderr.decode(errors='replace')}
    except subprocess.TimeoutExpired as error:capability={'command':command,'timeout':True,'stderr':(error.stderr or b'').decode(errors='replace')}
    (ROOT/'socat-gost-capability.json').write_text(json.dumps(capability,indent=2)+'\n')
    print(json.dumps(capability),flush=True)
