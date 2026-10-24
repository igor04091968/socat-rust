import importlib.util,json,socket,sys,time,shutil
from pathlib import Path
root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bench',root.parent/'clean/benchmark.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.ROOT=root
shutil.copytree(root.parent/'clean/pki',root/'pki')
results=[]
try:
 for mode in ['tcp','tls12','tls13']:
  backend,upstream=m.start_backend(mode)
  try:
   for implementation in ['rust','socat']:
    relay,port=m.start_relay(implementation,upstream,mode,'memory')
    clients=[]
    try:
     for _ in range(32):
      s=m.connect(port);clients.append(s);s.sendall(b'held');assert m.receive(s,4)==b'held'
     time.sleep(.2)
     row=m.usage(relay.pid,pss=True);row['private_mib']=0
     for pid,_ in m.family(relay.pid):
      for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
       if line.startswith(('Private_Clean:','Private_Dirty:')):row['private_mib']+=int(line.split()[1])/1024
     row.update({'mode':mode,'implementation':implementation});results.append(row);print(json.dumps(row),flush=True)
    finally:
     for s in clients:s.close()
     m.stop(relay)
  finally:m.stop(backend)
 (root/'memory.json').write_text(json.dumps(results,indent=2)+'\n')
finally:
 for p in reversed(m.CREATED):m.stop(p)
