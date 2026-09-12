"""Benign loopback-only normal TLS test of the freshly extracted ROM program."""
import pathlib,re,selectors,subprocess,sys,time
binary,cert,key=sys.argv[1:]
server=subprocess.Popen([binary,'--serve','0',cert,key],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
try:
 selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ)
 if not selector.select(10):raise RuntimeError('Server did not announce a port')
 first=server.stdout.readline();print(first,end='',flush=True);match=re.search(r'listening_port=(\d+)',first)
 if not match:raise RuntimeError('Invalid server startup')
 client=subprocess.run([binary,'--client',match.group(1)],capture_output=True,text=True,timeout=10)
 print(client.stdout,end='',flush=True);print(client.stderr,end='',file=sys.stderr)
 output,_=server.communicate(timeout=10);print(output,end='',flush=True)
 if client.returncode or server.returncode:raise RuntimeError('Normal TCP TLS test failed')
 print('normal_tcp_tls=ok no_attack_payload=true',flush=True)
finally:
 if server.poll() is None:server.terminate();server.wait(timeout=5)
