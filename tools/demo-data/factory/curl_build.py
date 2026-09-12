"""Real curl build and benign loopback SOCKS5/HTTP observation."""
import argparse,contextlib,http.server,json,os,pathlib,shutil,socket,socketserver,threading,time
from build import ROOT,VENDOR,HERE,CC,extract,init,run,write,sha
from fetch import fetch_all
class Http(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'fresh update payload\n';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
class Socks(socketserver.BaseRequestHandler):
 def recv_exact(self,n):
  result=b''
  while len(result)<n:
   part=self.request.recv(n-len(result))
   if not part:raise ConnectionError('Client closed')
   result+=part
  return result
 def handle(self):
  self.request.settimeout(10);started=time.monotonic()
  header=self.recv_exact(2);methods=self.recv_exact(header[1]);time.sleep(0.15);self.request.sendall(b'\x05\x00')
  head=self.recv_exact(4)
  if head!=b'\x05\x01\x00\x03':raise ValueError('Expected remote hostname request')
  length=self.recv_exact(1)[0];hostname=self.recv_exact(length).decode('ascii');port=int.from_bytes(self.recv_exact(2),'big')
  if hostname!='demo.test' or port!=self.server.http_port:raise ValueError('Only benign local test destination allowed')
  self.server.events.append({'event':'socks5_connect','atyp':3,'requested_hostname':hostname,'hostname_length':length,'port':port,'greeting_delay_seconds':0.15,'elapsed_seconds':time.monotonic()-started})
  with socket.create_connection(('127.0.0.1',self.server.http_port),timeout=10) as dest:
   self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
   request=b''
   while b'\r\n\r\n' not in request:request+=self.request.recv(4096)
   dest.sendall(request)
   while True:
    part=dest.recv(4096)
    if not part:break
    self.request.sendall(part)
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True

def build_curl(patched):
 root,bid=init('curl');src=root/'source/curl';extract('curl-8.3.0.tar.xz',src)
 (root/'patches').mkdir();shutil.copy2(VENDOR/'curl-socks5.patch',root/'patches/curl-socks5.patch')
 if patched:
  patch_text=(root/'patches/curl-socks5.patch').read_text()
  marker='diff --git a/lib/socks.c b/lib/socks.c'
  code_patch=marker+patch_text.split(marker,1)[1].split('diff --git ',1)[0]
  (root/'patches/curl-socks5-code.patch').write_text(code_patch)
  write(root/'patches/selection.json',{'upstream_patch_sha256':sha(root/'patches/curl-socks5.patch'),'selected_file':'lib/socks.c','selected_patch_sha256':sha(root/'patches/curl-socks5-code.patch'),'reason':'Upstream test-list context differs from 8.3.0 release; apply the exact official product-code hunk only.'})
  run(root,['patch','-p1','--forward','--batch','-i',root/'patches/curl-socks5-code.patch'],cwd=src,label='official-patch')
 install=root/'install';env={'CC':str(CC),'CFLAGS':'-O0 -g'}
 run(root,['./configure',f'--prefix={install}','--enable-shared','--disable-static','--without-ssl','--without-libidn2','--without-libpsl','--without-zstd','--without-brotli','--without-nghttp2','--disable-ldap','--disable-ldaps'],cwd=src,extra=env,label='curl-configure')
 run(root,['make','-j2'],cwd=src,extra=env,label='curl-build')
 run(root,['make','install'],cwd=src,extra=env,label='curl-install')
 return complete_curl(root,bid)

def complete_curl(root,bid):
 install=root/'install'
 (install/'etc').mkdir(exist_ok=True)
 launcher=install/'download-update.sh'
 launcher.write_text('''#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -ne 1 ]; then echo 'usage: download-update.sh URL' >&2; exit 64; fi
export LD_LIBRARY_PATH="$base/lib"
exec "$base/bin/curl" --config "$base/etc/download.conf" --url "$1"
''');launcher.chmod(0o755)
 with http.server.ThreadingHTTPServer(('127.0.0.1',0),Http) as httpd, Server(('127.0.0.1',0),Socks) as socks:
  socks.http_port=httpd.server_port;socks.events=[]
  (install/'etc/download.conf').write_text(f'socks5-hostname = "127.0.0.1:{socks.server_address[1]}"\nlimit-rate = 16384\nnoproxy = ""\nlocation\nfail\nsilent\nshow-error\nmax-time = 10\n')
  threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in [httpd,socks]]
  for t in threads:t.start()
  try:
   run(root,[launcher,f'http://demo.test:{httpd.server_port}/update.bin'],label='normal-socks5-download')
   if not socks.events:raise RuntimeError('No real SOCKS observation')
   write(root/'observations/socks5.json',{'events':socks.events,'test_kind':'benign normal download; no long hostname or overflow execution','product_sha256':sha(install/'bin/curl'),'library_sha256':sha(install/'lib/libcurl.so.4.8.0')})
  finally:
   httpd.shutdown();socks.shutdown()
   for t in threads:t.join(timeout=3)
 run(root,[install/'bin/curl','--version'],extra={'LD_LIBRARY_PATH':str(install/'lib')},label='curl-version')
 run(root,['readelf','-d',install/'bin/curl'],label='curl-dynamic')
 run(root,['readelf','-d',install/'lib/libcurl.so.4.8.0'],label='libcurl-dynamic')
 record={'schema_version':'1.0','build_id':bid,'product_id':'fresh-curl','release_id':bid,'format':'curl','build_root':str(root),'primary_artifact':{'path':'install/bin/curl','sha256':sha(install/'bin/curl')},'components':[{'name':'curl','version':'8.3.0','source_root':'source/curl','libraries':['install/lib/libcurl.so.4.8.0'],'license_file':'source/curl/COPYING'}],'scope':{'description':'Delivered curl executable, matching libcurl, launcher/config; HTTP and SOCKS5 enabled, TLS intentionally not built; system zlib is outside the curl CVE profile','deployed_exposure_assessed':False}}
 write(root/'build/build-record.json',record)
 from metadata import finalize
 finalize(root)
 write(root.parent/'completed.json',{'build_id':bid,'package':str(root),'format':'curl','artifact_sha256':sha(install/'bin/curl')})
 print('BUILD COMPLETE',root,flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--patched',action='store_true');a=p.parse_args();fetch_all();build_curl(a.patched)
