"""Acquire public OSS afresh; never consult previous project folders."""
import hashlib,json,pathlib,urllib.request,datetime,time
ROOT=pathlib.Path(__file__).resolve().parents[3]
VENDOR=ROOT/'var/artifacts/vendor/2026-09-12'
SOURCES={
 'openssl-1.0.1f.tar.gz':('https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/OpenSSL_1_0_1f','OpenSSL 1.0.1f','OpenSSL/SSLeay'),
 'zlib-1.2.12.tar.gz':('https://zlib.net/fossils/zlib-1.2.12.tar.gz','zlib 1.2.12','Zlib'),
 'zlib-1.2.13.tar.gz':('https://zlib.net/fossils/zlib-1.2.13.tar.gz','zlib 1.2.13','Zlib'),
 'curl-8.3.0.tar.xz':('https://curl.se/download/curl-8.3.0.tar.xz','curl 8.3.0','curl'),
 'curl-socks5.patch':('https://github.com/curl/curl/commit/fb4415d8aee6c1.patch','curl official SOCKS5 fix','curl'),
}
def fetch_all():
 VENDOR.mkdir(parents=True,exist_ok=True)
 lock_path=ROOT/'tools/demo-data/upstream-lock.json'
 locked=json.loads(lock_path.read_text()) if lock_path.exists() else {}
 for name,(url,version,license_name) in SOURCES.items():
  dst=VENDOR/name; receipt=VENDOR/(name+'.receipt.json')
  if dst.exists() and receipt.exists():
   meta=json.loads(receipt.read_text())
   actual_hash=hashlib.sha256(dst.read_bytes()).hexdigest()
   if (name in locked and actual_hash!=locked[name]['sha256']) or actual_hash!=meta['sha256']: raise ValueError('Changed downloaded source: '+name)
   continue
  for attempt in range(3):
   try:
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'CVEvidence-Hackathon/1.0'}),timeout=90) as r: content=r.read(); final_url=r.url
    break
   except Exception:
    if attempt==2: raise
    time.sleep(1)
  if name in locked and hashlib.sha256(content).hexdigest()!=locked[name]['sha256']:raise ValueError('Upstream source differs from reviewed lock: '+name)
  dst.write_bytes(content)
  meta={'requested_url':url,'resolved_url':final_url,'version':version,'license':license_name,'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content),'acquired_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'origin':'fresh official upstream download'}
  receipt.write_text(json.dumps(meta,indent=2)+'\n')
  print(name,meta['sha256'],len(content),flush=True)
if __name__=='__main__':fetch_all()
