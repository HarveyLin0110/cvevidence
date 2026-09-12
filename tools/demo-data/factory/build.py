"""Fresh demo factory. Build-time execution only; never imported by analyzer."""
import argparse,datetime,hashlib,json,os,pathlib,shutil,subprocess,tarfile,uuid,sys,zlib,struct
from fetch import ROOT,VENDOR,fetch_all
HERE=pathlib.Path(__file__).resolve().parent
CC=HERE/'cc_capture.py'
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def write(p,v):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def extract(name,dest):
 dest.mkdir(parents=True,exist_ok=False)
 with tarfile.open(VENDOR/name) as tar:
  members=tar.getmembers();prefix=members[0].name.split('/')[0]
  for m in members:
   rel=pathlib.PurePosixPath(m.name).relative_to(prefix)
   if not str(rel) or str(rel)=='.':continue
   if '..' in rel.parts or rel.is_absolute():raise ValueError('Invalid upstream archive path')
   target=dest/rel
   if m.isdir():target.mkdir(parents=True,exist_ok=True)
   elif m.isfile():target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(tar.extractfile(m).read());target.chmod(m.mode&0o777)
   elif m.issym():
    target.parent.mkdir(parents=True,exist_ok=True)
    if not (target.parent/m.linkname).resolve().is_relative_to(dest.resolve()):raise ValueError('External upstream symlink')
    target.symlink_to(m.linkname)
   else:raise ValueError('Unsupported upstream entry')
def run(root,args,cwd=None,extra=None,expected=0,label=None):
 logs=root/'build/commands';logs.mkdir(parents=True,exist_ok=True)
 token=f'{len(list(logs.glob("*.json"))):04d}-{label or pathlib.Path(str(args[0])).name}'
 logfile=logs/(token+'.log');env=os.environ.copy();env['CVEVIDENCE_BUILD_ROOT']=str(root)
 if extra:env.update(extra)
 started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with logfile.open('wb') as out:
  result=subprocess.run([str(x) for x in args],cwd=cwd or root,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=900)
 write(logs/(token+'.json'),{'argv':[str(x) for x in args],'cwd':str(cwd or root),'started_at':started,'returncode':result.returncode,'expected_returncode':expected,'log':logfile.relative_to(root).as_posix(),'log_sha256':sha(logfile)})
 if result.returncode!=expected:
  print(logfile.read_text(errors='replace')[-8000:],flush=True);raise RuntimeError(f'Command failed: {args}; log={logfile}')
 return logfile

def init(family):
 build_id=family+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:6]
 root=ROOT/'var/build'/build_id/'package';root.mkdir(parents=True)
 for sub in ['source','build','product','provenance','observations']: (root/sub).mkdir()
 for p in VENDOR.glob('*.receipt.json'):shutil.copy2(p,root/'provenance'/p.name)
 run(root,['gcc','--version'],label='compiler-version')
 return root,build_id

def finish(root,build_id,family,components,artifact):
 build={'schema_version':'1.0','build_id':build_id,'product_id':'fresh-'+family,'release_id':build_id,'format':family,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'primary_artifact':{'path':artifact,'sha256':sha(root/artifact)},'components':components,'scope':{'description':'Entire generated demo product and its delivered libraries; Linux x86_64 only','deployed_exposure_assessed':False},'build_root':str(root)}
 write(root/'build/build-record.json',build)
 run(root,['readelf','-d',root/('product/device-management' if family=='rom' else 'product/update-reader')],label='product-dynamic')
 print('BUILD COMPLETE',root,flush=True)
 from metadata import finalize
 finalize(root)
 write(root.parent/'completed.json',{'build_id':build_id,'package':str(root),'format':family,'artifact_sha256':sha(root/artifact)})
 return root

def openssl(root,disabled):
 src=root/'source/openssl';extract('openssl-1.0.1f.tar.gz',src)
 flags=['shared','no-asm',f'--prefix={root/"sdk"}',f'--openssldir={root/"sdk/ssl"}']
 if disabled:flags+=['-DOPENSSL_NO_HEARTBEATS']
 run(root,['perl','Configure','linux-x86_64',*flags],cwd=src,label='openssl-configure')
 run(root,['make','-j2',f'CC={CC}','build_libs'],cwd=src,label='openssl-build')
 sdk=root/'sdk';(sdk/'lib').mkdir(parents=True,exist_ok=True);(sdk/'include/openssl').mkdir(parents=True,exist_ok=True)
 for p in (src/'include/openssl').glob('*.h'):shutil.copy2(p,sdk/'include/openssl'/p.name)
 for n in ['libssl.so.1.0.0','libcrypto.so.1.0.0']:
  shutil.copy2(src/n,sdk/'lib'/n);(sdk/'lib'/n.split('.so')[0]).with_suffix('.so').symlink_to(n)
 for file in ['ssl/t1_lib.c','ssl/s3_pkt.c']:
  run(root,[CC,'-E','-I.','-Iinclude',*(['-DOPENSSL_NO_HEARTBEATS'] if disabled else []),file,'-o',str(root/'build'/(pathlib.Path(file).stem+'.i'))],cwd=src,label='preprocess-'+pathlib.Path(file).stem)
 return {'name':'openssl','version':'1.0.1f','source_root':'source/openssl','libraries':['sdk/lib/libssl.so.1.0.0','sdk/lib/libcrypto.so.1.0.0'],'license_file':'source/openssl/LICENSE'}

def zlib_build(root,version,shared):
 src=root/'source/zlib';extract('zlib-'+version+'.tar.gz',src)
 env={'CC':str(CC)}
 run(root,['./configure',f'--prefix={root/"sdk"}',*(['--static'] if not shared else [])],cwd=src,extra=env,label='zlib-configure')
 run(root,['make','-j2'],cwd=src,extra=env,label='zlib-build')
 run(root,['make','install'],cwd=src,extra=env,label='zlib-install')
 return {'name':'zlib','version':version,'source_root':'source/zlib','libraries':['sdk/lib/libz.so.'+version] if shared else ['sdk/lib/libz.a'],'license_file':'source/zlib/README'}

def rom(disabled):
 root,bid=init('rom');comp=openssl(root,disabled);zc=zlib_build(root,'1.2.13',True)
 shutil.copy2(HERE/'device.c',root/'source/device.c')
 run(root,[CC,'-O0','-g','-I'+str(root/'sdk/include'),'-c',root/'source/device.c','-o',root/'build/device.o'],label='device-compile')
 run(root,[CC,root/'build/device.o','-L'+str(root/'sdk/lib'),'-Wl,-rpath,$ORIGIN/../lib','-Wl,-Map,'+str(root/'build/product.map'),'-lssl','-lcrypto','-lz','-ldl','-o',root/'product/device-management'],label='device-link')
 romroot=root/'rom-root';(romroot/'bin').mkdir(parents=True);(romroot/'lib').mkdir();(romroot/'etc').mkdir()
 shutil.copy2(root/'product/device-management',romroot/'bin/device-management')
 for p in (root/'sdk/lib').glob('*.so*'):
  if p.is_symlink():(romroot/'lib'/p.name).symlink_to(os.readlink(p))
  else:shutil.copy2(p,romroot/'lib'/p.name)
 (romroot/'etc/device.conf').write_text('product=fresh-device\nsettings_backup=zlib\ntransport=TLSv1.2\n')
 run(root,['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'observations/key.pem','-out',root/'observations/cert.pem','-days','1','-subj','/CN=localhost-demo-only'],label='local-test-certificate')
 (root/'images').mkdir()
 run(root,['mksquashfs',romroot,root/'images/device.rom','-noappend','-all-root','-processors','2'],label='pack-squashfs')
 unpack=root/'unpacked';run(root,['unsquashfs','-d',unpack,root/'images/device.rom'],label='unpack-squashfs')
 comparisons=[]
 for p in romroot.rglob('*'):
  if p.is_file() and not p.is_symlink():
   q=unpack/p.relative_to(romroot);assert sha(p)==sha(q);comparisons.append({'packed_path':p.relative_to(root).as_posix(),'unpacked_path':q.relative_to(root).as_posix(),'sha256':sha(p)})
 write(root/'observations/rom-comparison.json',comparisons)
 run(root,[unpack/'bin/device-management',root/'observations/cert.pem',root/'observations/key.pem'],label='extracted-device-normal-run')
 run(root,[sys.executable,HERE/'tcp_smoke.py',unpack/'bin/device-management',root/'observations/cert.pem',root/'observations/key.pem'],label='extracted-device-tcp-normal-run')
 return finish(root,bid,'rom',[comp,zc],'images/device.rom')

def cmake(version):
 root,bid=init('cmake');extract('zlib-'+version+'.tar.gz',root/'source/zlib');shutil.copy2(HERE/'update_reader.c',root/'source/update_reader.c')
 (root/'source/CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.16)
project(FreshUpdate C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_subdirectory(zlib)
add_executable(update-reader update_reader.c)
target_include_directories(update-reader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/zlib ${CMAKE_CURRENT_BINARY_DIR}/zlib)
target_link_libraries(update-reader PRIVATE zlibstatic)
target_link_options(update-reader PRIVATE "-Wl,-Map,${CMAKE_CURRENT_BINARY_DIR}/product.map")
''')
 run(root,['cmake','-S',root/'source','-B',root/'build/cmake','-DCMAKE_C_COMPILER='+str(CC),'-DCMAKE_BUILD_TYPE=Debug'],label='cmake-configure')
 run(root,['cmake','--build',root/'build/cmake','--target','update-reader','-j','2','--verbose'],label='cmake-build')
 shutil.copy2(root/'build/cmake/update-reader',root/'product/update-reader')
 shutil.copy2(root/'build/cmake/product.map',root/'build/product.map')
 (root/'samples').mkdir();payload=b'firmware update content\n'*10;extra=b'AB'+struct.pack('<H',12)+b'normal-extra';compressor=zlib.compressobj(wbits=-15)
 data=b'\x1f\x8b\x08\x04'+b'\x00'*4+b'\x00\xff'+struct.pack('<H',len(extra))+extra+compressor.compress(payload)+compressor.flush()+struct.pack('<II',zlib.crc32(payload),len(payload))
 (root/'samples/normal.gz').write_bytes(data);(root/'samples/truncated.gz').write_bytes(data[:-6])
 run(root,[root/'product/update-reader',root/'samples/normal.gz'],label='normal-update')
 run(root,[root/'product/update-reader',root/'samples/truncated.gz'],expected=2,label='truncated-update')
 return finish(root,bid,'cmake',[{'name':'zlib','version':version,'source_root':'source/zlib','libraries':['build/cmake/zlib/libz.a'],'license_file':'source/zlib/README'}],'product/update-reader')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('family',choices=['rom-on','rom-off','cmake-old','cmake-fixed']);a=p.parse_args();fetch_all()
 {'rom-on':lambda:rom(False),'rom-off':lambda:rom(True),'cmake-old':lambda:cmake('1.2.12'),'cmake-fixed':lambda:cmake('1.2.13')}[a.family]()
