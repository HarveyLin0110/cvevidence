"""Derive SBOM metadata after build, checking delivered headers and libraries."""
import json,pathlib,re,uuid
from build import ROOT,write,sha

def finalize(root):
 record=json.loads((root/'build/build-record.json').read_text());components=[]
 for component in record['components']:
  name=component['name'];source=root/component['source_root']
  header={'openssl':source/'crypto/opensslv.h','zlib':source/'zlib.h','curl':source/'include/curl/curlver.h'}[name]
  pattern={'openssl':r'OPENSSL_VERSION_TEXT\s+"OpenSSL\s+([^ ]+)','zlib':r'ZLIB_VERSION\s+"([^"]+)','curl':r'LIBCURL_VERSION\s+"([^"]+)'}[name]
  versions=re.findall(pattern,header.read_text())
  if component['version'] not in versions:raise ValueError('Source header version mismatch')
  libraries=[{'path':p,'sha256':sha(root/p)} for p in component['libraries']]
  components.append({'type':'library','name':name,'version':component['version'],'bom-ref':name+'@'+component['version'],'properties':[{'name':'cvevidence:source_header','value':header.relative_to(root).as_posix()},{'name':'cvevidence:source_header_sha256','value':sha(header)},{'name':'cvevidence:delivered_libraries','value':json.dumps(libraries,sort_keys=True)}]})
 sbom={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'component':{'type':'application','name':record['product_id'],'version':record['release_id']},'properties':[{'name':'cvevidence:scope','value':'Recorded demo libraries only; does not claim a complete system dependency inventory.'},{'name':'cvevidence:artifact_sha256','value':record['primary_artifact']['sha256']}]},'components':components}
 write(root/'sbom.cdx.json',sbom)
 return {'build_id':record['build_id'],'component_count':len(components)}
if __name__=='__main__':
 for completed in sorted((ROOT/'var/build').glob('*/completed.json')):
  root=pathlib.Path(json.loads(completed.read_text())['package'])
  if (root/'sbom.cdx.json').exists():continue
  print(finalize(root))
