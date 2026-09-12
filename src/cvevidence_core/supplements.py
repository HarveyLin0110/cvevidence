"""Pure supplement semantics; snapshot persistence belongs to Frankie's Runner."""
from __future__ import annotations
import json,pathlib
from .integrity import InputPackage,IntegrityError,scan,digest

def validate_supplement(context:InputPackage,path:str|pathlib.Path)->dict:
 context.assert_current();root=pathlib.Path(path).resolve()
 try:manifest=json.loads((root/'manifest.json').read_text())
 except (OSError,ValueError) as e:raise IntegrityError('Invalid supplement manifest') from e
 if manifest.get('schema_version')!='1.0' or manifest.get('kind')!='supplement':raise IntegrityError('Unsupported supplement schema')
 files=scan(root)
 if manifest.get('files')!=files:raise IntegrityError('Supplement inventory or hash mismatch')
 for field in ['product_id','release_id','build_id','format','primary_artifact']:
  if manifest.get(field)!=context.manifest.get(field):
   return {'status':'DIFFERENT_BUILD','reason':'Identity differs: '+field,'can_merge':False,'requires_new_release':True,'source_context_hash':context.context_hash}
 if manifest.get('base_package_id')!=context.manifest['package_id']:raise IntegrityError('Supplement targets a different package')
 original={r['path']:r for r in context.manifest['files']};added=[];duplicates=[]
 for row in files:
  if row['path'] in original:
   if row!=original[row['path']]:raise IntegrityError('Conflicting replacement in same-build supplement: '+row['path'])
   duplicates.append(row['path'])
  else:added.append(row)
 return {'status':'READY_FOR_NEW_SNAPSHOT','can_merge':True,'requires_new_release':False,'source_context_hash':context.context_hash,'supplement_hash':digest(manifest),'added_files':added,'identical_duplicates':duplicates,'primary_artifact':context.manifest['primary_artifact'],'instructions':'Runner must create a new immutable snapshot and run, retain parent_run_id, then re-ingest, collect, verify and assess. This validation itself is not an assessment.'}

def interpret_statement(text:str,source_context_hash:str)->dict:
 if not isinstance(text,str) or not text.strip() or len(text)>16000:raise ValueError('Statement must contain 1 to 16000 characters')
 value={'text':text,'source_context_hash':source_context_hash,'kind':'USER_STATEMENT','verified_engineering_fact':False}
 return {'material_id':'M-'+digest(value)[:24],**value,'review_required':True,'effect':'Investigation context only; do not change formal conditions without verified original evidence.'}


def statement_parts(text:str,format:str)->list[dict]:
 """Bounded, deterministic triage of complete clauses, never engineering proof.

 Unknown wording stays reviewable. In particular, a recognized word inside a
 longer correction must not hide its unparsed scope, negation or qualification.
 """
 import re,unicodedata
 text=unicodedata.normalize('NFKC',text)
 clauses=re.split(r'[。!?！？;；\n,，]+|\.(?=\s|$)',text)
 neutral=(
  r'(?:已|我已|我們已)(?:提供|上傳|附上|補上)(?:(?:這次|本次|此次)(?:使用)?的|同\s*build\s*的?)?(?:檔案|文件|資料|工程資料|附件|補件|證據)',
  r'請(?:協助)?(?:查核|核對|分析|重新分析|覆核)(?:這些檔案|附件|所附檔案|本次資料)?',
  r'(?:i have |we have )?(?:uploaded|provided|attached) (?:the )?files(?: for this build)?',
  r'please (?:review|check|analyze|analyse)(?: (?:the )?(?:attached files|files|attachments))?',
  r'(?:謝謝|感謝|thanks|thank you)',
 )
 keys='build_identity|component|library_binding|product_binding|scope_complete|vulnerable_implementation|entry_reachable|trigger_prerequisites'
 patterns=[
  ('vulnerable_implementation',False,r'(?:受影響實作|漏洞實作)(?:已)?(?:排除|移除|修補)'),
  ('vulnerable_implementation',True,r'(?:受影響實作|漏洞實作)(?:仍然|仍|確實)?存在'),
  ('entry_reachable',True,r'外部輸入可(?:以)?進入(?:相關)?程式路徑'),
  ('entry_reachable',False,r'外部輸入(?:無法|不能|不可)進入(?:相關)?程式路徑'),
  ('trigger_prerequisites',True,r'(?:漏洞)?觸發(?:必要|所需)?條件(?:均|皆|都)?成立'),
  ('trigger_prerequisites',False,r'(?:漏洞)?觸發(?:必要|所需)?條件不成立'),
 ]
 if format=='rom':
  patterns += [
   ('vulnerable_implementation',False,r'(?:已(?:停用|關閉)\s*heartbeats?|heartbeats?\s*(?:已)?(?:停用|關閉|disabled)|openssl_no_heartbeats\s*(?:已設定|已啟用))'),
   ('vulnerable_implementation',True,r'(?:已啟用\s*heartbeats?|heartbeats?\s*(?:仍|已)?(?:啟用|enabled))'),
  ]
 result=[]
 for raw in clauses:
  clause=raw.strip()
  if not clause:continue
  if any(re.fullmatch(p,clause,re.IGNORECASE) for p in neutral):
   result.append({'text':clause,'kind':'OPERATIONAL_CONTEXT'});continue
  claim=re.sub(r'^(?:供應商|工程師)(?:說|表示)\s*','',clause)
  explicit=re.fullmatch(r'('+keys+r')\s*(?:=|:|為)\s*(true|false|supported|blocked)',claim,re.IGNORECASE)
  if explicit:
   result.append({'text':clause,'kind':'CONDITION_CLAIM','condition_id':explicit[1].lower(),'claimed_value':explicit[2].lower() in ('true','supported')});continue
  matched=False
  for key,value,pattern in patterns:
   if re.fullmatch(pattern,claim,re.IGNORECASE):
    result.append({'text':clause,'kind':'CONDITION_CLAIM','condition_id':key,'claimed_value':value});matched=True;break
  if matched:continue
  artifact=re.fullmatch(r'(?:另有|還有|範圍包含)(?:交付)?(?:成品|執行檔)\s*[`「"]?([A-Za-z0-9_./+-]+)[`」"]?',claim)
  if artifact:
   result.append({'text':clause,'kind':'ARTIFACT_SCOPE','path':artifact[1]});continue
  new_scope=re.search(r'(?:另|還有|新增|未涵蓋|未提供|未交付|漏|another|additional|uncovered)',claim,re.IGNORECASE) and re.search(r'(?:入口|成品|執行檔|路徑|服務|entry|artifact|path|service)',claim,re.IGNORECASE)
  result.append({'text':clause,'kind':'UNRESOLVED_SCOPE' if new_scope else 'UNCLASSIFIED_STATEMENT'})
 return result or [{'text':text,'kind':'UNCLASSIFIED_STATEMENT'}]
