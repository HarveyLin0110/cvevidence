"""Evidence identities bind extracted facts to their exact source witnesses."""
from __future__ import annotations
from dataclasses import dataclass
from .integrity import InputPackage,IntegrityError,digest
from .sources import read_excerpt

QUERY_IDS=('Q1_COMPONENT','Q2_BUILD','Q3_IMPLEMENTATION','Q4_BINDING','Q5_PATH')

class EvidenceBuilder:
    def __init__(self,context:InputPackage):
        self.context=context
        self.evidence=[]
        self.queries={qid:{'query_id':qid,'status':'COMPLETED','evidence_ids':[],'missing':[],'conflicts':[]} for qid in QUERY_IDS}

    def emit(self,query_id,key,value,source_ids=(),reason='',excerpts=()):
        if value is None or (isinstance(value,dict) and value.get('confirmed') is False):
            reason='尚未驗證成立；以下為需要查核的規則或路徑：'+reason
        source_ids=sorted(set(source_ids))
        witnesses=[]
        for sid in source_ids:
            path,row=self.context.source(sid)
            witnesses.append({'source_id':sid,'path':row['path'],'sha256':row['sha256'],'size':row['size']})
        payload={'query_id':query_id,'fact_key':key,'value':value,'artifact_sha256':self.context.manifest['primary_artifact']['sha256'],'release_id':self.context.manifest['release_id'],'witnesses':witnesses,'excerpts':list(excerpts),'reason':reason}
        identity={**payload,'excerpts':[{k:v for k,v in x.items() if k!='context_hash'} for x in payload['excerpts']]}
        evidence={'evidence_id':'E-'+digest(identity),**payload}
        self.evidence.append(evidence);self.queries[query_id]['evidence_ids'].append(evidence['evidence_id'])
        return evidence

    def gap(self,query_id,message):
        if message not in self.queries[query_id]['missing']:self.queries[query_id]['missing'].append(message)
        self.queries[query_id]['status']='COMPLETED_WITH_GAPS'

    def conflict(self,query_id,message):
        if message not in self.queries[query_id]['conflicts']:self.queries[query_id]['conflicts'].append(message)
        self.queries[query_id]['status']='CONFLICT'

    def excerpt(self,path,needle,before=3,after=8):
        pair=self.context.by_path(path)
        if not pair:return None
        p,row=pair
        if row['size']>3_000_000:return None
        lines=p.read_text(errors='replace').splitlines()
        for index,line in enumerate(lines):
            if needle in line:return read_excerpt(self.context,row['source_id'],max(1,index+1-before),min(len(lines),index+1+after))
        return None

    def result(self,cve_id,profile_version):
        return {'schema_version':'1.0','cve_id':cve_id,'profile_version':profile_version,'context_hash':self.context.context_hash,'queries':list(self.queries.values()),'evidence':self.evidence}

@dataclass(frozen=True)
class VerifiedEvidence:
    context_hash:str
    cve_id:str
    profile_version:str
    collection_hash:str
    records:tuple
    queries:tuple
    certificate:str
