"""CNA version statements; only plain numeric ranges are comparable here."""
import re


def numeric(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d+(?:\.\d+){0,3}',value):return None
    v=tuple(map(int,value.split('.')))
    return v+(0,)*(4-len(v))


def normalize(affected):
    result=[]
    for product in affected:
        for row in product.get('versions',[]):
            result.append({'vendor':product.get('vendor',''),'product':product.get('product',''),
                'start':row.get('version'),'end':row.get('lessThan',row.get('lessThanOrEqual')),
                'end_inclusive':'lessThanOrEqual' in row,'status':row.get('status','unknown'),
                'version_type':row.get('versionType','unspecified'),'changes':row.get('changes',[]),
                'default_status':product.get('defaultStatus','unknown'),
                'comparison_supported':numeric(row.get('version')) is not None and not row.get('changes') and
                    (not ('lessThan' in row or 'lessThanOrEqual' in row) or numeric(row.get('lessThan',row.get('lessThanOrEqual'))) is not None),
                'source_statement':row})
    return result


def compare(version, ranges):
    v=numeric(version)
    if v is None:return {'status':'VERSION_UNRESOLVED','reason':'版本包含發行版、回補、預發行或未知標記，不能用數字排序推定。'}
    matches=[];unknown=False
    for row in ranges:
        if not row['comparison_supported']:unknown=True;continue
        start=numeric(row['start']);end=numeric(row['end']) if row['end'] is not None else None
        if (v==start if end is None else start<=v and (v<=end if row['end_inclusive'] else v<end)):
            matches.append(row['status'])
    status=('VERSION_STATEMENTS_CONFLICT' if len(set(matches))>1 else
            'MATCHES_DECLARED_AFFECTED_RANGE' if matches==['affected'] or set(matches)=={'affected'} else
            'MATCHES_DECLARED_UNAFFECTED_RANGE' if set(matches)=={'unaffected'} else 'VERSION_UNRESOLVED')
    return {'status':status,'unresolved_ranges':unknown,'reason':'僅比對公告版本宣告；修正版標籤、供應商回補、建置與部署仍須另查，不構成產品判定。'}
