"""Source-backed software vulnerability intelligence; no exploit execution.

Unknown product mappings, unsupported version syntaxes and environmental CPE
conditions stay uncertain. Metadata in an unsigned executable is self-reported.
"""
import hashlib
import json
import re
import time
from datetime import timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from redis import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .models import Session, IntelligenceCache, now
from .config import settings

AFFECTED='CONFIRMED_AFFECTED'
POTENTIAL='POTENTIALLY_AFFECTED'
UNAFFECTED='NOT_AFFECTED'
UNKNOWN='UNKNOWN'


def normalized(value):return re.sub(r'[^a-z0-9+#]','',str(value).casefold())

def vendor_key(value):
    return normalized(re.sub(r'\b(incorporated|corporation|corp|inc|llc|ltd|limited)\b','',str(value),flags=re.I))


def identify(static,declared_identity=None,filename=None):
    metadata=static.get('version_info',{}) or {}
    product=(metadata.get('ProductName') or metadata.get('FileDescription') or '').strip() or None
    if normalized(product) in ('setup','installer','installation','application'):product=None
    vendor=(metadata.get('CompanyName') or '').strip() or None
    declared=(metadata.get('ProductVersion') or static.get('fixed_product_version') or metadata.get('FileVersion') or '').strip()
    source='PE version resource'
    if declared_identity:
        product=declared_identity['name'];declared=declared_identity['version']
        vendor=declared_identity.get('vendor') or None
        source='User-supplied product and version'
    elif not product and filename:
        candidate=re.fullmatch(r'(.+?)[ _.-]+v?(\d+(?:\.\d+)+)(?:[ _.-]+(?:setup|installer|x64|x86|win64|win32))*\.exe',filename,re.I)
        if candidate:
            product,declared=candidate.groups();source='Filename candidate (unverified)'
    version=re.sub(r',\s*','.',declared) if re.fullmatch(r'\d+(?:[.,]\s*\d+){0,3}',declared) else None
    identity={'name':product,'vendor':vendor,'version':version,'declared_version':declared or None,
        'file_version':metadata.get('FileVersion'),'architecture':static.get('architecture'),
        'file_type':'Windows PE executable','platform':'windows','source':source,
        'embedded_metadata':{k:metadata.get(k) for k in ('ProductName','ProductVersion','CompanyName','FileVersion')},
        'identity_assurance':'Product/version advisory comparison only; the file identity and exploitability are not authenticated.',
        'cpe_prefixes':[],'packages':[],'aliases':[],'vendor_aliases':[],'mapping':'UNVERIFIED'}
    catalog=Path(settings.software_catalog_path)
    if catalog.is_file():
        for entry in json.loads(catalog.read_text()).get('products',[]):
            if normalized(product) in {normalized(n) for n in entry['names']} and (not vendor or normalized(vendor) in {normalized(v) for v in entry['vendors']}):
                identity.update(cpe_prefixes=entry.get('cpe_prefixes',[]),packages=entry.get('packages',[]),
                    aliases=entry['names'],vendor_aliases=entry['vendors'],mapping='CATALOG_MATCH',mapping_reference=entry.get('reference'))
                break
    return identity


def resolve_product(identity,transport):
    """Resolve an exact product name through NVD; ambiguous publishers stay uncertain."""
    candidates={};exact={};offset=0;seen=set()
    while True:
        page=transport.read('NVD',settings.nvd_cpe_api_url,params={
            'keywordSearch':identity['name'],'keywordExactMatch':'','resultsPerPage':1000,'startIndex':offset})
        if not isinstance(page,dict) or not isinstance(page.get('totalResults'),int):raise SourceFailure('Invalid NVD product response')
        products=page.get('products',[])
        fingerprint=tuple(item.get('cpe',{}).get('cpeName') for item in products)
        if fingerprint in seen and products:raise SourceFailure('NVD repeated a product page')
        seen.add(fingerprint)
        for item in products:
            cpe=item.get('cpe',{});parts=re.split(r'(?<!\\):',cpe.get('cpeName',''))
            if cpe.get('deprecated') or len(parts)!=13 or parts[2]!='a':continue
            names={normalized(parts[4]),normalized(parts[3]+' '+parts[4])}
            if normalized(identity['name']) not in names:continue
            if identity.get('vendor') and vendor_key(identity['vendor'])!=vendor_key(parts[3]):continue
            prefix=':'.join(parts[:5]);candidates[prefix]=cpe.get('cpeName')
            if identity.get('version') and compare(identity['version'],parts[5])==0:exact[prefix]=cpe.get('cpeName')
        offset+=len(products)
        if offset>=page['totalResults']:break
        if not products or offset>=5000:raise SourceFailure('Product search was incomplete; narrow the software name or publisher')
    identity['mapping_candidates']=list(candidates)
    selected=exact if len(exact)==1 else candidates
    if len(selected)==1:
        identity.update(cpe_prefixes=list(selected),mapping='NVD_CPE_MATCH',
                        mapping_reference='https://nvd.nist.gov/products/cpe',matched_cpe=next(iter(selected.values())))
    return len(candidates)


def numeric(value):
    if not isinstance(value,str) or len(value)>128 or not re.fullmatch(r'\d+(?:\.\d+)*',value):return None
    return tuple(int(part) for part in value.split('.'))


def compare(a,b):
    a,b=numeric(a),numeric(b)
    if a is None or b is None:return None
    width=max(len(a),len(b));a+= (0,)*(width-len(a));b+=(0,)*(width-len(b))
    return (a>b)-(a<b)


def in_range(version, constraints):
    if numeric(version) is None:return UNKNOWN
    uncertain=False
    for field,relation in [('versionStartIncluding',lambda c:c>=0),('versionStartExcluding',lambda c:c>0),
                           ('versionEndIncluding',lambda c:c<=0),('versionEndExcluding',lambda c:c<0)]:
        if field in constraints:
            result=compare(version,str(constraints[field]))
            if result is None:uncertain=True;continue
            if not relation(result):return UNAFFECTED
    return UNKNOWN if uncertain else AFFECTED


def cpe_match(match,identity,conditional=False,negated=False):
    parts=re.split(r'(?<!\\):',match.get('criteria',''))
    if len(parts)!=13 or not match.get('vulnerable'):return None
    prefix=':'.join(parts[:5])
    mapped=prefix in identity.get('cpe_prefixes',[])
    if not mapped and normalized(parts[4])!=normalized(identity.get('name')):return None
    version=identity.get('version')
    status=in_range(version,match)
    if parts[5] not in ('*','-'):
        equal=compare(version,parts[5]) if version else None
        exact=UNKNOWN if equal is None else AFFECTED if equal==0 else UNAFFECTED
        status=UNAFFECTED if UNAFFECTED in (status,exact) else UNKNOWN if UNKNOWN in (status,exact) else AFFECTED
    elif parts[5]=='-':status=UNKNOWN
    if parts[10] not in ('*','-','windows'):status=UNAFFECTED
    extra=any(parts[i] not in ('*','-') for i in (6,7,8,9,12))
    if parts[11] not in ('*','-'):
        supported={'x64':{'x64','x86_64'},'x86':{'x86','i386','i686'}}.get(identity.get('architecture'),set())
        if parts[11] not in supported:extra=True
    if status==AFFECTED and (not mapped or conditional or extra or identity.get('source','').startswith('Filename')):status=POTENTIAL
    if negated:status=UNKNOWN
    return {'source':'NVD','classification':status,'criteria':match,'conditional_environment':conditional or extra,
            'product_mapping':identity.get('mapping','catalog') if mapped else 'name candidate'}


def nvd_matches(configurations,identity):
    evidence=[]
    def visit(node,conditional=False,negated=False):
        negated=negated or node.get('negate',False)
        conditional=conditional or node.get('operator')=='AND' or negated
        for match in node.get('cpeMatch',[]):
            item=cpe_match(match,identity,conditional,negated)
            if item:evidence.append(item)
        for child in node.get('nodes',[])+node.get('children',[]):visit(child,conditional,negated)
    for config in configurations:visit(config)
    return evidence


def aggregate(evidence):
    values={e['classification'] for e in evidence}
    if AFFECTED in values:return AFFECTED
    if POTENTIAL in values:return POTENTIAL
    if UNKNOWN in values or not values:return UNKNOWN
    return UNAFFECTED


def references(items):
    output=[]
    for item in items:
        item={'url':item} if isinstance(item,str) else item
        if not isinstance(item,dict):continue
        url=item.get('url','')
        try:parts=urlsplit(url)
        except ValueError:continue
        if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password:continue
        tags=item.get('tags',[])
        output.append({'url':url,'tags':tags,'provenance':'Published advisory reference',
            'public_exploit_reference': any(str(tag).casefold() in ('exploit','proof-of-concept') for tag in tags) or parts.hostname in ('www.exploit-db.com','exploit-db.com'),
            'link_validation':'SOURCE_PUBLISHED_NOT_FETCHED',
            'exploit_validation':'NOT_EXECUTED'})
    return output


def score(metrics):
    for key in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'):
        for item in metrics.get(key,[]):
            data=item.get('cvssData',{})
            if isinstance(data.get('baseScore'),(int,float)):
                return {'score':data['baseScore'],'severity':data.get('baseSeverity') or item.get('baseSeverity'),
                        'vector':data.get('vectorString'),'source':item.get('source')}
    return {'score':None,'severity':None}


def nvd_record(cve,identity):
    evidence=nvd_matches(cve.get('configurations',[]),identity)
    text=next((d['value'] for d in cve.get('descriptions',[]) if d['lang']=='en'),'')
    return {'id':cve['id'],'aliases':[cve['id']],'description':text,'classification':aggregate(evidence),
        'version_evidence':evidence,'cvss':score(cve.get('metrics',{})),
        'references':references(cve.get('references',[]))+references(['https://nvd.nist.gov/vuln/detail/'+cve['id']]),
        'sources':['NVD'],'published':cve.get('published'),'modified':cve.get('lastModified'),
        # An excluded NVD boundary is not evidence that a vendor shipped a fix.
        'fixed_versions':[],
        'excluded_version_boundaries':sorted({m['criteria']['versionEndExcluding'] for m in evidence if 'versionEndExcluding' in m['criteria']}),
        'remediation':'Use the vendor advisory to identify and install the applicable fixed release.'}


class SourceFailure(Exception):pass


class Transport:
    def __init__(self):self.deadline=time.monotonic()+settings.intelligence_timeout
    def read(self,provider,url,*,method='GET',params=None,payload=None):
        key=hashlib.sha256(json.dumps([provider,url,method,params,payload],sort_keys=True).encode()).hexdigest()
        with Session() as db:
            cached=db.get(IntelligenceCache,key)
            if cached and cached.expires_at.replace(tzinfo=now().tzinfo)>now():return cached.data['value']
        for attempt in range(3):
            remaining=self.deadline-time.monotonic()
            if remaining<=0:raise SourceFailure('Intelligence deadline exceeded; results are partial')
            if provider=='NVD':
                with Redis.from_url(settings.redis_url,socket_timeout=3,socket_connect_timeout=3) as redis:
                    while not redis.set('intelligence:nvd:rate', '1', nx=True,px=650 if settings.nvd_api_key else 6200):
                        if time.monotonic()>=self.deadline:raise SourceFailure('NVD rate-limit wait exceeded deadline')
                        time.sleep(.2)
                remaining=self.deadline-time.monotonic()
                if remaining<=0:raise SourceFailure('NVD rate-limit wait exceeded deadline')
            headers={'User-Agent':'SentinelScan/1.0 vulnerability-intelligence','Accept':'application/json'}
            if provider=='NVD' and settings.nvd_api_key:headers['apiKey']=settings.nvd_api_key
            if provider=='GitHub':
                headers.update(Accept='application/vnd.github+json',**{'X-GitHub-Api-Version':'2022-11-28'})
                if settings.github_advisories_token:headers['Authorization']='Bearer '+settings.github_advisories_token
            try:
                with httpx.Client(timeout=min(settings.request_timeout,remaining),follow_redirects=False) as client:
                    with client.stream(method,url,params=params,json=payload,headers=headers) as response:
                        if response.status_code in (429,500,502,503,504):
                            delay=response.headers.get('retry-after','')
                            try:pause=float(delay) if delay.isdigit() else (parsedate_to_datetime(delay)-now()).total_seconds()
                            except (ValueError,TypeError,OverflowError):pause=2**attempt
                            pause=min(max(pause,0),30)
                            if attempt==2:raise SourceFailure(f'{provider} returned HTTP {response.status_code}')
                            time.sleep(min(pause,max(0,self.deadline-time.monotonic())));continue
                        response.raise_for_status()
                        body=bytearray()
                        for part in response.iter_bytes():
                            if time.monotonic()>=self.deadline:raise SourceFailure('Intelligence deadline exceeded while reading response')
                            body.extend(part)
                            if len(body)>32*1024*1024:raise SourceFailure('Provider response exceeds decoding limit')
                        result=json.loads(body)
                with Session.begin() as db:
                    cached=db.get(IntelligenceCache,key)
                    if cached:cached.data={'value':result};cached.expires_at=now()+timedelta(hours=settings.intelligence_cache_hours)
                    else:db.add(IntelligenceCache(key=key,data={'value':result},expires_at=now()+timedelta(hours=settings.intelligence_cache_hours)))
                return result
            except IntegrityError:return result
            except (httpx.TimeoutException,httpx.NetworkError):
                if attempt==2:raise SourceFailure(provider+' network request failed')
                time.sleep(min(2**attempt,max(0,self.deadline-time.monotonic())))
        raise SourceFailure(provider+' did not complete')


def osv_match(affected,version):
    if not version:return UNKNOWN
    if version in affected.get('versions',[]):return AFFECTED
    evidence=[]
    for interval in affected.get('ranges',[]):
        if interval.get('type') not in ('SEMVER','ECOSYSTEM'):evidence.append(UNKNOWN);continue
        # Unsupported version syntax must not be interpreted as a safe release.
        if numeric(version) is None:evidence.append(UNKNOWN);continue
        start=None
        for event in interval.get('events',[]):
            if 'introduced' in event:start=event['introduced'];continue
            end=event.get('fixed') or event.get('last_affected') or event.get('limit')
            if end is not None:
                if start is None:evidence.append(UNKNOWN);continue
                constraints={}
                if start not in (None,'0'):constraints['versionStartIncluding']=start
                constraints['versionEndIncluding' if 'last_affected' in event else 'versionEndExcluding']=end
                evidence.append(in_range(version,constraints));start=None
        if start is not None:evidence.append(in_range(version,{} if start=='0' else {'versionStartIncluding':start}))
    if AFFECTED in evidence:return AFFECTED
    if UNKNOWN in evidence:return UNKNOWN
    return UNAFFECTED if evidence or affected.get('versions') else UNKNOWN


def package_name_matches(left,right,ecosystem):
    if not isinstance(left,str) or not isinstance(right,str):return False
    if ecosystem in ('PyPI','pip'):
        return re.sub(r'[-_.]+','-',left).lower()==re.sub(r'[-_.]+','-',right).lower()
    if ecosystem in ('NuGet','nuget'):return left.casefold()==right.casefold()
    if ecosystem in ('crates.io','rust'):return left.lower().replace('_','-')==right.lower().replace('_','-')
    return left==right


def package_record(vuln,package,version):
    matched=[a for a in vuln.get('affected',[]) if a.get('package',{}).get('ecosystem')==package['ecosystem'] and package_name_matches(a.get('package',{}).get('name'),package['name'],package['ecosystem'])]
    evidence=[{'source':'OSV','classification':osv_match(a,version),'package':a.get('package'),'ranges':a.get('ranges',[]),'versions':a.get('versions',[])} for a in matched]
    cvss=vuln.get('database_specific',{}).get('severity')
    return {'id':vuln['id'],'aliases':list(dict.fromkeys([vuln['id'],*vuln.get('aliases',[])])),
        'description':vuln.get('summary') or vuln.get('details',''),'classification':aggregate(evidence),
        'version_evidence':evidence,'cvss':{'score':None,'severity':cvss},'sources':['OSV'],
        'references':references(vuln.get('references',[])),'published':vuln.get('published'),'modified':vuln.get('modified'),
        'fixed_versions':sorted({e['fixed'] for a in matched for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e}),
        'remediation':'Upgrade to a fixed package release listed in the source advisory.'}


def cna_version(product,version):
    """Evaluate CVE 5 version entries without guessing an unsupported ordering."""
    statuses={'affected':AFFECTED,'unaffected':UNAFFECTED,'unknown':UNKNOWN}
    if not version:return UNKNOWN
    uncertain=False
    for entry in product.get('versions',[]):
        start=entry.get('version')
        if 'lessThan' not in entry and 'lessThanOrEqual' not in entry:
            # Literal equality is valid even for non-numeric version schemes.
            if version==start:return statuses.get(entry.get('status'),UNKNOWN)
            if numeric(start) is not None and numeric(version) is not None:
                if compare(version,start)==0:return statuses.get(entry.get('status'),UNKNOWN)
            elif start not in (None,'*'):uncertain=True
            if start=='*':uncertain=True
            continue
        if entry.get('versionType') not in ('semver','custom') or numeric(version) is None:
            uncertain=True;continue
        bounds={'versionStartIncluding':start}
        end=entry.get('lessThan',entry.get('lessThanOrEqual'))
        if end!='*':bounds['versionEndExcluding' if 'lessThan' in entry else 'versionEndIncluding']=end
        match=in_range(version,bounds)
        if match==UNKNOWN:uncertain=True;continue
        if match==UNAFFECTED:continue
        status=statuses.get(entry.get('status'),UNKNOWN)
        changes=entry.get('changes',[])
        if any(numeric(change.get('at')) is None for change in changes):return UNKNOWN
        # CVE requires changes in ascending order; sort to avoid order-dependent evidence.
        for change in sorted(changes,key=lambda c:numeric(c['at'])):
            if compare(version,change['at'])>=0:status=statuses.get(change.get('status'),UNKNOWN)
        return status
    return UNKNOWN if uncertain else statuses.get(product.get('defaultStatus'),UNKNOWN)


def cna_matches(products,identity):
    evidence=[]
    names={normalized(name) for name in [identity.get('name'),*identity.get('aliases',[])] if name}
    vendors={normalized(name) for name in [identity.get('vendor'),*identity.get('vendor_aliases',[])] if name}
    for product in products:
        cpes=product.get('cpes',[])
        cpe_mapped=any(':'.join(re.split(r'(?<!\\):',cpe)[:5]) in identity.get('cpe_prefixes',[]) for cpe in cpes)
        if not cpe_mapped and normalized(product.get('product')) not in names:continue
        vendor=normalized(product.get('vendor'))
        verified=cpe_mapped or (identity.get('mapping')=='CATALOG_MATCH' and vendor in vendors)
        status=cna_version(product,identity.get('version'))
        conditional=any(product.get(key) for key in ('modules','programFiles','programRoutines'))
        platforms=product.get('platforms',[])
        if platforms and not any(normalized(p) in ('windows','win32','win64','x86','x64') for p in platforms):conditional=True
        if status==AFFECTED and (not verified or conditional or identity.get('source','').startswith('Filename')):status=POTENTIAL
        evidence.append({'source':'CVE Program / CNA','classification':status,'product_mapping':'catalog' if verified else 'name candidate',
            'product':product.get('product'),'vendor':product.get('vendor'),'versions':product.get('versions',[]),
            'default_status':product.get('defaultStatus'),'conditional_environment':conditional,'platforms':platforms})
    return evidence


GITHUB_ECOSYSTEMS={'PyPI':'pip','npm':'npm','Maven':'maven','NuGet':'nuget','Packagist':'composer',
    'RubyGems':'rubygems','Go':'go','crates.io':'rust','Hex':'erlang','Pub':'pub','SwiftURL':'swift','GitHub Actions':'actions'}


def github_range(expression,version):
    """GHSA numeric comparators only; unsupported ecosystem syntax stays unknown."""
    if numeric(version) is None or not isinstance(expression,str) or not expression.strip():return UNKNOWN
    results=[]
    for alternative in expression.split('||'):
        parts=[part.strip() for part in alternative.split(',')]
        conditions=[]
        for part in parts:
            match=re.fullmatch(r'(<=|>=|<|>|=)?\s*(\d+(?:\.\d+)*)',part)
            if not match:conditions.append(UNKNOWN);continue
            operation,target=match.groups();order=compare(version,target)
            valid={'<':order<0,'<=':order<=0,'>':order>0,'>=':order>=0,'=':order==0,None:order==0}[operation]
            conditions.append(AFFECTED if valid else UNAFFECTED)
        results.append(UNAFFECTED if UNAFFECTED in conditions else UNKNOWN if UNKNOWN in conditions else AFFECTED)
    return aggregate([{'classification':value} for value in results])


def github_record(advisory,identity):
    matched=[]
    for vulnerability in advisory.get('vulnerabilities',[]):
        package=vulnerability.get('package',{})
        if any(package.get('ecosystem')==GITHUB_ECOSYSTEMS.get(p['ecosystem']) and package_name_matches(package.get('name'),p['name'],p['ecosystem']) for p in identity.get('packages',[])):
            matched.append(vulnerability)
    evidence=[{'source':'GitHub','classification':github_range(v.get('vulnerable_version_range'),identity.get('version')),
        'package':v.get('package'),'affected_range':v.get('vulnerable_version_range')} for v in matched]
    aliases=[advisory['ghsa_id']]+([advisory['cve_id']] if advisory.get('cve_id') else [])
    return {'id':advisory.get('cve_id') or advisory['ghsa_id'],'aliases':aliases,'sources':['GitHub'],
        'description':advisory.get('summary',''),'classification':aggregate(evidence),'version_evidence':evidence,
        'references':references([advisory.get('html_url',''),*advisory.get('references',[])]),
        'cvss':{'score':(advisory.get('cvss') or {}).get('score'),'severity':advisory.get('severity')},
        'fixed_versions':sorted({v['first_patched_version'] for v in matched if isinstance(v.get('first_patched_version'),str)}),
        'published':advisory.get('published_at'),'modified':advisory.get('updated_at'),
        'remediation':'Review the affected range and upgrade to the vendor/package fixed release.'}


def combine_classes(classes):
    values=set(classes)
    return UNKNOWN if {AFFECTED,UNAFFECTED}<=values else aggregate([{'classification':c} for c in values])


def deduplicate(records):
    groups=[]
    for record in records:
        record.setdefault('classification_evidence',[
            {'sources':record['sources'][:],'classification':record['classification']}
        ] if record.get('version_evidence') else [])
        matching=[g for g in groups if set(g['aliases']) & set(record['aliases'])]
        if not matching:groups.append(record);continue
        for group in matching:
            groups.remove(group)
            for key in ('aliases','sources','references','version_evidence','fixed_versions','classification_evidence','excluded_version_boundaries'):
                record.setdefault(key,[])
                for value in group.get(key,[]):
                    if value not in record[key]:record[key].append(value)
            record['classification']=combine_classes(c['classification'] for c in record['classification_evidence'])
            if record['cvss'].get('score') is None:record['cvss']=group['cvss']
            for key in ('cna_affected','cna_remediation'):
                if key in group and key not in record:record[key]=group[key]
            if not record.get('description'):record['description']=group.get('description','')
        groups.append(record)
    for group in groups:
        group['id']=next((a for a in group['aliases'] if a.startswith('CVE-')),group['id'])
    return sorted(groups,key=lambda g:g['id'])


def assess(identity, transport=None):
    result={'status':'COMPLETED','identity':identity,'findings':[],'providers':[],
        'scope':'Published product/version advisories; not proof of exploitability and not an embedded dependency inventory',
        'applicability_assumption':'Version findings assume the executable self-reported product metadata is authentic; this lookup does not authenticate the publisher.',
        'checked_at':now().isoformat(),'summary':{status:0 for status in (AFFECTED,POTENTIAL,UNAFFECTED,UNKNOWN)}}
    if not identity.get('name'):
        return {**result,'status':'IDENTIFICATION_REQUIRED','reason':'Product name could not be identified. Enter the software name and version to run the advisory check.'}
    transport=transport or Transport();records=[]
    def run(provider,fn):
        try:
            count=fn();result['providers'].append({'provider':provider,'status':'COMPLETED','records':count})
        except Exception as error:
            result['status']='PARTIAL'
            result['providers'].append({'provider':provider,'status':'UNAVAILABLE','error_type':type(error).__name__,
                'reason':str(error) if isinstance(error,SourceFailure) else f'Provider returned HTTP {error.response.status_code}' if isinstance(error,httpx.HTTPStatusError) else 'Provider lookup failed; no absence-of-vulnerabilities conclusion is possible'})
    if not identity.get('cpe_prefixes'):
        run('NVD product dictionary',lambda:resolve_product(identity,transport))
    def nvd():
        count=0
        queries=[{'virtualMatchString':p+':*:*:*:*:*:*:*:*'} for p in (identity.get('cpe_prefixes') or identity.get('mapping_candidates',[]))] or [{'keywordSearch':identity['name']}]
        for query in queries:
            offset=0;seen=set()
            while True:
                page=transport.read('NVD',settings.nvd_api_url,params={**query,'startIndex':offset,'resultsPerPage':100})
                if not isinstance(page,dict) or not isinstance(page.get('totalResults'),int):raise SourceFailure('Invalid NVD response')
                batch=page.get('vulnerabilities',[])
                fingerprint=tuple(item['cve']['id'] for item in batch)
                if fingerprint in seen and batch:raise SourceFailure('NVD repeated a results page')
                seen.add(fingerprint)
                for item in batch:
                    if item['cve'].get('vulnStatus')!='Rejected':
                        record=nvd_record(item['cve'],identity)
                        if record['version_evidence']:records.append(record);count+=1
                offset+=len(batch)
                if offset>=page.get('totalResults',0):break
                if not batch:raise SourceFailure('NVD pagination stopped before all results were retrieved')
        return count
    run('NVD',nvd)
    def osv():
        count=0
        for package in identity.get('packages',[]):
            token=None;seen=set()
            while True:
                query={'package':{k:package[k] for k in ('name','ecosystem')},'version':identity.get('version')}
                if not query['version']:raise SourceFailure('Package version is unknown')
                if token:query['page_token']=token
                page=transport.read('OSV',settings.osv_api_url+'/query',method='POST',payload=query)
                for vuln in page.get('vulns',[]):
                    if vuln.get('withdrawn'):continue
                    records.append(package_record(vuln,package,query['version']));count+=1
                token=page.get('next_page_token')
                if not token:break
                if token in seen:raise SourceFailure('OSV repeated a pagination token')
                seen.add(token)
        return count
    if identity.get('packages'):run('OSV',osv)
    else:result['providers'].append({'provider':'OSV','status':'NOT_APPLICABLE','reason':'No verified package ecosystem/name mapping; product names are not package identifiers'})
    result['findings']=deduplicate(records)
    def enrich():
        count=0
        for record in result['findings']:
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}',record['id']):continue
            payload=transport.read('CVE',settings.cve_api_url+'/'+record['id'])
            if payload.get('cveMetadata',{}).get('cveId')!=record['id']:raise SourceFailure('CVE record identity mismatch')
            if payload.get('cveMetadata',{}).get('state')=='REJECTED':
                record.update(classification=UNKNOWN,cve_record_state='REJECTED')
                record['classification_evidence']=[{'sources':['CVE Program / CNA'],'classification':UNKNOWN}]
                count+=1;continue
            cna=payload.get('containers',{}).get('cna',{})
            record['sources'].append('CVE Program / CNA')
            record['references']+=references(cna.get('references',[]))
            record['cna_affected']=cna.get('affected',[])
            record['cna_remediation']=cna.get('solutions',[])
            evidence=cna_matches(cna.get('affected',[]),identity)
            record['version_evidence']+=evidence
            if evidence:
                record['classification_evidence'].append({'sources':['CVE Program / CNA'],'classification':aggregate(evidence)})
                record['classification']=combine_classes(e['classification'] for e in record['classification_evidence'])
            if record['cvss'].get('score') is None:
                for metric in cna.get('metrics',[]):
                    for key in ('cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0'):
                        if metric.get(key,{}).get('baseScore') is not None:
                            data=metric[key];record['cvss']={'score':data['baseScore'],'severity':data.get('baseSeverity'),'vector':data.get('vectorString'),'source':'CVE Program / CNA'};break
            count+=1
        return count
    run('CVE',enrich)
    def github():
        count=0
        queries=[{'affects':p['name']+'@'+identity['version'],'ecosystem':GITHUB_ECOSYSTEMS[p['ecosystem']]} for p in identity.get('packages',[]) if identity.get('version') and p['ecosystem'] in GITHUB_ECOSYSTEMS]
        queries += [{'cve_id':r['id']} for r in result['findings'] if r['id'].startswith('CVE-')]
        for query in queries:
            page=1;seen=set()
            while True:
                batch=transport.read('GitHub',settings.github_advisories_url,params={**query,'per_page':100,'page':page})
                if not isinstance(batch,list):raise SourceFailure('Invalid GitHub response')
                fingerprint=tuple(a.get('ghsa_id') for a in batch)
                if fingerprint in seen and batch:raise SourceFailure('GitHub repeated a results page')
                seen.add(fingerprint)
                for advisory in batch:
                    if advisory.get('withdrawn_at'):continue
                    result['findings'].append(github_record(advisory,identity))
                    count+=1
                if len(batch)<100:break
                page+=1
        return count
    run('GitHub',github)
    result['findings']=deduplicate(result['findings'])
    def kev():
        try:feed=transport.read('CISA KEV',settings.cisa_kev_url)
        except httpx.HTTPStatusError as error:
            if error.response.status_code!=403:raise
            feed=transport.read('CISA KEV','https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
        entries={v['cveID']:v for v in feed['vulnerabilities']}
        for record in result['findings']:
            item=entries.get(record['id']);record['cisa_kev']=bool(item)
            if item:
                record['kev_evidence']={k:item.get(k) for k in ('dateAdded','requiredAction','knownRansomwareCampaignUse','notes')}
                record['references']+=references(['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'])
                record['sources'].append('CISA KEV')
        return len(entries)
    run('CISA KEV',kev)
    for record in result['findings']:
        record['references']=list({r['url']:r for r in record['references']}.values())
        record['sources']=list(dict.fromkeys(record['sources']));record['aliases']=list(dict.fromkeys(record['aliases']))
        record['public_exploit_references']=[r for r in record['references'] if r['public_exploit_reference']]
        record['patch_availability']='PUBLISHED_FIXED_VERSION' if record['fixed_versions'] else 'REVIEW_VENDOR_ADVISORY'
        record.setdefault('cisa_kev',None)
    result['summary']={status:sum(r['classification']==status for r in result['findings']) for status in (AFFECTED,POTENTIAL,UNAFFECTED,UNKNOWN)}
    if not identity.get('version'):
        result['status']='PARTIAL';result['reason']='Product version is unknown; applicability remains uncertain'
    elif identity.get('mapping') not in ('CATALOG_MATCH','NVD_CPE_MATCH'):
        result['status']='PARTIAL';result['reason']='Product mapping is ambiguous or unavailable; candidate name/version matches are shown for review.'
    elif identity.get('source','').startswith('Filename'):
        result['status']='PARTIAL';result['reason']='Identity was inferred from the filename. Confirm the software name and version to establish advisory applicability.'
    affected=result['summary'][AFFECTED];potential=result['summary'][POTENTIAL]+result['summary'][UNKNOWN]
    subject=f"{identity['name']} {identity.get('version') or identity.get('declared_version') or '(version unknown)'}"
    result['conclusion']=f'{subject}: '+(f'{affected} published vulnerabilities affect this version.' if affected else
        f'{potential} advisory matches need review.' if potential else
        'no applicable advisories found by the completed lookups.' if result['status']=='COMPLETED' else
        'vulnerability lookup is incomplete; no safe-version conclusion is available.')
    return result
