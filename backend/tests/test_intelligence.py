"""Published-schema fixtures; no sample or exploit is executed by these tests."""
import copy
import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import intelligence as intel
from app.config import settings
from app.models import Base, IntelligenceCache, now


@pytest.fixture
def identity(monkeypatch):
    monkeypatch.setattr(settings, 'software_catalog_path', str(Path(intel.__file__).with_name('software_catalog.json')))
    return intel.identify({'version_info':{'ProductName':'7-Zip','CompanyName':'Igor Pavlov','ProductVersion':'16.00'},'architecture':'x64'})


def match(**kwargs):
    return {'vulnerable':True,'criteria':'cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*',**kwargs}


def cve(identifier='CVE-2016-2334', **kwargs):
    return {'id':identifier,'descriptions':[{'lang':'en','value':'Published test advisory'}],
        'configurations':[{'nodes':[{'operator':'OR','cpeMatch':[match(versionEndExcluding='16.02')]}]}],
        'references':[{'url':'https://vendor.example/advisory'}],**kwargs}


def test_identification_requires_product_and_vendor_catalog_match(identity):
    assert identity['mapping']=='CATALOG_MATCH' and identity['version']=='16.00'
    assert identity['packages']==[]  # An EXE name is not a package identifier.
    assert intel.identify({'version_info':{'ProductName':'7-Zip','CompanyName':'unrelated','ProductVersion':'16.00'}})['mapping']=='UNVERIFIED'
    assert intel.identify({'version_info':{'ProductName':'7-Zip','CompanyName':'Igor Pavlov','ProductVersion':'16, 0, 1, 0'}})['version']=='16.0.1.0'
    assert intel.identify({'version_info':{'ProductName':'7-Zip','ProductVersion':'16.00 beta'}})['version'] is None
    assert intel.identify({'version_info':{'FileVersion':'16.00'},'filename':'7zip16.exe'})['name'] is None


@pytest.mark.parametrize('version,expected', [('15.99',intel.UNAFFECTED),('16',intel.AFFECTED),('16.01',intel.AFFECTED),('16.02',intel.UNAFFECTED),('16.01-beta',intel.UNKNOWN),(None,intel.UNKNOWN)])
def test_numeric_range_boundaries(version,expected):
    assert intel.in_range(version,{'versionStartIncluding':'16.00','versionEndExcluding':'16.02'})==expected


def test_cpe_exact_version_does_not_override_excluded_range(identity):
    evidence=intel.cpe_match(match(criteria='cpe:2.3:a:7-zip:7-zip:16.00:*:*:*:*:*:*:*',versionEndExcluding='16.00'),identity)
    assert evidence['classification']==intel.UNAFFECTED


def test_cpe_unknown_mapping_and_environment_are_not_confirmed(identity):
    assert intel.cpe_match(match(),{**identity,'cpe_prefixes':[]})['classification']==intel.POTENTIAL
    config=[{'operator':'AND','nodes':[{'operator':'OR','cpeMatch':[match()]}]}]
    assert intel.aggregate(intel.nvd_matches(config,identity))==intel.POTENTIAL
    config=[{'negate':True,'nodes':[{'cpeMatch':[match(versionEndExcluding='1')]}]}]
    assert intel.aggregate(intel.nvd_matches(config,identity))==intel.UNKNOWN
    assert intel.cpe_match(match(criteria='cpe:2.3:a:7-zip:7-zip:*:*:*:de:*:*:*:*'),identity)['classification']==intel.POTENTIAL


def test_nvd_boundary_is_not_a_claim_of_available_patch(identity):
    record=intel.nvd_record(cve(),identity)
    assert record['classification']==intel.AFFECTED
    assert record['fixed_versions']==[] and record['excluded_version_boundaries']==['16.02']


@pytest.mark.parametrize('version,expected',[('1.0',intel.AFFECTED),('1.5',intel.UNAFFECTED),('1.7',intel.AFFECTED),('2',intel.UNAFFECTED)])
def test_cna_version_changes_and_default(version,expected):
    product={'defaultStatus':'unaffected','versions':[{'version':'1.0','lessThan':'2.0','versionType':'semver','status':'affected',
        'changes':[{'at':'1.5','status':'unaffected'},{'at':'1.7','status':'affected'}]}]}
    assert intel.cna_version(product,version)==expected


def test_cna_unsupported_ordering_cannot_be_declared_unaffected():
    product={'defaultStatus':'unaffected','versions':[{'version':'1.0-rc1','lessThan':'2.0','versionType':'semver','status':'affected'}]}
    assert intel.cna_version(product,'1.0')==intel.UNKNOWN
    assert intel.cna_version({'versions':[{'version':'1.0-beta','status':'affected'}]},'1.0-beta')==intel.AFFECTED
    assert intel.cna_version({'defaultStatus':'affected','versions':[]},None)==intel.UNKNOWN


def test_cna_vendor_and_component_constraints(identity):
    product={'product':'7-Zip','vendor':'Igor Pavlov','versions':[{'version':'16.00','status':'affected'}]}
    assert intel.cna_matches([product],identity)[0]['classification']==intel.AFFECTED
    assert intel.cna_matches([{**product,'vendor':'Unrelated vendor'}],identity)[0]['classification']==intel.POTENTIAL
    assert intel.cna_matches([{**product,'modules':['optional feature']}],identity)[0]['classification']==intel.POTENTIAL
    assert intel.cna_matches([{**product,'product':'different product'}],identity)==[]


@pytest.mark.parametrize('version,expected',[('0.9',intel.UNAFFECTED),('1.0',intel.AFFECTED),('1.9',intel.AFFECTED),('2.0',intel.UNAFFECTED),('2.1',intel.AFFECTED),('2.5',intel.UNAFFECTED)])
def test_osv_disjoint_ranges(version,expected):
    affected={'ranges':[{'type':'SEMVER','events':[{'introduced':'1.0'},{'fixed':'2.0'},{'introduced':'2.1'},{'last_affected':'2.4'}]}]}
    assert intel.osv_match(affected,version)==expected


def test_osv_missing_start_and_git_ranges_remain_unknown():
    assert intel.osv_match({'ranges':[{'type':'SEMVER','events':[{'fixed':'2'}]}]},'1')==intel.UNKNOWN
    assert intel.osv_match({'ranges':[{'type':'GIT','events':[{'introduced':'abcd'},{'fixed':'efab'}]}]},'1')==intel.UNKNOWN


def test_package_registry_canonical_names_are_used_only_in_known_ecosystems():
    assert intel.package_name_matches('Jinja2','jinja2','PyPI')
    assert intel.package_name_matches('Example_Package','example.package','PyPI')
    assert intel.package_name_matches('Example_Name','example-name','crates.io')
    assert not intel.package_name_matches('Example_Name','example-name','npm')
    vuln={'id':'GHSA-fixture','affected':[{'package':{'name':'jinja2','ecosystem':'PyPI'},'versions':['2.10']}]}
    assert intel.package_record(vuln,{'name':'Jinja2','ecosystem':'PyPI'},'2.10')['classification']==intel.AFFECTED


@pytest.mark.parametrize('expression,version,expected',[('>= 1.0, < 2','1.9',intel.AFFECTED),('>= 1.0, < 2','2.0',intel.UNAFFECTED),
    ('< 1 || >= 2, < 3','2.5',intel.AFFECTED),('^1.0','1.1',intel.UNKNOWN),('>= 1.0-rc1, < 2','1.1',intel.UNKNOWN)])
def test_github_ranges(expression,version,expected):
    assert intel.github_range(expression,version)==expected


def advisory(**kwargs):
    return {'ghsa_id':'GHSA-test-1234-5678','cve_id':'CVE-2016-2334','html_url':'https://github.com/advisories/GHSA-test-1234-5678',
        'summary':'Published package advisory','references':[],'vulnerabilities':[{'package':{'ecosystem':'pip','name':'example'},
        'vulnerable_version_range':'>= 1, < 2','first_patched_version':'2.0'}],**kwargs}


def test_github_matches_name_and_ecosystem_and_only_matched_fixed_versions(identity):
    mapped={**identity,'version':'1.0','packages':[{'name':'example','ecosystem':'PyPI'}]}
    record=intel.github_record(advisory(),mapped)
    assert record['classification']==intel.AFFECTED and record['fixed_versions']==['2.0']
    record=intel.github_record(advisory(),{**mapped,'packages':[{'name':'example','ecosystem':'npm'}]})
    assert record['classification']==intel.UNKNOWN and record['fixed_versions']==[]


def test_dedup_preserves_conflicts_through_more_sources(identity):
    one=intel.nvd_record(cve(),identity)
    two=copy.deepcopy(one);two['classification']=intel.UNAFFECTED;two['sources']=['OSV'];two['aliases']+=['GHSA-test']
    three=copy.deepcopy(one);three['sources']=['GitHub'];three['aliases']+=['GHSA-test']
    records=intel.deduplicate([one,two,three])
    assert len(records)==1 and records[0]['classification']==intel.UNKNOWN
    assert set(records[0]['sources'])=={'NVD','OSV','GitHub'}


class FixtureTransport:
    def __init__(self):self.calls=[]
    def read(self,provider,url,**kwargs):
        self.calls.append((provider,url,kwargs))
        if provider=='NVD':
            offset=kwargs['params']['startIndex']
            return {'totalResults':2,'vulnerabilities':[{'cve':cve('CVE-2016-2334' if offset==0 else 'CVE-2016-2335',
                configurations=[{'nodes':[{'operator':'OR','cpeMatch':[match(versionEndExcluding='16.02' if offset==0 else '16.00')]}]}])}]}
        if provider=='CVE':return {'cveMetadata':{'cveId':url.rsplit('/',1)[-1],'state':'PUBLISHED'},'containers':{'cna':{'references':[
            {'url':'https://exploit-db.com/exploits/example','tags':['exploit']}],'affected':[]}}}
        if provider=='GitHub':return [advisory(cve_id=kwargs['params']['cve_id'],ghsa_id='GHSA-'+kwargs['params']['cve_id'])]
        if provider=='CISA KEV':return {'vulnerabilities':[{'cveID':'CVE-2016-2334','dateAdded':'2026-01-01','requiredAction':'Apply updates'}]}
        raise AssertionError(provider)


def test_assessment_queries_all_pages_without_age_filter_and_keeps_not_affected(identity):
    transport=FixtureTransport();result=intel.assess(identity,transport)
    assert result['status']=='COMPLETED' and len(result['findings'])==2
    assert result['summary'][intel.AFFECTED]==1 and result['summary'][intel.UNAFFECTED]==1
    assert result['findings'][0]['cisa_kev'] is True and result['findings'][1]['cisa_kev'] is False
    assert result['findings'][0]['public_exploit_references'][0]['exploit_validation']=='NOT_EXECUTED'
    assert len([c for c in transport.calls if c[0]=='NVD'])==2
    assert all(not any('date' in key.lower() for key in c[2]['params']) for c in transport.calls if c[0]=='NVD')
    assert next(p for p in result['providers'] if p['provider']=='OSV')['status']=='NOT_APPLICABLE'


def test_missing_identity_does_not_query_or_guess_filename():
    transport=FixtureTransport();result=intel.assess(intel.identify({}),transport)
    assert result['status']=='IDENTIFICATION_REQUIRED' and transport.calls==[]


def test_source_failure_is_partial_and_kev_unknown(identity):
    class Broken(FixtureTransport):
        def read(self,provider,url,**kwargs):
            if provider=='CISA KEV':raise intel.SourceFailure('Service unavailable')
            return super().read(provider,url,**kwargs)
    result=intel.assess(identity,Broken())
    assert result['status']=='PARTIAL' and all(r['cisa_kev'] is None for r in result['findings'])
    assert next(p for p in result['providers'] if p['provider']=='CISA KEV')['status']=='UNAVAILABLE'


def test_repeated_pagination_fails_with_partial_findings(identity):
    class Repeated(FixtureTransport):
        def read(self,provider,url,**kwargs):
            if provider=='NVD':return {'totalResults':20,'vulnerabilities':[{'cve':cve()}]}
            return super().read(provider,url,**kwargs)
    result=intel.assess(identity,Repeated())
    assert result['status']=='PARTIAL' and 'repeated' in result['providers'][0]['reason']


@pytest.fixture
def cache(tmp_path,monkeypatch):
    engine=create_engine('sqlite:///'+str(tmp_path/'cache.db'))
    Base.metadata.create_all(engine)
    session=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(intel,'Session',session)
    yield session
    engine.dispose()


def http_client(monkeypatch,handler):
    original=httpx.Client
    monkeypatch.setattr(intel.httpx,'Client',lambda **kwargs:original(transport=httpx.MockTransport(handler),**kwargs))


def test_transport_retries_then_uses_cache_and_refetches_expired(cache,monkeypatch):
    calls=[];sleeps=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(429,headers={'Retry-After':'2'}) if len(calls)==1 else httpx.Response(200,json={'value':len(calls)})
    http_client(monkeypatch,handler)
    monkeypatch.setattr(intel.time,'sleep',sleeps.append)
    read=lambda:intel.Transport().read('GitHub','https://api.github.com/advisories',params={'cve_id':'CVE-2016-2334'})
    assert read()=={'value':2} and read()=={'value':2}
    assert len(calls)==2 and sleeps==[2]
    with cache.begin() as db:
        row=db.scalar(select(IntelligenceCache));row.expires_at=now()-timedelta(seconds=1)
    assert read()=={'value':3}
    assert calls[-1].headers['X-GitHub-Api-Version']=='2022-11-28'


def test_transport_bounds_retries(cache,monkeypatch):
    calls=[]
    def handler(request):calls.append(request);return httpx.Response(503)
    http_client(monkeypatch,handler);monkeypatch.setattr(intel.time,'sleep',lambda seconds:None)
    with pytest.raises(intel.SourceFailure,match='HTTP 503'):intel.Transport().read('OSV','https://api.osv.dev/v1/query')
    assert len(calls)==3


def test_nvd_rate_limit_and_secrets_are_not_cached(cache,monkeypatch):
    calls=[];reservations=[]
    class RateGate:
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def set(self,*args,**kwargs):reservations.append(kwargs);return True
    monkeypatch.setattr(intel.Redis,'from_url',lambda *args,**kwargs:RateGate())
    monkeypatch.setattr(settings,'nvd_api_key','fixture-secret-never-store')
    def handler(request):calls.append(request);return httpx.Response(200,json={'totalResults':0,'vulnerabilities':[]})
    http_client(monkeypatch,handler)
    assert intel.Transport().read('NVD',settings.nvd_api_url)['totalResults']==0
    assert calls[0].headers['apiKey']=='fixture-secret-never-store' and reservations==[{'nx':True,'px':650}]
    with cache() as db:
        assert 'fixture-secret-never-store' not in json.dumps([row.data for row in db.scalars(select(IntelligenceCache))])


def test_references_reject_non_web_and_credentials_and_are_never_executed():
    refs=intel.references(['file:///tmp/exploit','javascript:alert(1)','https://secret:password@example.com/',
        {'url':'https://vendor.example/advisory','tags':['Exploit']}])
    assert len(refs)==1 and refs[0]['public_exploit_reference'] is True
    assert refs[0]['link_validation']=='SOURCE_PUBLISHED_NOT_FETCHED'


def test_user_identity_overrides_metadata_and_name_version_alone_maps():
    identity=intel.identify({'version_info':{'ProductName':'Wrapper','ProductVersion':'1.0'}},{'name':'7-Zip','version':'16.00'})
    assert identity['mapping']=='CATALOG_MATCH' and identity['version']=='16.00'
    assert identity['source']=='User-supplied product and version'
    assert identity['embedded_metadata']['ProductName']=='Wrapper'
    assert intel.identify({'version_info':{'ProductName':'7-Zip','FileVersion':'16.00'}})['version']=='16.00'


def test_filename_candidate_never_becomes_confirmed_without_confirmation():
    identity=intel.identify({},filename='7-Zip-16.00-x64.exe')
    assert identity['name']=='7-Zip' and identity['version']=='16.00'
    assert intel.cpe_match(match(versionEndExcluding='16.02'),identity)['classification']==intel.POTENTIAL
    assert intel.normalized('Notepad++')!=intel.normalized('Notepad')


def test_dynamic_product_mapping_and_ambiguous_publishers():
    def product(vendor,version):return {'cpe':{'cpeName':f'cpe:2.3:a:{vendor}:widget:{version}:*:*:*:*:*:*:*','deprecated':False}}
    class Dictionary:
        def read(self,*a,**kw):return {'totalResults':2,'products':[product('old','1.0'),product('current','2.0')]}
    identity=intel.identify({},dict(name='Widget',version='2.0'))
    intel.resolve_product(identity,Dictionary())
    assert identity['mapping']=='NVD_CPE_MATCH' and identity['cpe_prefixes']==['cpe:2.3:a:current:widget']
    identity=intel.identify({},dict(name='Widget',version='3.0'))
    intel.resolve_product(identity,Dictionary())
    assert identity['mapping']=='UNVERIFIED' and len(identity['mapping_candidates'])==2


def test_name_version_only_returns_vulnerable_and_fixed_conclusions():
    affected=intel.assess(intel.identify({},dict(name='7-Zip',version='16.00')),FixtureTransport())
    assert affected['summary'][intel.AFFECTED]==1 and 'affect this version' in affected['conclusion']
    fixed=intel.assess(intel.identify({},dict(name='7-Zip',version='16.02')),FixtureTransport())
    assert fixed['summary'][intel.AFFECTED]==0 and fixed['summary'][intel.UNAFFECTED]==2
    assert 'no applicable advisories' in fixed['conclusion']
