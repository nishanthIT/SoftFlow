"""Bounded public API verification using declared test identities, never samples."""
import json
from pathlib import Path
import sys
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app import intelligence as intel
from app.models import IntelligenceCache,now
from app.config import settings


def main():
    output=ROOT/'.local/verification/intelligence-live.json';output.parent.mkdir(parents=True,exist_ok=True)
    evidence={'checked_at':now().isoformat(),'purpose':'Public source integration using synthetic product/package metadata; no guest execution','providers':{}}
    with tempfile.TemporaryDirectory(prefix='luna-intelligence-') as folder:
        engine=create_engine('sqlite:///'+str(Path(folder)/'cache.db'))
        IntelligenceCache.__table__.create(engine);intel.Session=sessionmaker(engine,expire_on_commit=False)
        transport=intel.Transport()
        def check(name,url,**kwargs):
            try:
                result=transport.read(name,url,**kwargs)
                evidence['providers'][name]={'status':'COMPLETED','url':url}
                return result
            except Exception as error:
                evidence['providers'][name]={'status':'FAILED','error_type':type(error).__name__}
                return None
        identity=intel.identify({'version_info':{'ProductName':'7-Zip','CompanyName':'Igor Pavlov','ProductVersion':'15.14'},'architecture':'x64'})
        nvd=check('NVD',settings.nvd_api_url,params={'cveId':'CVE-2016-2334'})
        if nvd:
            evidence['nvd_findings']=[intel.nvd_record(v['cve'],identity) for v in nvd['vulnerabilities']]
        cve=check('CVE',settings.cve_api_url+'/CVE-2016-2334')
        if cve:evidence['cve_identity']=cve['cveMetadata']['cveId']
        github=check('GitHub',settings.github_advisories_url,params={'cve_id':'CVE-2024-22195','per_page':100})
        if github is not None:evidence['github_records']=[a['ghsa_id'] for a in github]
        package={'name':'Jinja2','ecosystem':'PyPI'}
        osv=check('OSV',settings.osv_api_url+'/query',method='POST',payload={'package':package,'version':'2.10'})
        if osv:
            evidence['osv_records']=[{'id':v['id'],'classification':intel.package_record(v,package,'2.10')['classification']} for v in osv.get('vulns',[])]
        kev=check('CISA KEV',settings.cisa_kev_url)
        if kev:evidence['kev_records']=len(kev['vulnerabilities'])
        engine.dispose()
    output.write_text(json.dumps(evidence,indent=2))
    print(json.dumps({'providers':evidence['providers'],'nvd_classifications':[f['classification'] for f in evidence.get('nvd_findings',[])],
        'osv_records':len(evidence.get('osv_records',[])),'evidence':str(output.relative_to(ROOT))},indent=2))
    return 0 if all(p['status']=='COMPLETED' for p in evidence['providers'].values()) else 2


if __name__=='__main__':sys.exit(main())
