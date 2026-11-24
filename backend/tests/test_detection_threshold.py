import pytest
from app.config import settings
from app.policy import verdict
from app.approval import recommend

@pytest.fixture(autouse=True)
def optional_providers(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','')
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','')



def evidence(count=None):
    data={'validation':{'validated':True},'hashing':{'sha256':'a'*64},
          'static':{'architecture':'x64','sections':[{'name':'.text'}]},
          'yara':{'rule_files':1,'matches':[]},
          'sandbox':{'source':'cuckoo','task_id':1,'report':{'signatures':[]}},
          'behavior':{'processes':[{'process_name':'fixture.exe'}],'events':[]},
          'network':{'events':[]},'dns':{'queries':[],'responses':[]},
          'vulnerabilities':{'status':'COMPLETED','identity':{'name':'Fixture','version':'1'},'findings':[]},
          'report':{'schema_version':'2.0'}}
    if count is not None:data['virustotal']={'stats':{'malicious':count,'undetected':40-count}}
    return {name:{'name':name,'status':'COMPLETED','data':value} for name,value in data.items()}


@pytest.mark.parametrize('count,state',[(0,'LEGITIMATE'),(1,'LEGITIMATE'),(2,'LEGITIMATE'),(3,'PARTIAL'),(4,'MALICIOUS'),(12,'MALICIOUS')])
def test_boundaries_and_approval(count,state,monkeypatch):
    monkeypatch.setattr(settings,'approval_require_reputation',False)
    results=evidence(count);finding=verdict(results)
    assert finding['security']==state and finding['detection_count']==count
    results['verdict']={'name':'verdict','status':'COMPLETED','data':finding}
    expected={'LEGITIMATE':'APPROVE','PARTIAL':'REVIEW_REQUIRED','MALICIOUS':'REJECT'}
    assert recommend('COMPLETED',list(results.values()))['recommendation']==expected[state]


def test_cuckoo_only_completed_analysis_can_qualify(monkeypatch):
    monkeypatch.setattr(settings,'approval_require_reputation',False)
    result=verdict(evidence())
    assert result['security']=='LEGITIMATE'
    assert result['detection_count'] is None  # Never invent antivirus votes.


@pytest.mark.parametrize('status',['FAILED','TIMEOUT','UNAVAILABLE','RUNNING'])
def test_incomplete_execution_never_green(status):
    results=evidence(0);results['sandbox']['status']=status
    assert verdict(results)['security']=='PARTIAL'


def test_empty_telemetry_never_green():
    results=evidence(0);results['behavior']['data']={}
    assert verdict(results)['security']=='PARTIAL'


def test_failed_checkpoint_is_not_counted():
    results=evidence(9);results['virustotal']['status']='FAILED'
    decision=verdict(results)
    assert decision['detection_count'] is None
    assert not any(r['source']=='virustotal' for r in decision['reasons'])


def test_threshold_configurable_and_overlapping_counts_not_summed(monkeypatch):
    monkeypatch.setattr(settings,'detection_review_threshold',5)
    results=evidence(4)
    results['hybrid-analysis']={'status':'COMPLETED','data':{'raw':{'av_matched':4,'av_total':40}}}
    decision=verdict(results)
    assert decision['detection_count']==4 and decision['security']=='LEGITIMATE'
    assert decision['approval_policy']['detection_review_threshold']==5


def test_percentages_and_scores_are_not_detection_counts():
    results=evidence(0)
    results['hybrid-analysis']={'status':'COMPLETED','data':{'verdict':'malicious','threat_score':99,'raw':{'av_detect':75}}}
    decision=verdict(results)
    assert decision['detection_count']==0 and decision['security']=='PARTIAL'


@pytest.mark.parametrize('stats',[{}, {'malicious':-1}, {'malicious':'0'}, {'malicious':False}, {'malicious':0,'undetected':0}])
def test_malformed_or_empty_av_counts_need_review(stats):
    results=evidence(0);results['virustotal']['data']['stats']=stats
    assert verdict(results)['security']=='PARTIAL'


def test_expected_provider_failure_requires_review(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','configured')
    results=evidence(0);results['virustotal']['status']='UNAVAILABLE'
    assert verdict(results)['security']=='PARTIAL'


def test_antivirus_timeouts_are_not_clean_votes():
    results=evidence(0);results['virustotal']['data']['stats']={'timeout':40}
    assert verdict(results)['security']=='PARTIAL'
