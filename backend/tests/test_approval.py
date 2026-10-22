"""Policy fixtures test decisions; they do not claim live sandbox execution."""
import pytest
from app.approval import recommend, criteria
from app import policy


def evidence():
    payloads={
        'validation': {'validated': True}, 'hashing': {'sha256':'f'*64},
        'static': {'architecture':'x64','sections':[{'name':'.text'}]},
        'yara': {'rule_files':1,'matches':[]},
        'sandbox': {'task_id':'20261022-ABC123','report':{'tasks':[{}]}},
        'behavior': {'processes':[{'name':'test.exe'}]}, 'network': {'events':[]},
        'virustotal': {'stats':{'undetected':30}},
        'verdict': {'score':0,'security':'LIKELY_BENIGN','reasons':[],'approval_policy':criteria()},
        'report': {'schema_version':'2.0'},
    }
    return [{'name':n,'status':'COMPLETED','data':d} for n,d in payloads.items()]


def test_complete_evidence_meets_policy():
    result=recommend('COMPLETED',evidence())
    assert result['recommendation']=='APPROVE'
    assert result['limitations'] and result['reasons']


@pytest.mark.parametrize('status',['QUEUED','RUNNING','FAILED','TIMEOUT','UNAVAILABLE','SKIPPED'])
def test_missing_execution_never_approves(status):
    engines=evidence()
    next(e for e in engines if e['name']=='sandbox')['status']=status
    assert recommend('COMPLETED',engines)['recommendation']=='REVIEW_REQUIRED'


@pytest.mark.parametrize('stage',['static','yara','sandbox','behavior','network','verdict'])
def test_success_flag_without_evidence_never_approves(stage):
    engines=evidence();next(e for e in engines if e['name']==stage)['data']={}
    assert recommend('COMPLETED',engines)['recommendation']=='REVIEW_REQUIRED'


def test_failure_after_verdict_never_approves():
    assert recommend('FAILED',evidence())['recommendation']=='REVIEW_REQUIRED'


def test_reject_and_intermediate_review():
    engines=evidence();finding=next(e for e in engines if e['name']=='verdict')['data']
    finding.update(score=70,security='LIKELY_MALICIOUS',reasons=[{'source':'sandbox','points':70,'evidence':'Score 9'}])
    assert recommend('COMPLETED',engines)['recommendation']=='REJECT'
    finding.update(score=25,security='SUSPICIOUS')
    assert recommend('COMPLETED',engines)['recommendation']=='REVIEW_REQUIRED'


def test_cuckoo_score_is_rejection_evidence():
    result=policy.verdict({'sandbox':{'status':'COMPLETED','data':{'source':'cuckoo3','report':{'tasks':[{'post':{'score':9}}]}}}})
    assert result['score']==70 and result['security']=='LIKELY_MALICIOUS'


def test_policy_snapshot_survives_configuration_change(monkeypatch):
    from app.config import settings
    engines=evidence()
    monkeypatch.setattr(settings,'approval_min_reputation_engines',100)
    assert recommend('COMPLETED',engines)['recommendation']=='APPROVE'


def test_inconclusive_finding_requires_review():
    engines=evidence();next(e for e in engines if e['name']=='verdict')['data']['security']='INCONCLUSIVE'
    assert recommend('COMPLETED',engines)['recommendation']=='REVIEW_REQUIRED'
