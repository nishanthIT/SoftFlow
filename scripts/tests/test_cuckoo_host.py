"""Host isolation checks; live firewall tests use a disposable network namespace."""
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepare_cuckoo_host as host
import provision


# nftables 1.1.7 list output, with only chain priorities requested numerically.
LISTING = '''table inet sentinelscan_cuckoo {
    chain input {
        type filter hook input priority -200; policy accept;
        iifname "ss-cuckoo0" ct state established,related accept
        iifname "ss-cuckoo0" ip daddr 192.168.30.1 tcp dport 2042 accept
        iifname "ss-cuckoo0" drop
    }

    chain forward {
        type filter hook forward priority -200; policy accept;
        iifname "ss-cuckoo0" drop
        oifname "ss-cuckoo0" drop
    }
}
'''


@pytest.mark.parametrize('listing,returncode,valid', [
    (LISTING, 0, True),
    (LISTING.replace('ct state established,related accept', 'accept'), 0, False),
    (LISTING.replace('tcp dport 2042', 'tcp dport 22'), 0, False),
    (LISTING.replace('oifname "ss-cuckoo0" drop', ''), 0, False),
    (LISTING.replace('priority -200', 'priority 0'), 0, False),
    (LISTING.replace('    chain input {', '    chain input {\n        accept'), 0, False),
    (LISTING, 1, False),
])
def test_firewall_comparison_retains_exact_controls(monkeypatch, listing, returncode, valid):
    def run(args, **kwargs):
        assert args == ['nft', '--numeric-priority', 'list', 'table', 'inet', 'sentinelscan_cuckoo']
        return SimpleNamespace(stdout=listing, stderr='permission denied' if returncode else '', returncode=returncode)

    monkeypatch.setattr(host.subprocess, 'run', run)
    verified, evidence = host.verify_firewall('ss-cuckoo0', '192.168.30.1', 2042)
    assert verified is valid
    assert evidence['observed'] == listing
    assert evidence['exit_code'] == returncode
    if returncode:
        assert evidence['error'] == 'permission denied'


def test_installed_nftables_roundtrip_in_private_namespace():
    if not shutil.which('unshare') or not shutil.which('nft'):
        pytest.skip('unshare and nft are required for the isolated kernel test')
    namespace = ['unshare', '--user', '--map-root-user', '--net']
    probe = subprocess.run(namespace + ['true'], capture_output=True, text=True)
    if probe.returncode:
        pytest.skip('Unprivileged network namespaces are unavailable: ' + probe.stderr.strip())
    # This never reads or changes the host network namespace or its firewall.
    script = '''
import subprocess
from prepare_cuckoo_host import firewall_rules, verify_firewall
rules = firewall_rules('ss-cuckoo0', '192.168.30.1', 2042)
subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
verified, evidence = verify_firewall('ss-cuckoo0', '192.168.30.1', 2042)
assert verified, evidence
subprocess.run(['nft', 'insert', 'rule', 'inet', 'sentinelscan_cuckoo', 'input', 'accept'], check=True)
verified, evidence = verify_firewall('ss-cuckoo0', '192.168.30.1', 2042)
assert not verified, 'An extra accept rule must invalidate verification'
subprocess.run(['nft', 'delete', 'table', 'inet', 'sentinelscan_cuckoo'], check=True)
verified, evidence = verify_firewall('ss-cuckoo0', '192.168.30.1', 2042)
assert not verified and evidence['exit_code'] != 0, evidence
'''
    result = subprocess.run(namespace + [sys.executable, '-c', script],
                            cwd=Path(host.__file__).parent, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_setup_prints_captured_verification_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(provision, 'ROOT', tmp_path)
    with pytest.raises(RuntimeError, match='Verify host failed'):
        provision.step('Verify host', [sys.executable, '-c',
                       'print(\'{"checks": {"firewall": false}}\'); raise SystemExit(2)'],
                       'network-verification.log', capture=True)
    assert '"firewall": false' in capsys.readouterr().out
    assert '"firewall": false' in (tmp_path / '.local/logs/network-verification.log').read_text()
