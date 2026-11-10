"""Certificate inspection, report integrity and durable API processing."""
from datetime import datetime,timedelta,timezone
from io import BytesIO
import socket,ssl,threading,time
from types import SimpleNamespace
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from openpyxl import load_workbook
from app import ssl_checker as checker,ssl_checks
from app.models import SSLCheck
from test_api import client


def test_domain_validation_and_limits():
    assert checker.parse_upload(b'Example.org\nexample.org\n*.example.org\n')==['example.org','*.example.org']
    for data in [b'',b'https://example.org',b'127.0.0.1',b'example.org:8443',b'example.org/path',b'bad\x00.example']:
        with pytest.raises(ValueError):checker.parse_upload(data)
    with pytest.raises(ValueError):checker.parse_upload('\n'.join(f'a{i}.example.org' for i in range(501)).encode())
    assert checker.check_domain('*.example.org')['status']=='WILDCARD_NOT_TESTED'


@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:8.8.8.8'])
def test_private_dns_answers_never_connect(monkeypatch,address):
    monkeypatch.setattr(checker.dns.resolver,'Resolver',lambda:SimpleNamespace(resolve=lambda *a,**kw:['8.8.8.8',address]))
    monkeypatch.setattr(checker.socket,'create_connection',lambda *a,**kw:pytest.fail('Private address connection attempted'))
    assert checker.check_domain('example.org')['status']=='INVALID_ADDRESS'


def test_dns_timeout_is_bounded_and_reported(monkeypatch):
    def resolve(*a,**kw):
        assert 0<kw['lifetime']<=checker.TIMEOUT and kw['search'] is False
        raise checker.dns.exception.Timeout
    monkeypatch.setattr(checker.dns.resolver,'Resolver',lambda:SimpleNamespace(resolve=resolve))
    assert checker.check_domain('example.org')['status']=='TIMEOUT'


@pytest.mark.parametrize('days,trusted,expected',[(-2,False,'EXPIRED'),(10,True,'EXPIRING_SOON'),(90,True,'VALID'),(90,False,'CERT_VERIFICATION_FAILED')])
def test_real_tls_and_der_fallback(tmp_path,monkeypatch,days,trusted,expected):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.org')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=10)).not_valid_after(now+timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.org')]),False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
        .add_extension(x509.KeyUsage(True,False,True,False,False,True,True,False,False),True).sign(key,hashes.SHA256()))
    crt=tmp_path/'cert.pem';crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem=tmp_path/'key.pem';pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(crt,pem)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(3);listener.settimeout(.1)
    port=listener.getsockname()[1];stopping=threading.Event()
    def serve():
        while not stopping.is_set():
            try:raw,_=listener.accept()
            except socket.timeout:continue
            except OSError:break
            try:
                with context.wrap_socket(raw,server_side=True) as connection:connection.recv(1)
            except (OSError,ssl.SSLError):raw.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    monkeypatch.setattr(checker,'PORT',port)
    monkeypatch.setattr(checker,'public_addresses',lambda *a:['127.0.0.1'])
    if trusted:
        original=ssl.create_default_context
        monkeypatch.setattr(checker.ssl,'create_default_context',lambda:original(cafile=str(crt)))
    try:
        result=checker.check_domain('example.org')
        assert result['status']==expected,result
        assert result['expiry_date'] and result['common_name']=='example.org' and result['san']=='example.org'
    finally:stopping.set();listener.close();thread.join(2)


def test_durable_api_excel_and_resume(client,monkeypatch):
    reply=client.post('/api/ssl-checks',files={'file':('domains.txt',b'example.org\n*.example.org')})
    assert reply.status_code==201
    identifier=reply.json()['id'];assert reply.json()['expires_at']
    assert client.get('/api/ssl-checks/'+identifier+'/report.xlsx').status_code==409
    calls=[]
    def check(domain):
        calls.append(domain)
        return {**checker.error_result(domain,'VALID',''), 'issuer':'=HYPERLINK("https://example.org")','days_remaining':42}
    monkeypatch.setattr(checker,'check_domain',check)
    ssl_checks.run_scan(identifier);ssl_checks.run_scan(identifier)
    assert len(calls)==2
    result=client.get('/api/ssl-checks/'+identifier).json()
    assert result['status']=='COMPLETED' and result['completed']==2
    response=client.get('/api/ssl-checks/'+identifier+'/report.xlsx');assert response.status_code==200
    workbook=load_workbook(BytesIO(response.content));sheet=workbook['SSL Results']
    assert workbook.sheetnames==['SSL Results','Summary'] and sheet.freeze_panes=='A2'
    assert sheet.auto_filter.ref=='A1:I3' and sheet.max_column==9
    assert all(cell.data_type!='f' for tab in workbook for row in tab for cell in row)
    assert sheet['G2'].value.startswith('=HYPERLINK')


def test_partial_failure_and_worker_recovery_limit(client,monkeypatch):
    identifier=client.post('/api/ssl-checks',files={'file':('domains.txt',b'example.org\nwww.python.org')}).json()['id']
    def broken(domain):
        if domain=='example.org':raise RuntimeError('failure')
        return checker.error_result(domain,'TIMEOUT','timed out')
    monkeypatch.setattr(checker,'check_domain',broken);ssl_checks.run_scan(identifier)
    assert client.get('/api/ssl-checks/'+identifier).json()['summary']=={'CHECK_ERROR':1,'TIMEOUT':1}
    with ssl_checks.Session.begin() as db:
        scan=db.get(SSLCheck,identifier);scan.status='RUNNING';scan.attempts=3
    ssl_checks.run_scan(identifier)
    assert client.get('/api/ssl-checks/'+identifier).json()['status']=='FAILED'
