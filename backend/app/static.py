import re
from pathlib import Path
import pefile
from cryptography.hazmat.primitives.serialization import pkcs7
from .config import settings

SUSPICIOUS = {'CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','SetWindowsHookExA','QueueUserAPC','WinExec','ShellExecuteA','InternetOpenUrlA'}
def text(value): return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else str(value)
def analyze(data):
    pe = pefile.PE(data=data)
    try:
        strings = [text(s) for s in re.findall(rb'[\x20-\x7e]{5,}',data)]
        strings += [s.decode('utf-16le', errors='replace') for s in re.findall(rb'(?:[\x20-\x7e]\x00){5,}',data)]
        strings = list(dict.fromkeys(s[:2048] for s in strings))[:30000]
        imports = [{'dll':text(i.dll),'name':text(f.name) if f.name else f'ordinal:{f.ordinal}'} for i in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]) for f in i.imports]
        cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        certificates = []
        certificate_error = None
        if cert_dir.Size:
            try:
                blob = data[cert_dir.VirtualAddress+8:cert_dir.VirtualAddress+cert_dir.Size]
                certificates = [{'subject':c.subject.rfc4514_string(),'issuer':c.issuer.rfc4514_string(),'serial':str(c.serial_number),'expires':c.not_valid_after_utc.isoformat()} for c in pkcs7.load_der_pkcs7_certificates(blob)]
            except ValueError: certificate_error = 'Certificate table could not be decoded'
        sections = [{'name':text(s.Name.rstrip(b'\x00')),'entropy':round(s.get_entropy(),3),'size':s.SizeOfRawData,'virtual_address':s.VirtualAddress} for s in pe.sections]
        versions = {}
        for group in getattr(pe,'FileInfo',[]):
            for entry in group:
                for st in getattr(entry,'StringTable',[]): versions.update({text(k):text(v) for k,v in st.entries.items()})
        return {'architecture':{0x8664:'x64',0x14c:'x86',0xaa64:'ARM64'}.get(pe.FILE_HEADER.Machine,hex(pe.FILE_HEADER.Machine)),
            'entry_point':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),
            'linker_version':f'{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}',
            'compiler':'Not reliably determined','sections':sections,'possible_packing':any(s['entropy']>7.2 for s in sections),
            'imports':imports,'suspicious_apis':[i for i in imports if i['name'] in SUSPICIOUS],
            'exports':[text(s.name) for s in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]) if s.name],
            'resources':[{'id':e.id,'name':str(e.name) if e.name else None} for e in getattr(getattr(pe,'DIRECTORY_ENTRY_RESOURCE',None),'entries',[])],
            'certificate_present':bool(cert_dir.Size),'signature_validation':'NOT_PERFORMED','certificates':certificates,'certificate_error':certificate_error,
            'version_info':versions,'strings':strings,'strings_limit':30000,
            'urls':list(dict.fromkeys(u for s in strings for u in re.findall(r'https?://[^\s"<>]+',s)))[:1000],
            'ips':list(dict.fromkeys(ip for s in strings for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',s)))[:1000],
            'registry_paths':[s for s in strings if re.search(r'HKEY_|Software\\|CurrentVersion\\Run',s,re.I)][:1000],
            'shell_strings':[s for s in strings if re.search(r'powershell|cmd\.exe|Invoke-Expression',s,re.I)][:1000]}
    finally: pe.close()
def scan_yara(data):
    import yara
    paths = sorted(Path(settings.yara_path).glob('**/*.yar*'))
    if not paths: raise FileNotFoundError('No YARA rules installed')
    rules = yara.compile(filepaths={str(i):str(p) for i,p in enumerate(paths)})
    return {'rule_files':len(paths),'matches':[{'rule':m.rule,'tags':m.tags,'meta':m.meta,'strings':[{'identifier':s.identifier,'offset':i.offset,'value':i.matched_data[:256].hex()} for s in m.strings for i in s.instances][:100]} for m in rules.match(data=data,timeout=60)]}
