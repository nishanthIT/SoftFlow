"""Website adapter for the user's SSL checker; original report layout retained."""
import ipaddress
import re
import socket
import ssl
import time
from io import BytesIO
from collections import Counter
from datetime import datetime,timezone
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID
from openpyxl import Workbook
from openpyxl.styles import Font,PatternFill,Alignment,Border,Side
from openpyxl.formatting.rule import FormulaRule
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

PORT=443
TIMEOUT=10
MAX_WORKERS=10
EXPIRING_SOON_DAYS=30
MAX_UPLOAD_BYTES=256*1024
MAX_DOMAINS=500

class NonPublicAddress(ValueError):pass

def parse_upload(data):
    try:text=data.decode('utf-8-sig')
    except UnicodeDecodeError:raise ValueError('Use a UTF-8 text file with one domain per line')
    result=[];seen=set()
    for line in text.splitlines():
        value=line.strip().lower().rstrip('.')
        if not value or value.startswith('#'):continue
        wildcard=value.startswith('*.');host=value[2:] if wildcard else value
        try:host=host.encode('idna').decode('ascii')
        except UnicodeError:raise ValueError('Invalid domain name in the text file')
        if len(host)>253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')):
            raise ValueError('Use domain names only, without URLs, paths, ports or IP addresses')
        try:ipaddress.ip_address(host)
        except ValueError:pass
        else:raise ValueError('Use domain names, not IP addresses')
        value=('*.' if wildcard else '')+host
        if value not in seen:result.append(value);seen.add(value)
        if len(result)>MAX_DOMAINS:raise ValueError('Upload at most 500 unique domains')
    if not result:raise ValueError('The file does not contain any domains')
    return result

def error_result(domain,status,error):
    return dict(domain=domain,ssl_valid='N/A',status=status,expiry_date='',days_remaining='',common_name='',issuer='',san='',error=error)

def public_addresses(domain,deadline):
    resolver=dns.resolver.Resolver();addresses=[]
    for kind in ('A','AAAA'):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('DNS deadline exceeded')
        try:answers=resolver.resolve(domain,kind,lifetime=min(TIMEOUT,remaining),search=False)
        except dns.resolver.NoAnswer:continue
        for answer in answers:
            address=str(answer);ip=ipaddress.ip_address(address)
            # Reject mixed public/private answers too; never reconnect by hostname.
            if not ip.is_global or ip.is_multicast or getattr(ip,'ipv4_mapped',None) is not None:
                raise NonPublicAddress('Domain resolves to a non-public address')
            addresses.append(address)
    if not addresses:raise dns.resolver.NoAnswer('No address found')
    return list(dict.fromkeys(addresses))[:2]

def certificate_dict(der):
    cert=x509.load_der_x509_certificate(der)
    names=lambda value:tuple((("commonName",entry.value),) for entry in value.get_attributes_for_oid(NameOID.COMMON_NAME))
    try:san=tuple(('DNS',value) for value in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:san=()
    return {'notAfter':cert.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT'),
            'subject':names(cert.subject),'issuer':names(cert.issuer),'subjectAltName':san}

def fetch_der(address,domain,context,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('TLS deadline exceeded')
    with socket.create_connection((address,PORT),timeout=min(TIMEOUT,remaining)) as raw:
        raw.settimeout(max(.1,min(TIMEOUT,deadline-time.monotonic())))
        with context.wrap_socket(raw,server_hostname=domain) as tls:return tls.getpeercert(binary_form=True)

def get_certificate(domain):
    deadline=time.monotonic()+20
    try:
        addresses=public_addresses(domain,min(deadline,time.monotonic()+TIMEOUT))
        last=None
        for address in addresses:
            try:
                der=fetch_der(address,domain,ssl.create_default_context(),deadline)
                return {'certificate':certificate_dict(der),'verification_failed':False,'error':''}
            except ssl.SSLCertVerificationError as error:
                reason=str(error)
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
                der=fetch_der(address,domain,context,deadline)
                return {'certificate':certificate_dict(der),'verification_failed':True,'error':reason}
            except (OSError,ssl.SSLError) as error:last=error
        if last:raise last
        raise OSError('No reachable address')
    except dns.exception.Timeout:status='TIMEOUT';reason='DNS lookup timed out'
    except dns.exception.DNSException:status='DNS_ERROR';reason='Domain did not resolve'
    except TimeoutError:status='TIMEOUT';reason='Certificate connection timed out'
    except ConnectionRefusedError:status='CONNECTION_REFUSED';reason='Port 443 refused the connection'
    except ConnectionResetError:status='CONNECTION_RESET';reason='Connection was reset'
    except NonPublicAddress as error:status='INVALID_ADDRESS';reason=str(error)
    except ValueError:status='CERT_PARSE_ERROR';reason='Certificate could not be decoded'
    except ssl.SSLError:status='TLS_ERROR';reason='TLS negotiation failed'
    except OSError:status='CONNECTION_ERROR';reason='Unable to connect to the server'
    except Exception:status='CERT_PARSE_ERROR';reason='Certificate could not be decoded'
    return {'certificate':None,'verification_failed':False,'error':status+': '+reason}



def parse_certificate(cert):

    # --------------------------------------------------------
    # Expiry
    # --------------------------------------------------------

    not_after = cert.get("notAfter")

    expiry_date = ""
    days_remaining = None

    if not_after:

        expiry = datetime.strptime(
            not_after,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        days_remaining = (
            expiry - now
        ).total_seconds() / 86400

        expiry_date = expiry.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

    # --------------------------------------------------------
    # Common Name
    # --------------------------------------------------------

    common_names = []

    for item in cert.get("subject", []):

        for key, value in item:

            if key == "commonName":
                common_names.append(value)

    common_name = ", ".join(common_names)

    # --------------------------------------------------------
    # Issuer
    # --------------------------------------------------------

    issuer_names = []

    for item in cert.get("issuer", []):

        for key, value in item:

            if key == "commonName":
                issuer_names.append(value)

    issuer = ", ".join(issuer_names)

    # --------------------------------------------------------
    # SAN
    # --------------------------------------------------------

    san_entries = []

    for entry_type, value in cert.get(
        "subjectAltName",
        []
    ):

        if entry_type == "DNS":
            san_entries.append(value)

    san = ", ".join(san_entries)

    return (
        expiry_date,
        days_remaining,
        common_name,
        issuer,
        san
    )

def check_domain(domain):

    domain = domain.strip()

    # --------------------------------------------------------
    # Wildcard domains cannot be directly tested.
    # --------------------------------------------------------

    if domain.startswith("*."):

        return {
            "domain": domain,
            "ssl_valid": "N/A",
            "status": "WILDCARD_NOT_TESTED",
            "expiry_date": "",
            "days_remaining": "",
            "common_name": "",
            "issuer": "",
            "san": "",
            "error": (
                "Wildcard hostname cannot be directly "
                "tested. Test an actual subdomain."
            )
        }

    # --------------------------------------------------------
    # Retrieve certificate
    # --------------------------------------------------------

    result = get_certificate(domain)

    cert = result["certificate"]

    # --------------------------------------------------------
    # No certificate
    # --------------------------------------------------------

    if cert is None:

        error = result["error"]

        return {
            "domain": domain,
            "ssl_valid": "N/A",
            "status": (
                error.split(":")[0]
                if ":" in error
                else "ERROR"
            ),
            "expiry_date": "",
            "days_remaining": "",
            "common_name": "",
            "issuer": "",
            "san": "",
            "error": error
        }

    # --------------------------------------------------------
    # Parse certificate
    # --------------------------------------------------------

    try:

        (
            expiry_date,
            days_remaining,
            common_name,
            issuer,
            san
        ) = parse_certificate(cert)

    except Exception as e:

        return {
            "domain": domain,
            "ssl_valid": "N/A",
            "status": "CERT_PARSE_ERROR",
            "expiry_date": "",
            "days_remaining": "",
            "common_name": "",
            "issuer": "",
            "san": "",
            "error": str(e)
        }

    # --------------------------------------------------------
    # Determine expiry status
    # --------------------------------------------------------

    if days_remaining is None:

        status = "UNKNOWN"
        ssl_valid = "N/A"

    elif days_remaining < 0:

        status = "EXPIRED"
        ssl_valid = "NO"

    elif days_remaining <= EXPIRING_SOON_DAYS:

        status = "EXPIRING_SOON"
        ssl_valid = "YES"

    else:

        status = "VALID"
        ssl_valid = "YES"

    # --------------------------------------------------------
    # Certificate verification issue
    #
    # IMPORTANT:
    # A verification failure does NOT automatically mean
    # the certificate is expired.
    # --------------------------------------------------------

    if result["verification_failed"]:

        if days_remaining is not None and days_remaining < 0:

            status = "EXPIRED"
            ssl_valid = "NO"

        elif days_remaining is not None:

            status = "CERT_VERIFICATION_FAILED"

            # Certificate exists and is not expired,
            # but normal trust/verification failed.
            ssl_valid = "N/A"

    return {
        "domain": domain,
        "ssl_valid": ssl_valid,
        "status": status,
        "expiry_date": expiry_date,
        "days_remaining": (
            round(days_remaining, 2)
            if days_remaining is not None
            else ""
        ),
        "common_name": common_name,
        "issuer": issuer,
        "san": san,
        "error": result["error"]
    }

def create_excel(results,metadata=None):

    results=[{key:ILLEGAL_CHARACTERS_RE.sub('',value)[:32767] if isinstance(value,str) else value for key,value in row.items()} for row in results]
    wb = Workbook()

    ws = wb.active
    ws.title = "SSL Results"

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    headers = [
        "Domain",
        "SSL Valid/Renewed",
        "Status",
        "Expiry Date",
        "Days Remaining",
        "Common Name",
        "Issuer",
        "SAN",
        "Error"
    ]

    ws.append(headers)

    # --------------------------------------------------------
    # Header formatting
    # --------------------------------------------------------

    header_fill = PatternFill(
        fill_type="solid",
        fgColor="1F4E78"
    )

    header_font = Font(
        bold=True,
        color="FFFFFF"
    )

    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin")
    )

    for cell in ws[1]:

        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(
            horizontal="center",
            vertical="center"
        )

        cell.border = thin_border

    # --------------------------------------------------------
    # Data
    # --------------------------------------------------------

    for result in results:

        ws.append([
            result["domain"],
            result["ssl_valid"],
            result["status"],
            result["expiry_date"],
            result["days_remaining"],
            result["common_name"],
            result["issuer"],
            result["san"],
            result["error"]
        ])

    # --------------------------------------------------------
    # Cell formatting
    # --------------------------------------------------------

    for row in ws.iter_rows(
        min_row=2,
        max_row=ws.max_row
    ):

        for cell in row:

            cell.border = thin_border
            cell.alignment = Alignment(
                vertical="top",
                wrap_text=True
            )

    # --------------------------------------------------------
    # Conditional formatting
    # --------------------------------------------------------

    # YES
    yes_fill = PatternFill(
        fill_type="solid",
        fgColor="C6EFCE"
    )

    # NO
    no_fill = PatternFill(
        fill_type="solid",
        fgColor="FFC7CE"
    )

    # N/A
    na_fill = PatternFill(
        fill_type="solid",
        fgColor="FFEB9C"
    )

    # Status cells: column C
    status_range = f"C2:C{ws.max_row}"

    ws.conditional_formatting.add(
        status_range,
        FormulaRule(
            formula=['C2="VALID"'],
            fill=yes_fill
        )
    )

    ws.conditional_formatting.add(
        status_range,
        FormulaRule(
            formula=['C2="EXPIRING_SOON"'],
            fill=na_fill
        )
    )

    ws.conditional_formatting.add(
        status_range,
        FormulaRule(
            formula=['C2="EXPIRED"'],
            fill=no_fill
        )
    )

    # SSL Valid column B
    ssl_range = f"B2:B{ws.max_row}"

    ws.conditional_formatting.add(
        ssl_range,
        FormulaRule(
            formula=['B2="YES"'],
            fill=yes_fill
        )
    )

    ws.conditional_formatting.add(
        ssl_range,
        FormulaRule(
            formula=['B2="NO"'],
            fill=no_fill
        )
    )

    ws.conditional_formatting.add(
        ssl_range,
        FormulaRule(
            formula=['B2="N/A"'],
            fill=na_fill
        )
    )

    # --------------------------------------------------------
    # Freeze header
    # --------------------------------------------------------

    ws.freeze_panes = "A2"

    # --------------------------------------------------------
    # Filter
    # --------------------------------------------------------

    ws.auto_filter.ref = ws.dimensions

    # --------------------------------------------------------
    # Column widths
    # --------------------------------------------------------

    widths = {
        "A": 48,
        "B": 20,
        "C": 28,
        "D": 25,
        "E": 18,
        "F": 40,
        "G": 35,
        "H": 70,
        "I": 60
    }

    for column, width in widths.items():

        ws.column_dimensions[column].width = width

    # --------------------------------------------------------
    # Row height
    # --------------------------------------------------------

    ws.row_dimensions[1].height = 25

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    summary=wb.create_sheet('Summary')
    summary.append(['SSL expiry report','Value'])
    for key,value in (metadata or {}).items():summary.append([key,str(value)])
    for key,value in sorted(Counter(row['status'] for row in results).items()):summary.append([key,value])
    summary.append(['Scope','Certificate expiry and trust check; does not establish renewal.'])
    summary.column_dimensions['A'].width=30;summary.column_dimensions['B'].width=90
    for sheet in wb:
        for row in sheet:
            for cell in row:
                if isinstance(cell.value,str):
                    cell.value=ILLEGAL_CHARACTERS_RE.sub('',cell.value)[:32767]
                    cell.data_type='s'
    output=BytesIO();wb.save(output);return output.getvalue()
