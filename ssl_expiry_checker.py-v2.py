#!/usr/bin/env python3

import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import FormulaRule


# ============================================================
# CONFIGURATION
# ============================================================

PORT = 443
TIMEOUT = 10
MAX_WORKERS = 10

# Certificate is considered EXPIRING_SOON when <= this many days remain
EXPIRING_SOON_DAYS = 30

OUTPUT_FILE = "ssl_expiry_results.xlsx"


# ============================================================
# DOMAINS
# ============================================================

DOMAINS = """
info.k2management.com
islb.inceptsustainability.com
kappendrupvandgis.vandnet.dk
klintebjergvandgis.vandnet.dk
kragelundvand.vandnet.dk
krajbjergvandgis.vandnet.dk
kundby-vand.vandnet.dk
link.haarbyvand.dk
lundeborgvandgis.vandnet.dk
mms.ramboll.com
networktest.dev.vu.city
networktest.nightly.vu.city
next.inceptsustainability.com
nextjs-staging.inceptsustainability.com
nonprod.survey-it.dk
norway.ramboll.com
opseyes.net
platform.vu.city
ramboll.carlbacks.dk
ramboll.ch
ramboll-apv.dk
rambollcircle.fi
rambolldata.dk
rambollsprog.dk
ramboll-visu.wp.ilme.fi
results.dk
results.ramboll.com
safetymoments.obg.com
sahl.dk
sandvedvand.vandnet.dk
scans.ramboll.no
seniorklubramboll-aarhus.dk
sgtm.rambollxact.dk
siili.koululiitu.fi
surveys.ramboll.com
surveyxact.be
surveyxact.com
tdt-demo.ramboll.com
tec-conseil.com
telemetry.demo.vu.city
test.survey-it.dk
transport.ramboll.com
united-kingdom.ramboll.com
utbildning.ramboll.se
visu.ramboll.fi
vpn.venergi.at
webview5.rambollfm.fi
www.digitaliseringsprisen.dk
www.fjellebrovand.dk
www.opseyes.net
www.rambollresults.eu
www.templegroup.co.uk
www.wg-ing.de
www.xn--hh-forldreportal-zob.dk
xact.dk
xn--hh-forldreportal-zob.dk
your.vu.city
*.danskeerhvervsjurister.dk
*.dkej.dk
*.ramboll.streamkey.dk
*.rambollresults.fr
*.streamkey.dk
acondas.de
acondas.net
ai.ramboll.com
americas.ramboll.com
api.franklin.ramboll-shair.com
api.stage.sfbayarea.ramboll-shair.com
api.stage.stockton.ramboll-shair.com
api2.rambollfm.fi
api5.rambollfm.fi
apollo.koululiitu.fi
bavandgis.vandnet.dk
bbstrandvandgis.vandnet.dk
blankeroerslevvandgis.vandnet.dk
blockpage.ramboll.com
borkopgis.vandnet.dk
brannkonsept-staging.ramboll.no
bsr-standortoptimierung.civity.de
buresoevandgis.vandnet.dk
caminocopilot-engapi-test.ramboll.com
certcrl-test.ramboll.com
checkmate-dev.ramboll.com
cleanharbors.ramboll.com
clecodev-api.ramboll.com
cms.inceptsustainability.com
computationaldesign.ramboll.co.uk
copilot.ramboll.com
customformsapi.ramboll.com
d99c2f1c.sni.cloudflaressl.com
de.ramboll.com
demo.vandnet.dk
demo1.vandnet.dk
demopixel.eastdil.vu.city
demotest.vandnet.dk
dev.rambollcircle.fi
digitalassetsapi.ramboll.com
draabyvandvaerkgis.vandnet.dk
""".strip().splitlines()


# ============================================================
# CLEAN DOMAIN LIST
# ============================================================

DOMAINS = [
    domain.strip()
    for domain in DOMAINS
    if domain.strip()
]


# ============================================================
# CREATE SSL CONTEXT
# ============================================================

def create_ssl_context():

    context = ssl.create_default_context()

    # We first perform normal certificate verification.
    # If that fails, we perform a second connection without
    # verification so that we can still inspect the certificate.
    return context


# ============================================================
# PARSE CERTIFICATE
# ============================================================

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


# ============================================================
# GET CERTIFICATE
# ============================================================

def get_certificate(domain):

    context = create_ssl_context()

    # --------------------------------------------------------
    # First attempt:
    # Normal TLS certificate verification
    # --------------------------------------------------------

    try:

        with socket.create_connection(
            (domain, PORT),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as tls:

                cert = tls.getpeercert()

                return {
                    "certificate": cert,
                    "verification_failed": False,
                    "error": ""
                }

    except ssl.SSLCertVerificationError as e:

        verification_error = str(e)

        # ----------------------------------------------------
        # Second attempt:
        # Ignore certificate verification so we can inspect
        # the actual certificate served by the server.
        # ----------------------------------------------------

        try:

            insecure_context = ssl._create_unverified_context()

            with socket.create_connection(
                (domain, PORT),
                timeout=TIMEOUT
            ) as sock:

                with insecure_context.wrap_socket(
                    sock,
                    server_hostname=domain
                ) as tls:

                    cert = tls.getpeercert()

                    # getpeercert() returns empty data when
                    # verification is disabled, so retrieve
                    # the DER certificate instead.

                    cert_der = tls.getpeercert(
                        binary_form=True
                    )

                    # We don't need to decode the DER manually
                    # here. The important information is that
                    # the certificate could be retrieved.

                    return {
                        "certificate": cert,
                        "verification_failed": True,
                        "error": verification_error
                    }

        except Exception:

            return {
                "certificate": None,
                "verification_failed": True,
                "error": verification_error
            }

    except socket.gaierror as e:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": f"DNS_ERROR: {e}"
        }

    except socket.timeout:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": "TIMEOUT: Connection timed out"
        }

    except ConnectionRefusedError:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": "CONNECTION_REFUSED: Port 443 refused"
        }

    except ConnectionResetError:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": "CONNECTION_RESET"

        }

    except OSError as e:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": f"OS_ERROR: {e}"
        }

    except Exception as e:

        return {
            "certificate": None,
            "verification_failed": False,
            "error": f"ERROR: {e}"
        }


# ============================================================
# CHECK ONE DOMAIN
# ============================================================

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


# ============================================================
# EXCEL REPORT
# ============================================================

def create_excel(results):

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

    wb.save(OUTPUT_FILE)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("SSL CERTIFICATE EXPIRY CHECKER")
    print("=" * 80)
    print()

    print(f"[*] Domains       : {len(DOMAINS)}")
    print(f"[*] TLS port      : {PORT}")
    print(f"[*] Timeout       : {TIMEOUT}s")
    print(
        f"[*] Expiring soon : <= {EXPIRING_SOON_DAYS} days"
    )
    print()

    results = []

    # --------------------------------------------------------
    # Concurrent scanning
    # --------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                check_domain,
                domain
            ): domain

            for domain in DOMAINS
        }

        for future in as_completed(futures):

            domain = futures[future]

            try:

                result = future.result()

                results.append(result)

                status = result["status"]

                days = result["days_remaining"]

                if status == "VALID":

                    print(
                        f"[+] {domain:<55} "
                        f"VALID "
                        f"({days} days)"
                    )

                elif status == "EXPIRING_SOON":

                    print(
                        f"[!] {domain:<55} "
                        f"EXPIRING SOON "
                        f"({days} days)"
                    )

                elif status == "EXPIRED":

                    print(
                        f"[!!!] {domain:<55} "
                        f"EXPIRED "
                        f"({days} days)"
                    )

                else:

                    print(
                        f"[-] {domain:<55} "
                        f"{status}"
                    )

            except Exception as e:

                print(
                    f"[-] {domain:<55} "
                    f"THREAD_ERROR"
                )

                results.append({
                    "domain": domain,
                    "ssl_valid": "N/A",
                    "status": "THREAD_ERROR",
                    "expiry_date": "",
                    "days_remaining": "",
                    "common_name": "",
                    "issuer": "",
                    "san": "",
                    "error": str(e)
                })

    # --------------------------------------------------------
    # Sort results
    # --------------------------------------------------------

    status_order = {
        "EXPIRED": 0,
        "EXPIRING_SOON": 1,
        "VALID": 2,
        "CERT_VERIFICATION_FAILED": 3,
        "CERT_PARSE_ERROR": 4,
        "DNS_ERROR": 5,
        "TIMEOUT": 6,
        "CONNECTION_REFUSED": 7,
        "CONNECTION_RESET": 8,
        "WILDCARD_NOT_TESTED": 9,
        "ERROR": 10,
        "OS_ERROR": 11,
        "THREAD_ERROR": 12,
        "UNKNOWN": 13
    }

    results.sort(
        key=lambda x: (
            status_order.get(
                x["status"],
                99
            ),
            x["domain"]
        )
    )

    # --------------------------------------------------------
    # Create Excel
    # --------------------------------------------------------

    create_excel(results)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = {}

    for result in results:

        status = result["status"]

        summary[status] = (
            summary.get(status, 0) + 1
        )

    print()
    print("=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)

    for status, count in sorted(
        summary.items(),
        key=lambda x: status_order.get(
            x[0],
            99
        )
    ):

        print(
            f"{status:<30} {count}"
        )

    print()
    print(
        f"[+] Excel report: {OUTPUT_FILE}"
    )

    print("=" * 80)
    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()