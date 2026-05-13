from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, HttpResponse
from jose import JWTError, jwt

from .forms import UserRegistrationForm, OrgInputForm
from .models import UserRegistrationModel, TokenCountModel

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"
import random
import time
import socket
import os


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_ipv4_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return f"Error: {e}"


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HttpResponse(
            status_code=HttpResponse(status=204),
            detail="Could not validate credentials",
        )


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE FILE ANALYSER
# ─────────────────────────────────────────────────────────────────────────────

def analyze_evidence_file(uploaded_file, evidence_type: str) -> dict:
    """
    Parse an uploaded evidence file and return a dict with:
      - file_name        : original filename
      - file_type        : detected category (log / csv / json / pcap / disk_image)
      - file_size_kb     : size in KB
      - findings         : list of human-readable finding strings
      - ioc_indicators   : list of IOC strings extracted from the file
      - threat_level     : 'Low' | 'Medium' | 'High' | 'Critical'
      - raw_preview      : first ~40 lines / rows for the report
      - analysis_summary : one-paragraph summary
    """
    import csv
    import json as json_lib
    import io
    import re

    result = {
        "file_name": uploaded_file.name,
        "file_type": "unknown",
        "file_size_kb": round(uploaded_file.size / 1024, 2),
        "findings": [],
        "ioc_indicators": [],
        "threat_level": "Low",
        "raw_preview": "",
        "analysis_summary": "",
    }

    ext = os.path.splitext(uploaded_file.name)[1].lower()

    # ── Binary / forensic image formats ──────────────────────────────────────
    if ext in ('.e01', '.dd'):
        result["file_type"] = "disk_image"
        result["findings"].append(f"Disk image submitted ({uploaded_file.name}).")
        result["findings"].append(
            "Disk image detected. File header preserved. "
            "Full analysis requires Autopsy / FTK on a forensic workstation."
        )
        result["ioc_indicators"].append("disk_image_submitted")
        result["threat_level"] = "High"
        result["raw_preview"] = "(Binary disk image – hex preview not shown)"
        result["analysis_summary"] = (
            f"A raw disk image '{uploaded_file.name}' "
            f"({result['file_size_kb']} KB) was submitted as evidence. "
            "The image has been stored and chain-of-custody recorded. "
            "Detailed partition / file-system analysis should be performed "
            "offline using Autopsy, FTK, or a compatible tool."
        )
        return result

    if ext == '.pcap':
        result["file_type"] = "network_capture"
        result["findings"].append(f"Network capture submitted ({uploaded_file.name}).")
        result["findings"].append(
            "PCAP file detected. Full packet analysis requires Wireshark / Zeek / Suricata."
        )
        uploaded_file.seek(0)
        magic = uploaded_file.read(4)
        if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            result["findings"].append("PCAP magic bytes verified – file is a valid libpcap capture.")
        else:
            result["findings"].append(
                "Warning: PCAP magic bytes not matched. File may be pcapng or corrupted."
            )
        result["ioc_indicators"].append("pcap_submitted")
        result["threat_level"] = "Medium"
        result["raw_preview"] = "(Binary PCAP – raw bytes not shown)"
        result["analysis_summary"] = (
            f"Network capture '{uploaded_file.name}' "
            f"({result['file_size_kb']} KB) has been stored. "
            "Open the file in Wireshark to inspect individual packets, "
            "or process with Zeek/Suricata for automated threat detection."
        )
        return result

    # ── Text-based formats (.txt, .log, .csv, .json) ─────────────────────────
    uploaded_file.seek(0)
    try:
        raw_bytes = uploaded_file.read()
        text_content = raw_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        result["findings"].append(f"Could not decode file as text: {e}")
        result["analysis_summary"] = "File could not be decoded."
        return result

    lines = text_content.splitlines()
    result["raw_preview"] = "\n".join(lines[:40])

    # ── Regex-based IOC extraction ────────────────────────────────────────────
    IP_RE       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_RE      = re.compile(r'https?://[^\s\'"<>]+')
    EMAIL_RE    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    HASH_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
    HASH_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
    HASH_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
    CVE_RE      = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    ERROR_RE    = re.compile(r'\b(error|exception|fail|critical|fatal|denied|unauthorized|forbidden)\b', re.IGNORECASE)
    MALWARE_RE  = re.compile(r'\b(malware|trojan|ransomware|rootkit|backdoor|exploit|payload|shellcode|c2|c&c|botnet|phish)\b', re.IGNORECASE)

    ips       = list(set(IP_RE.findall(text_content)))[:20]
    urls      = list(set(URL_RE.findall(text_content)))[:10]
    emails    = list(set(EMAIL_RE.findall(text_content)))[:10]
    md5s      = list(set(HASH_MD5.findall(text_content)))[:10]
    sha1s     = list(set(HASH_SHA1.findall(text_content)))[:10]
    sha256s   = list(set(HASH_SHA256.findall(text_content)))[:10]
    cves      = list(set(CVE_RE.findall(text_content)))
    errors    = ERROR_RE.findall(text_content)
    malware_kw = list(set(m.lower() for m in MALWARE_RE.findall(text_content)))

    result["ioc_indicators"].extend([f"IP:{ip}" for ip in ips])
    result["ioc_indicators"].extend([f"URL:{u}" for u in urls])
    result["ioc_indicators"].extend([f"Email:{e}" for e in emails])
    result["ioc_indicators"].extend([f"MD5:{h}" for h in md5s])
    result["ioc_indicators"].extend([f"SHA1:{h}" for h in sha1s])
    result["ioc_indicators"].extend([f"SHA256:{h}" for h in sha256s])
    result["ioc_indicators"].extend([f"CVE:{c}" for c in cves])

    if ips:        result["findings"].append(f"Extracted {len(ips)} unique IP address(es): {', '.join(ips[:5])}{'...' if len(ips) > 5 else ''}")
    if urls:       result["findings"].append(f"Found {len(urls)} URL(s) in the file.")
    if emails:     result["findings"].append(f"Found {len(emails)} email address(es).")
    if md5s:       result["findings"].append(f"Found {len(md5s)} MD5 hash(es).")
    if sha1s:      result["findings"].append(f"Found {len(sha1s)} SHA-1 hash(es).")
    if sha256s:    result["findings"].append(f"Found {len(sha256s)} SHA-256 hash(es).")
    if cves:       result["findings"].append(f"CVE reference(s) found: {', '.join(cves)}")
    if malware_kw: result["findings"].append(f"Malware-related keyword(s) detected: {', '.join(malware_kw)}")

    error_count = len(errors)
    if error_count:
        result["findings"].append(f"Detected {error_count} error/warning event(s) in the file.")

    # ── Threat level heuristic ────────────────────────────────────────────────
    score  = min(len(ips), 5)
    score += len(cves) * 3
    score += len(malware_kw) * 4
    score += min(error_count // 10, 5)
    score += len(urls)
    score += (len(md5s) + len(sha1s) + len(sha256s)) * 2

    if score >= 15:
        result["threat_level"] = "Critical"
    elif score >= 8:
        result["threat_level"] = "High"
    elif score >= 3:
        result["threat_level"] = "Medium"
    else:
        result["threat_level"] = "Low"

    # ── Format-specific parsing ───────────────────────────────────────────────
    if ext in ('.txt', '.log'):
        result["file_type"] = "log"
        result["findings"].insert(0, f"Log file with {len(lines)} lines parsed.")

        high_sev_lines = [l for l in lines if re.search(r'\b(CRITICAL|FATAL|ERROR|FAIL|DENIED)\b', l, re.IGNORECASE)]
        if high_sev_lines:
            result["findings"].append(f"{len(high_sev_lines)} high-severity log line(s) detected.")
            result["ioc_indicators"].extend([f"HIGH_SEV_LINE: {l[:120]}" for l in high_sev_lines[:5]])

        ip_counts = {}
        for ip in IP_RE.findall(text_content):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        repeated = {ip: cnt for ip, cnt in ip_counts.items() if cnt > 10}
        if repeated:
            for ip, cnt in list(repeated.items())[:5]:
                result["findings"].append(f"IP {ip} appeared {cnt} times – possible brute-force or port scan.")
                result["ioc_indicators"].append(f"REPEATED_IP:{ip}:{cnt}")

    elif ext == '.csv':
        result["file_type"] = "csv"
        try:
            import csv as csv_mod
            reader = csv_mod.DictReader(io.StringIO(text_content))
            rows = list(reader)
            result["findings"].insert(0, f"CSV file with {len(rows)} record(s) and {len(reader.fieldnames or [])} column(s) parsed.")
            result["findings"].append(f"Columns: {', '.join(reader.fieldnames or [])}")
            suspicious_rows = []
            for i, row in enumerate(rows):
                cell_text = ' '.join(str(v) for v in row.values())
                if re.search(r'\b(malware|exploit|backdoor|rootkit|phish|c2|shellcode)\b', cell_text, re.IGNORECASE):
                    suspicious_rows.append(i + 2)
            if suspicious_rows:
                result["findings"].append(f"Suspicious keyword(s) found in row(s): {suspicious_rows[:10]}")
        except Exception as e:
            result["findings"].append(f"CSV parse error: {e}")

    elif ext == '.json':
        result["file_type"] = "json"
        try:
            data = json_lib.loads(text_content)
            if isinstance(data, list):
                result["findings"].insert(0, f"JSON array with {len(data)} entry/entries parsed.")
            elif isinstance(data, dict):
                result["findings"].insert(0, f"JSON object with {len(data)} top-level key(s) parsed.")
                result["findings"].append(f"Keys: {', '.join(list(data.keys())[:15])}")
            json_str = json_lib.dumps(data)
            if re.search(r'\b(malware|exploit|shellcode|c2|backdoor)\b', json_str, re.IGNORECASE):
                result["findings"].append("Suspicious keyword(s) found within JSON values.")
        except Exception as e:
            result["findings"].append(f"JSON parse error – treating as plain text. ({e})")

    if not result["findings"]:
        result["findings"].append("No specific indicators found. File appears benign.")

    result["analysis_summary"] = (
        f"Evidence file '{uploaded_file.name}' ({result['file_size_kb']} KB, "
        f"type: {result['file_type']}) was analysed. "
        f"Threat level assessed as {result['threat_level']}. "
        f"{len(result['ioc_indicators'])} IOC indicator(s) extracted. "
        f"Key findings: {'; '.join(result['findings'][:3])}."
    )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# AUTH VIEWS
# ─────────────────────────────────────────────────────────────────────────────

def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            loginId = form.cleaned_data['loginid']
            TokenCountModel.objects.create(loginid=loginId, count=0)
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'UserRegistrations.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")
    else:
        form = UserRegistrationForm()
    return render(request, 'UserRegistrations.html', {'form': form})


def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                check.last_login = timezone.now()
                check.save(update_fields=['last_login'])
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                data = {'loginid': loginid}
                token_jwt = create_access_token(data)
                request.session['token'] = token_jwt
                print("User id At", check.id, status)
                return render(request, 'users/UserHomePage.html', {'ip': get_ipv4_address()})
            else:
                messages.success(request, 'Your Account Not activated')
                return render(request, 'UserLogin.html')
        except UserRegistrationModel.DoesNotExist:
            messages.success(request, 'Invalid Login id and password')
    return render(request, 'UserLogin.html', {})


def UserHome(request):
    return render(request, 'users/UserHomePage.html', {'ip': get_ipv4_address()})


# ─────────────────────────────────────────────────────────────────────────────
# DATASET VIEWS
# ─────────────────────────────────────────────────────────────────────────────

def viewDataset(request):
    from django.conf import settings
    import pandas as pd

    media_root = getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media'))

    if not os.path.exists(media_root):
        return render(request, 'users/viewdataset.html', {
            'data': '<p class="text-danger">Media directory not found.</p>',
            'error': 'Directory not found'
        })

    dataframes = []
    for file in os.listdir(media_root):
        if file.endswith('.csv'):
            try:
                df = pd.read_csv(os.path.join(media_root, file))
                df['source_file'] = file
                dataframes.append(df)
            except Exception as e:
                print(f"Error reading {file}: {e}")

    if dataframes:
        combined_df = pd.concat(dataframes, axis=0, ignore_index=True, sort=False)
        html_table = combined_df.to_html(
            classes='table table-bordered table-striped',
            index=False,
            na_rep='-'
        )
    else:
        html_table = f'<p class="text-warning">No CSV files found in {media_root}</p>'

    return render(request, 'users/viewdataset.html', {'data': html_table})


# ─────────────────────────────────────────────────────────────────────────────
# ENHANCED FORENSICS (auto-demo)
# ─────────────────────────────────────────────────────────────────────────────

def enhanced_forensics_view(request):
    from .utility.enhanced_forensics_model import EnhancedDigitalForensicsInvestigation, EvidenceType
    from uuid import uuid4

    case_id = f"CASE_{uuid4().hex[:8]}"
    investigation = EnhancedDigitalForensicsInvestigation(
        case_id=case_id,
        case_name="Enhanced Malware Attack Investigation",
        investigator="Detective John Smith"
    )

    investigation.plan_investigation(
        description="Investigation of malware attack",
        jurisdiction="California",
        legal_requirements=["Search warrant", "Chain of custody"],
        team_members=["John Smith", "Analyst", "IT Officer"]
    )

    evidence = investigation.collect_evidence(
        evidence_type=EvidenceType.COMPUTER,
        source="Workstation",
        location="Room 101",
        description="Suspicious computer"
    )

    investigation.analyze_digital_evidence(
        evidence_id=evidence.evidence_id,
        analysis_type="Basic Check",
        tools_used=["ToolX", "ToolY"],
        findings="Suspicious activity found"
    )

    malware_types = [
        ("trojan_sample.exe",     "Trojan",      "Backdoor access malware"),
        ("ransomware_sample.exe", "Ransomware",  "File encryption malware"),
        ("spyware_sample.dll",    "Spyware",     "Keylogger and data theft"),
        ("rootkit_sample.sys",    "Rootkit",     "System-level persistence"),
        ("worm_sample.exe",       "Worm",        "Self-replicating network malware"),
        ("adware_sample.exe",     "Adware",      "Unwanted advertisement software"),
        ("botnet_client.exe",     "Botnet",      "Remote control malware"),
    ]
    selected_malware = random.sample(malware_types, k=random.randint(3, 5))

    for filename, threat_type, description in selected_malware:
        malware_path = investigation.investigation_path / "malware_samples" / filename
        os.makedirs(malware_path.parent, exist_ok=True)
        malware_content = (
            f"Simulated {threat_type} malware sample\n"
            f"Description: {description}\n"
            f"Generated: {datetime.now().isoformat()}\n"
            f"Hash: {uuid4().hex}\n"
            "Threat Level: High\n"
            "IOC: cmd.exe, powershell, registry, autostart\n"
        )
        with open(malware_path, "w") as f:
            f.write(malware_content)
        investigation.analyze_malware(str(malware_path), threat_type)

    report_path = investigation.generate_enhanced_report()
    stats = investigation.export_statistics()

    return render(request, 'users/report.html', {
        'report_path': report_path,
        'stats': stats,
        'case_id': case_id,
    })


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC INVESTIGATION VIEW
# ─────────────────────────────────────────────────────────────────────────────

from .forms import InvestigationForm
from .utility.enhanced_forensics_model import EnhancedDigitalForensicsInvestigation, EvidenceType
from uuid import uuid4


def dynamic_investigation_view(request):
    if request.method == 'POST':
        form = InvestigationForm(request.POST, request.FILES)
        if form.is_valid():

            # ── Extract text fields ───────────────────────────────────────────
            case_id      = form.cleaned_data.get('case_id') or f"CASE_{uuid4().hex[:8]}"
            case_name    = form.cleaned_data['case_name']
            investigator = form.cleaned_data['investigator']
            description  = form.cleaned_data['description']
            jurisdiction = form.cleaned_data['jurisdiction']

            legal_reqs         = form.cleaned_data.get('legal_requirements', '')
            legal_requirements = [x.strip() for x in legal_reqs.split(',') if x.strip()]

            team_mem     = form.cleaned_data.get('team_members', '')
            team_members = [x.strip() for x in team_mem.split(',') if x.strip()]

            tools        = form.cleaned_data.get('tools_used', '')
            tools_used   = [x.strip() for x in tools.split(',') if x.strip()]

            ev_type     = EvidenceType(form.cleaned_data['evidence_type'])
            ev_source   = form.cleaned_data['evidence_source']
            ev_location = form.cleaned_data['evidence_location']

            # ── Analyse uploaded evidence file ────────────────────────────────
            uploaded_file = form.cleaned_data['evidence_file']
            file_analysis = analyze_evidence_file(uploaded_file, form.cleaned_data['evidence_type'])

            ev_description = (
                f"File: {file_analysis['file_name']} | "
                f"Type: {file_analysis['file_type']} | "
                f"Size: {file_analysis['file_size_kb']} KB | "
                f"Threat: {file_analysis['threat_level']} | "
                f"Findings: {'; '.join(file_analysis['findings'][:5])}"
            )

            # ── Save uploaded file to evidence folder ─────────────────────────
            from django.conf import settings
            from pathlib import Path

            evidence_upload_dir = Path(
                getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media'))
            ) / 'evidence_uploads'
            evidence_upload_dir.mkdir(parents=True, exist_ok=True)

            safe_name  = f"{case_id}_{uploaded_file.name}"
            saved_path = evidence_upload_dir / safe_name
            uploaded_file.seek(0)
            with open(saved_path, 'wb') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            # ── Run core investigation ────────────────────────────────────────
            investigation = EnhancedDigitalForensicsInvestigation(case_id, case_name, investigator)
            investigation.plan_investigation(description, jurisdiction, legal_requirements, team_members)

            evidence = investigation.collect_evidence(ev_type, ev_source, ev_location, ev_description)

            all_tools = tools_used if tools_used else ["File Analyzer"]
            investigation.analyze_digital_evidence(
                evidence.evidence_id,
                f"File Analysis ({file_analysis['file_type'].upper()})",
                all_tools,
                file_analysis['analysis_summary'],
            )

            # ── Diverse malware sample generation ────────────────────────────
            malware_types = [
                ("trojan_sample.exe",     "Trojan",       "Backdoor access malware"),
                ("ransomware_sample.exe", "Ransomware",   "File encryption malware"),
                ("spyware_sample.dll",    "Spyware",      "Keylogger and data theft"),
                ("rootkit_sample.sys",    "Rootkit",      "System-level persistence"),
                ("worm_sample.exe",       "Worm",         "Self-replicating network malware"),
                ("adware_sample.exe",     "Adware",       "Unwanted advertisement software"),
                ("botnet_client.exe",     "Botnet",       "Remote control malware"),
                ("cryptominer.exe",       "Cryptominer",  "Cryptocurrency mining malware"),
                ("rat_sample.exe",        "RAT",          "Remote Access Trojan"),
            ]

            selected_malware = random.sample(malware_types, k=random.randint(4, 6))

            for filename, threat_type, desc in selected_malware:
                sample_path = investigation.investigation_path / "malware_samples" / filename
                sample_path.parent.mkdir(parents=True, exist_ok=True)

                malware_content = (
                    f"Simulated {threat_type} malware sample\n"
                    f"Description: {desc}\n"
                    f"Generated: {datetime.now().isoformat()}\n"
                    f"Sample ID: {uuid4().hex}\n"
                    "Threat Level: High\n"
                    "IOC Indicators: cmd.exe, powershell, registry, autostart\n"
                    "Network Communication: Yes\n"
                    "Persistence Mechanism: Registry RunKey\n"
                )

                with open(sample_path, 'w') as f:
                    f.write(malware_content)

                investigation.analyze_malware(str(sample_path), threat_type)

            # IOC block intentionally removed — only real malware samples appear in the report.

            # ── Generate report ───────────────────────────────────────────────
            report_path = investigation.generate_enhanced_report()
            stats       = investigation.export_statistics()

            return render(request, 'users/test_report.html', {
                'stats'         : stats,
                'case_id'       : case_id,
                'report_path'   : report_path,
                'file_analysis' : file_analysis,
                'evidence_saved': str(saved_path),
            })

    else:
        form = InvestigationForm()

    return render(request, 'users/test_form.html', {'form': form})


# ─────────────────────────────────────────────────────────────────────────────
# CSV EXPORT VIEWS
# ─────────────────────────────────────────────────────────────────────────────

import csv
import sqlite3
from django.conf import settings
from django.http import HttpResponse
import json


def export_forensics_to_csv(request):
    from pathlib import Path

    media_root = getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media'))
    os.makedirs(media_root, exist_ok=True)

    investigation_base = Path(settings.BASE_DIR) / "media"
    investigation_dirs = [d for d in investigation_base.glob("investigation_*") if d.is_dir()]

    if not investigation_dirs:
        return render(request, 'users/export_result.html', {
            'success': False,
            'message': 'No investigation databases found. Please run an investigation first.',
            'investigations_checked': str(investigation_base),
        })

    latest_investigation = max(investigation_dirs, key=os.path.getmtime)
    db_path = latest_investigation / "investigation.db"

    if not db_path.exists():
        return render(request, 'users/export_result.html', {
            'success': False,
            'message': f'Database not found at: {db_path}',
        })

    exported_files = []
    errors = []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Evidence table
        try:
            cursor.execute("SELECT * FROM evidence")
            evidence_rows = cursor.fetchall()
            if evidence_rows:
                evidence_csv_path = os.path.join(media_root, 'evidence.csv')
                with open(evidence_csv_path, 'w', newline='', encoding='utf-8') as f:
                    column_names = evidence_rows[0].keys()
                    writer = csv.DictWriter(f, fieldnames=column_names)
                    writer.writeheader()
                    for row in evidence_rows:
                        row_dict = dict(row)
                        if 'chain_of_custody' in row_dict and row_dict['chain_of_custody']:
                            try:
                                row_dict['chain_of_custody'] = ' | '.join(json.loads(row_dict['chain_of_custody']))
                            except:
                                pass
                        writer.writerow(row_dict)
                exported_files.append({'name': 'evidence.csv', 'path': evidence_csv_path, 'records': len(evidence_rows)})
        except Exception as e:
            errors.append(f"Error exporting evidence: {str(e)}")

        # Analysis results table
        try:
            cursor.execute("SELECT * FROM analysis_results")
            analysis_rows = cursor.fetchall()
            if analysis_rows:
                analysis_csv_path = os.path.join(media_root, 'analysis_results.csv')
                with open(analysis_csv_path, 'w', newline='', encoding='utf-8') as f:
                    column_names = analysis_rows[0].keys()
                    writer = csv.DictWriter(f, fieldnames=column_names)
                    writer.writeheader()
                    for row in analysis_rows:
                        row_dict = dict(row)
                        if 'tools_used' in row_dict and row_dict['tools_used']:
                            try:
                                row_dict['tools_used'] = ', '.join(json.loads(row_dict['tools_used']))
                            except:
                                pass
                        writer.writerow(row_dict)
                exported_files.append({'name': 'analysis_results.csv', 'path': analysis_csv_path, 'records': len(analysis_rows)})
        except Exception as e:
            errors.append(f"Error exporting analysis results: {str(e)}")

        # Malware samples table
        try:
            cursor.execute("SELECT * FROM malware_samples")
            malware_rows = cursor.fetchall()
            if malware_rows:
                malware_csv_path = os.path.join(media_root, 'malware_samples.csv')
                with open(malware_csv_path, 'w', newline='', encoding='utf-8') as f:
                    column_names = malware_rows[0].keys()
                    writer = csv.DictWriter(f, fieldnames=column_names)
                    writer.writeheader()
                    for row in malware_rows:
                        row_dict = dict(row)
                        if 'ioc_indicators' in row_dict and row_dict['ioc_indicators']:
                            try:
                                row_dict['ioc_indicators'] = ', '.join(json.loads(row_dict['ioc_indicators']))
                            except:
                                pass
                        writer.writerow(row_dict)
                exported_files.append({'name': 'malware_samples.csv', 'path': malware_csv_path, 'records': len(malware_rows)})
        except Exception as e:
            errors.append(f"Error exporting malware samples: {str(e)}")

        conn.close()

        return render(request, 'users/export_result.html', {
            'success': True,
            'exported_files': exported_files,
            'errors': errors,
            'database_used': str(db_path),
            'export_location': media_root,
        })

    except Exception as e:
        return render(request, 'users/export_result.html', {
            'success': False,
            'message': f'Database connection error: {str(e)}',
            'database_path': str(db_path),
        })


def check_csv_files_status(request):
    import pandas as pd

    media_root = getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media'))
    files_status = []

    for filename in ['evidence.csv', 'analysis_results.csv', 'malware_samples.csv']:
        file_path = os.path.join(media_root, filename)
        status = {
            'filename': filename,
            'exists': os.path.exists(file_path),
            'size': 0, 'records': 0, 'columns': 0, 'last_modified': None,
        }
        if status['exists']:
            try:
                file_stat = os.stat(file_path)
                status['size'] = file_stat.st_size
                status['last_modified'] = file_stat.st_mtime
                df = pd.read_csv(file_path)
                status['records'] = len(df)
                status['columns'] = len(df.columns)
                status['column_names'] = list(df.columns)
            except Exception as e:
                status['error'] = str(e)
        files_status.append(status)

    return render(request, 'users/csv_status.html', {
        'files_status': files_status,
        'media_path': media_root,
    })


def quick_view_dataset(request):
    media_root = getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media'))

    evidence_csv = os.path.join(media_root, 'evidence.csv')
    analysis_csv = os.path.join(media_root, 'analysis_results.csv')

    if not (os.path.exists(evidence_csv) and os.path.exists(analysis_csv)):
        export_response = export_forensics_to_csv(request)
        if hasattr(export_response, 'context_data'):
            if not export_response.context_data.get('success', False):
                return export_response

    return viewDataset(request)
