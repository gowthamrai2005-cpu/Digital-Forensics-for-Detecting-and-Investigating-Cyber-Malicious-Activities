"""
Enhanced Digital Forensics Investigation Model
Extended implementation with visualization, statistical analysis, and advanced reporting features
Based on "Forensic Investigation of Malicious Activities in Digital Environments"
"""

# ── FIX 1: Force non-GUI matplotlib backend BEFORE any other matplotlib import ──
import matplotlib
matplotlib.use('Agg')   # Prevents Tkinter/GUI crash in Django threads
import matplotlib.pyplot as plt
# ────────────────────────────────────────────────────────────────────────────────

import os
import hashlib
import json
import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import csv
import zipfile
import shutil
from pathlib import Path
import seaborn as sns
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationStatus(Enum):
    PLANNING = "planning"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    MALWARE_ANALYSIS = "malware_analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"


class EvidenceType(Enum):
    COMPUTER = "computer"
    MOBILE_DEVICE = "mobile_device"
    NETWORK_LOGS = "network_logs"
    CLOUD_SERVICES = "cloud_services"
    REMOVABLE_MEDIA = "removable_media"
    MEMORY_DUMP = "memory_dump"


class MaliciousActivityType(Enum):
    MALWARE_ATTACK = "malware_attack"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    CYBER_ESPIONAGE = "cyber_espionage"
    IDENTITY_THEFT = "identity_theft"


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InvestigationCase:
    case_id: str
    case_name: str
    description: str
    jurisdiction: str
    investigator: str
    start_date: datetime.datetime
    status: InvestigationStatus
    legal_requirements: List[str]
    team_members: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DigitalEvidence:
    evidence_id: str
    case_id: str
    evidence_type: EvidenceType
    source: str
    location: str
    collection_date: datetime.datetime
    hash_value: str
    description: str
    chain_of_custody: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    result_id: str
    case_id: str
    evidence_id: str
    analysis_type: str
    findings: str
    tools_used: List[str]
    analysis_date: datetime.datetime
    analyst: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class EnhancedDigitalForensicsInvestigation:
    """
    Enhanced digital forensics investigation model with visualization and advanced analysis.
    """

    def __init__(self, case_id: str, case_name: str, investigator: str):
        self.case_id = case_id
        self.case_name = case_name
        self.investigator = investigator
        self.case = None
        self.evidence_list: List[DigitalEvidence] = []
        self.analysis_results: List[AnalysisResult] = []
        self.malware_samples: List[Dict] = []
        self.investigation_path = Path(f"media/investigation_{case_id}")
        self.database_path = self.investigation_path / "investigation.db"

        self._create_directory_structure()
        self._initialize_database()

        # ── FIX 2: Use a thread-safe matplotlib style ──────────────────────
        try:
            plt.style.use('seaborn-v0_8-darkgrid')
        except OSError:
            plt.style.use('ggplot')  # fallback if seaborn style not available
        sns.set_palette("husl")
        # ───────────────────────────────────────────────────────────────────

        logger.info(f"Initialized enhanced investigation: {case_name} (ID: {case_id})")

    # ── Directory & DB setup ─────────────────────────────────────────────────

    def _create_directory_structure(self):
        directories = [
            "evidence", "analysis", "reports", "malware_samples",
            "logs", "backups", "visualizations", "statistics"
        ]
        for directory in directories:
            (self.investigation_path / directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"Created enhanced investigation directory structure: {self.investigation_path}")

    def _initialize_database(self):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT,
                description TEXT,
                jurisdiction TEXT,
                investigator TEXT,
                start_date TEXT,
                status TEXT,
                legal_requirements TEXT,
                team_members TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT,
                evidence_type TEXT,
                source TEXT,
                location TEXT,
                collection_date TEXT,
                hash_value TEXT,
                description TEXT,
                chain_of_custody TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                result_id TEXT PRIMARY KEY,
                case_id TEXT,
                evidence_id TEXT,
                analysis_type TEXT,
                findings TEXT,
                tools_used TEXT,
                analysis_date TEXT,
                analyst TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id),
                FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_samples (
                sample_id TEXT PRIMARY KEY,
                case_id TEXT,
                filename TEXT,
                hash_value TEXT,
                analysis_status TEXT,
                threat_type TEXT,
                ioc_indicators TEXT,
                analysis_date TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Initialized enhanced investigation database")

    # ── Investigation steps ──────────────────────────────────────────────────

    def plan_investigation(self, description: str, jurisdiction: str,
                           legal_requirements: List[str], team_members: List[str]) -> InvestigationCase:
        """Step 1: Case Planning and Preparation"""
        self.case = InvestigationCase(
            case_id=self.case_id,
            case_name=self.case_name,
            description=description,
            jurisdiction=jurisdiction,
            investigator=self.investigator,
            start_date=datetime.datetime.now(),
            status=InvestigationStatus.PLANNING,
            legal_requirements=legal_requirements,
            team_members=team_members
        )

        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.case.case_id,
            self.case.case_name,
            self.case.description,
            self.case.jurisdiction,
            self.case.investigator,
            self.case.start_date.isoformat(),
            self.case.status.value,
            json.dumps(self.case.legal_requirements),
            json.dumps(self.case.team_members)
        ))
        conn.commit()
        conn.close()

        logger.info(f"Enhanced investigation planned: {self.case.case_name}")
        return self.case

    def collect_evidence(self, evidence_type: EvidenceType, source: str,
                         location: str, description: str) -> DigitalEvidence:
        """Step 2: Evidence Collection and Preservation"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute("SELECT evidence_id FROM evidence WHERE case_id = ?", (self.case_id,))
        existing_ids = [row[0] for row in cursor.fetchall()]

        max_num = 0
        for eid in existing_ids:
            try:
                num = int(eid.split('_')[-1])
                if num > max_num:
                    max_num = num
            except Exception:
                continue
        new_counter = max_num + 1
        evidence_id = f"EVID_{self.case_id}_{new_counter:04d}"

        collection_date = datetime.datetime.now()
        hash_value = self._generate_evidence_hash(source, location)

        chain_of_custody = [
            f"{collection_date.isoformat()} - Collected by {self.investigator}",
            f"Source: {source}",
            f"Location: {location}"
        ]

        evidence = DigitalEvidence(
            evidence_id=evidence_id,
            case_id=self.case_id,
            evidence_type=evidence_type,
            source=source,
            location=location,
            collection_date=collection_date,
            hash_value=hash_value,
            description=description,
            chain_of_custody=chain_of_custody
        )

        self.evidence_list.append(evidence)

        cursor.execute('''
            INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence.evidence_id,
            evidence.case_id,
            evidence.evidence_type.value,
            evidence.source,
            evidence.location,
            evidence.collection_date.isoformat(),
            evidence.hash_value,
            evidence.description,
            json.dumps(evidence.chain_of_custody)
        ))
        conn.commit()
        conn.close()

        logger.info(f"Evidence collected: {evidence_id} - {evidence_type.value}")
        return evidence

    def _generate_evidence_hash(self, source: str, location: str) -> str:
        content = f"{source}{location}{datetime.datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()

    def analyze_digital_evidence(self, evidence_id: str, analysis_type: str,
                                  tools_used: List[str], findings: str) -> AnalysisResult:
        """Step 3: Digital Data Analysis"""
        result_id = f"ANALYSIS_{self.case_id}_{len(self.analysis_results) + 1:04d}"
        analysis_date = datetime.datetime.now()

        result = AnalysisResult(
            result_id=result_id,
            case_id=self.case_id,
            evidence_id=evidence_id,
            analysis_type=analysis_type,
            findings=findings,
            tools_used=tools_used,
            analysis_date=analysis_date,
            analyst=self.investigator
        )

        self.analysis_results.append(result)

        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.result_id,
            result.case_id,
            result.evidence_id,
            result.analysis_type,
            result.findings,
            json.dumps(result.tools_used),
            result.analysis_date.isoformat(),
            result.analyst
        ))
        conn.commit()
        conn.close()

        logger.info(f"Analysis completed: {result_id} - {analysis_type}")
        return result

    def analyze_malware(self, sample_path: str, threat_type: str) -> Dict:
        """Step 4: Malware Analysis"""
        sample_id = f"MALWARE_{self.case_id}_{len(self.malware_samples) + 1:04d}"
        analysis_date = datetime.datetime.now()

        with open(sample_path, 'rb') as f:
            file_content = f.read()
            hash_value = hashlib.sha256(file_content).hexdigest()

        analysis_result = {
            'sample_id': sample_id,
            'case_id': self.case_id,
            'filename': os.path.basename(sample_path),
            'hash_value': hash_value,
            'analysis_status': 'completed',
            'threat_type': threat_type,
            'ioc_indicators': self._extract_ioc_indicators(file_content),
            'analysis_date': analysis_date.isoformat(),
            'file_size': len(file_content),
            'file_type': self._detect_file_type(file_content),
            'entropy_score': self._calculate_entropy(file_content),
            'suspicious_patterns': self._detect_suspicious_patterns(file_content)
        }

        self.malware_samples.append(analysis_result)

        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO malware_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_result['sample_id'],
            analysis_result['case_id'],
            analysis_result['filename'],
            analysis_result['hash_value'],
            analysis_result['analysis_status'],
            analysis_result['threat_type'],
            json.dumps(analysis_result['ioc_indicators']),
            analysis_result['analysis_date']
        ))
        conn.commit()
        conn.close()

        logger.info(f"Enhanced malware analysis completed: {sample_id} - {threat_type}")
        return analysis_result

    # ── Analysis helpers ─────────────────────────────────────────────────────

    def _extract_ioc_indicators(self, file_content: bytes) -> List[str]:
        iocs = []
        content_str = file_content.decode('utf-8', errors='ignore')
        malicious_patterns = [
            'http://', 'https://', 'cmd.exe', 'powershell', 'regsvr32',
            'rundll32', 'schtasks', 'netcat', 'nc.exe', 'wget', 'curl',
            'base64', 'encrypt', 'decrypt', 'keylogger', 'backdoor',
            'trojan', 'virus', 'worm', 'ransomware', 'spyware'
        ]
        for pattern in malicious_patterns:
            if pattern.lower() in content_str.lower():
                iocs.append(f"Contains {pattern}")
        return iocs

    def _detect_file_type(self, file_content: bytes) -> str:
        if file_content.startswith(b'MZ'):
            return 'PE Executable'
        elif file_content.startswith(b'\x7fELF'):
            return 'ELF Executable'
        elif file_content.startswith(b'PK'):
            return 'ZIP Archive'
        elif file_content.startswith(b'\x89PNG'):
            return 'PNG Image'
        elif file_content.startswith(b'\xff\xd8\xff'):
            return 'JPEG Image'
        else:
            return 'Unknown'

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        return entropy

    def _detect_suspicious_patterns(self, file_content: bytes) -> List[str]:
        patterns = []
        content_str = file_content.decode('utf-8', errors='ignore')
        entropy = self._calculate_entropy(file_content)
        if entropy > 7.5:
            patterns.append(f"High entropy detected ({entropy:.2f})")
        suspicious_strings = [
            'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory',
            'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
            'registry', 'startup', 'autostart', 'persistence'
        ]
        for string in suspicious_strings:
            if string.lower() in content_str.lower():
                patterns.append(f"Suspicious API call: {string}")
        return patterns

    # ── Visualizations ───────────────────────────────────────────────────────

    def generate_visualizations(self) -> Dict[str, str]:
        """Generate all charts and save as PNG / HTML files."""
        viz_path = self.investigation_path / "visualizations"
        viz_files = {}

        # ── 1. Evidence Type Distribution ────────────────────────────────────
        if self.evidence_list:
            evidence_types = [ev.evidence_type.value for ev in self.evidence_list]
            evidence_counts = Counter(evidence_types)
            evidence_series = pd.Series(evidence_counts)

            fig, ax = plt.subplots(figsize=(10, 6))
            evidence_series.plot(kind='bar', ax=ax, color='steelblue')
            ax.set_title('Evidence Type Distribution')
            ax.set_xlabel('Evidence Type')
            ax.set_ylabel('Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            evidence_viz_path = viz_path / "evidence_distribution.png"
            plt.savefig(evidence_viz_path, dpi=150, bbox_inches='tight')
            plt.close('all')   # ── FIX 3: close ALL figures, not just current
            viz_files['evidence_distribution'] = str(evidence_viz_path)

        # ── 2. Analysis Timeline ─────────────────────────────────────────────
        if self.analysis_results:
            dates = [result.analysis_date for result in self.analysis_results]
            analysis_types = [result.analysis_type for result in self.analysis_results]

            fig, ax = plt.subplots(figsize=(12, 6))
            for i, (date, analysis_type) in enumerate(zip(dates, analysis_types)):
                ax.scatter(date, i, s=100, alpha=0.7)
                ax.annotate(analysis_type, (date, i), textcoords="offset points",
                            xytext=(5, 0), fontsize=7)
            ax.set_title('Analysis Timeline')
            ax.set_xlabel('Date')
            ax.set_ylabel('Analysis Number')
            plt.tight_layout()
            timeline_viz_path = viz_path / "analysis_timeline.png"
            plt.savefig(timeline_viz_path, dpi=150, bbox_inches='tight')
            plt.close('all')
            viz_files['analysis_timeline'] = str(timeline_viz_path)

        # ── 3. Malware charts ────────────────────────────────────────────────
        if self.malware_samples:
            threat_types = [sample['threat_type'] for sample in self.malware_samples]
            threat_counts = Counter(threat_types)
            file_sizes = [sample['file_size'] for sample in self.malware_samples]
            entropy_values = [sample.get('entropy_score', 0) for sample in self.malware_samples]
            ioc_counts = [len(sample.get('ioc_indicators', [])) for sample in self.malware_samples]
            sample_names = [f"S{i+1}" for i in range(len(self.malware_samples))]

            # Threat distribution pie
            fig1, ax1 = plt.subplots(figsize=(8, 6))
            ax1.pie(threat_counts.values(), labels=threat_counts.keys(),
                    autopct='%1.1f%%', startangle=90)
            ax1.set_title('Threat Type Distribution')
            plt.tight_layout()
            threat_dist_path = viz_path / "threat_distribution.png"
            plt.savefig(threat_dist_path, dpi=150, bbox_inches='tight')
            plt.close('all')
            viz_files['threat_distribution'] = str(threat_dist_path)

            # File size bar
            fig2, ax2 = plt.subplots(figsize=(10, 6))
            ax2.bar(sample_names, file_sizes, color='steelblue')
            ax2.set_title('Malware File Size Analysis')
            ax2.set_xlabel('Sample')
            ax2.set_ylabel('File Size (bytes)')
            plt.xticks(rotation=45)
            plt.tight_layout()
            filesize_path = viz_path / "file_size_analysis.png"
            plt.savefig(filesize_path, dpi=150, bbox_inches='tight')
            plt.close('all')
            viz_files['file_size_analysis'] = str(filesize_path)

            # Entropy histogram
            fig3, ax3 = plt.subplots(figsize=(10, 6))
            ax3.hist(entropy_values, bins=max(5, len(entropy_values)),
                     color='coral', edgecolor='black')
            ax3.set_title('Entropy Distribution')
            ax3.set_xlabel('Entropy Score')
            ax3.set_ylabel('Frequency')
            ax3.axvline(x=7.5, color='red', linestyle='--', label='High Entropy Threshold')
            ax3.legend()
            plt.tight_layout()
            entropy_path = viz_path / "entropy_analysis.png"
            plt.savefig(entropy_path, dpi=150, bbox_inches='tight')
            plt.close('all')
            viz_files['entropy_analysis'] = str(entropy_path)

            # IOC indicators bar
            fig4, ax4 = plt.subplots(figsize=(10, 6))
            ax4.bar(sample_names, ioc_counts, color='indianred')
            ax4.set_title('IOC Indicators per Sample')
            ax4.set_xlabel('Sample')
            ax4.set_ylabel('Number of IOCs')
            plt.xticks(rotation=45)
            plt.tight_layout()
            ioc_path = viz_path / "ioc_indicators.png"
            plt.savefig(ioc_path, dpi=150, bbox_inches='tight')
            plt.close('all')
            viz_files['ioc_indicators'] = str(ioc_path)

            # Interactive Plotly dashboard
            try:
                fig_plotly = make_subplots(
                    rows=2, cols=2,
                    subplot_titles=(
                        'Threat Type Distribution', 'File Size Analysis',
                        'Entropy Analysis', 'IOC Indicators'
                    ),
                    specs=[
                        [{"type": "pie"}, {"type": "bar"}],
                        [{"type": "histogram"}, {"type": "bar"}]
                    ]
                )
                fig_plotly.add_trace(
                    go.Pie(labels=list(threat_counts.keys()),
                           values=list(threat_counts.values())),
                    row=1, col=1
                )
                fig_plotly.add_trace(
                    go.Bar(x=sample_names, y=file_sizes, name='File Size'),
                    row=1, col=2
                )
                fig_plotly.add_trace(
                    go.Histogram(x=entropy_values, nbinsx=10, name='Entropy'),
                    row=2, col=1
                )
                fig_plotly.add_trace(
                    go.Bar(x=sample_names, y=ioc_counts, name='IOCs'),
                    row=2, col=2
                )
                fig_plotly.update_layout(
                    height=800,
                    title_text="Malware Analysis Dashboard",
                    showlegend=False
                )
                dashboard_path = viz_path / "malware_dashboard.html"
                fig_plotly.write_html(str(dashboard_path))
                viz_files['malware_dashboard'] = str(dashboard_path)
            except Exception as e:
                logger.warning(f"Plotly dashboard generation skipped: {e}")

        # ── 4. Tools Usage ───────────────────────────────────────────────────
        if self.analysis_results:
            all_tools = []
            for result in self.analysis_results:
                all_tools.extend(result.tools_used)
            tool_counts = Counter(all_tools)
            if tool_counts:
                tool_series = pd.Series(tool_counts)
                fig, ax = plt.subplots(figsize=(10, 6))
                tool_series.plot(kind='barh', ax=ax, color='teal')
                ax.set_title('Forensic Tools Usage')
                ax.set_xlabel('Usage Count')
                plt.tight_layout()
                tools_viz_path = viz_path / "tools_usage.png"
                plt.savefig(tools_viz_path, dpi=150, bbox_inches='tight')
                plt.close('all')
                viz_files['tools_usage'] = str(tools_viz_path)

        logger.info(f"Generated {len(viz_files)} visualizations")
        return viz_files

    # ── Statistics ───────────────────────────────────────────────────────────

    def generate_statistical_report(self) -> Dict[str, Any]:
        """Generate comprehensive statistical analysis."""
        stats = {
            'case_id': self.case_id,
            'total_evidence': len(self.evidence_list),
            'total_analysis_results': len(self.analysis_results),
            'total_malware_samples': len(self.malware_samples),
            'evidence_by_type': {},
            'malicious_activities': {},
            'tools_used': set(),
            'analysis_timeline': {},
            'malware_statistics': {},
            'investigation_metrics': {}
        }

        for evidence in self.evidence_list:
            ev_type = evidence.evidence_type.value
            stats['evidence_by_type'][ev_type] = stats['evidence_by_type'].get(ev_type, 0) + 1

        for result in self.analysis_results:
            stats['tools_used'].update(result.tools_used)
            date_str = result.analysis_date.strftime('%Y-%m-%d')
            stats['analysis_timeline'][date_str] = stats['analysis_timeline'].get(date_str, 0) + 1

        if self.malware_samples:
            threat_counter = Counter([s['threat_type'] for s in self.malware_samples])
            stats['malicious_activities'] = dict(threat_counter)
            stats['malware_statistics'] = {
                'total_samples': len(self.malware_samples),
                'threat_types': dict(threat_counter),
                'file_types': dict(Counter([s['file_type'] for s in self.malware_samples])),
                'avg_file_size': float(np.mean([s['file_size'] for s in self.malware_samples])),
                'avg_entropy': float(np.mean([s.get('entropy_score', 0) for s in self.malware_samples])),
                'total_iocs': sum(len(s.get('ioc_indicators', [])) for s in self.malware_samples)
            }

        if self.case:
            duration = datetime.datetime.now() - self.case.start_date
            stats['investigation_metrics'] = {
                'duration_days': duration.days,
                'evidence_per_day': len(self.evidence_list) / max(duration.days, 1),
                'analysis_per_day': len(self.analysis_results) / max(duration.days, 1),
                'team_size': len(self.case.team_members)
            }

        stats['tools_used'] = list(stats['tools_used'])

        stats_path = self.investigation_path / "statistics" / "investigation_statistics.json"
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2, default=str)

        logger.info(f"Generated statistical report: {stats_path}")
        return stats

    # ── Report generation ────────────────────────────────────────────────────

    def generate_enhanced_report(self) -> str:
        """Generate the full HTML investigation report with embedded charts."""
        import base64

        report_path = self.investigation_path / "reports" / f"enhanced_report_{self.case_id}.html"

        viz_files = self.generate_visualizations()
        stats = self.generate_statistical_report()

        def image_to_base64(image_path: str) -> str:
            try:
                with open(image_path, 'rb') as img_file:
                    encoded = base64.b64encode(img_file.read()).decode()
                    return f"data:image/png;base64,{encoded}"
            except Exception:
                return ""

        # ── HTML ─────────────────────────────────────────────────────────────
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Digital Forensics Investigation Report - {self.case_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f5f5;
        }}
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section {{
            margin: 30px 0;
            padding: 25px;
            border: 1px solid #ddd;
            border-radius: 10px;
            background: #fafafa;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .visualization {{
            text-align: center;
            margin: 30px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
        }}
        .visualization img {{
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .visualization h3 {{ color: #34495e; margin-bottom: 15px; }}
        .stats {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-box {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            border-left: 4px solid #3498db;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
            font-weight: 600;
        }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #e8f4f8; }}
        .malware-section {{ border-left: 5px solid #e74c3c; }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: #ecf0f1;
            border-radius: 8px;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
<div class="report-container">

    <div class="header">
        <h1>&#128269; Digital Forensics Investigation Report</h1>
        <h2>Case ID: {self.case_id}</h2>
        <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <!-- Case Information -->
    <div class="section">
        <h2>&#128203; Case Information</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td><strong>Case ID</strong></td><td>{self.case_id}</td></tr>
            <tr><td><strong>Case Name</strong></td><td>{self.case_name}</td></tr>
            <tr><td><strong>Investigator</strong></td><td>{self.investigator}</td></tr>
            <tr><td><strong>Start Date</strong></td>
                <td>{self.case.start_date.strftime('%Y-%m-%d %H:%M:%S') if self.case else 'N/A'}</td></tr>
            <tr><td><strong>Status</strong></td>
                <td>{self.case.status.value if self.case else 'N/A'}</td></tr>
            <tr><td><strong>Jurisdiction</strong></td>
                <td>{self.case.jurisdiction if self.case else 'N/A'}</td></tr>
            <tr><td><strong>Team Members</strong></td>
                <td>{', '.join(self.case.team_members) if self.case else 'N/A'}</td></tr>
            <tr><td><strong>Legal Requirements</strong></td>
                <td>{', '.join(self.case.legal_requirements) if self.case else 'N/A'}</td></tr>
        </table>
    </div>

    <!-- Quick Statistics -->
    <div class="section">
        <h2>&#128202; Quick Statistics</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">{stats['total_evidence']}</div>
                <div class="stat-label">Evidence Items</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats['total_analysis_results']}</div>
                <div class="stat-label">Analysis Results</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats['total_malware_samples']}</div>
                <div class="stat-label">Malware Samples</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(stats['tools_used'])}</div>
                <div class="stat-label">Tools Used</div>
            </div>
        </div>
    </div>

    <!-- Evidence Summary -->
    <div class="section">
        <h2>&#128230; Evidence Summary</h2>
"""

        # Evidence distribution chart
        if 'evidence_distribution' in viz_files:
            img_data = image_to_base64(viz_files['evidence_distribution'])
            if img_data:
                html_content += f"""
        <div class="visualization">
            <h3>Evidence Type Distribution</h3>
            <img src="{img_data}" alt="Evidence Distribution">
        </div>
"""

        html_content += f"""
        <div class="stats">
            <h3>Evidence Statistics</h3>
            <p><strong>Total Evidence Items:</strong> {stats['total_evidence']}</p>
            <ul>
"""
        for ev_type, count in stats['evidence_by_type'].items():
            html_content += f"            <li><strong>{ev_type.replace('_', ' ').title()}:</strong> {count} item(s)</li>\n"

        html_content += """            </ul>
        </div>
    </div>

    <!-- Analysis Results -->
    <div class="section">
        <h2>&#128300; Analysis Results</h2>
"""

        if 'analysis_timeline' in viz_files:
            img_data = image_to_base64(viz_files['analysis_timeline'])
            if img_data:
                html_content += f"""
        <div class="visualization">
            <h3>Analysis Timeline</h3>
            <img src="{img_data}" alt="Analysis Timeline">
        </div>
"""

        if 'tools_usage' in viz_files:
            img_data = image_to_base64(viz_files['tools_usage'])
            if img_data:
                html_content += f"""
        <div class="visualization">
            <h3>Forensic Tools Usage</h3>
            <img src="{img_data}" alt="Tools Usage">
        </div>
"""

        html_content += f"""
        <div class="stats">
            <h3>Analysis Statistics</h3>
            <p><strong>Total Analysis Results:</strong> {stats['total_analysis_results']}</p>
            <p><strong>Tools Used:</strong> {', '.join(stats['tools_used']) if stats['tools_used'] else 'N/A'}</p>
        </div>
    </div>

    <!-- Malware Analysis -->
    <div class="section malware-section">
        <h2>&#129440; Malware Analysis</h2>
"""

        for key, label in [
            ('threat_distribution', 'Threat Type Distribution'),
            ('file_size_analysis', 'File Size Analysis'),
            ('entropy_analysis', 'Entropy Analysis'),
            ('ioc_indicators', 'IOC Indicators per Sample'),
        ]:
            if key in viz_files:
                img_data = image_to_base64(viz_files[key])
                if img_data:
                    html_content += f"""
        <div class="visualization">
            <h3>{label}</h3>
            <img src="{img_data}" alt="{label}">
        </div>
"""

        if stats.get('malware_statistics'):
            ms = stats['malware_statistics']
            html_content += f"""
        <div class="stats">
            <h3>Malware Statistics</h3>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{ms['total_samples']}</div>
                    <div class="stat-label">Total Samples</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{ms['avg_file_size']:.0f}</div>
                    <div class="stat-label">Avg File Size (bytes)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{ms['avg_entropy']:.2f}</div>
                    <div class="stat-label">Avg Entropy</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{ms['total_iocs']}</div>
                    <div class="stat-label">Total IOCs</div>
                </div>
            </div>
            <h4>Threat Types Detected:</h4>
            <ul>
"""
            for threat_type, count in stats['malicious_activities'].items():
                html_content += f"            <li><strong>{threat_type.title()}:</strong> {count} sample(s)</li>\n"

            html_content += """            </ul>
        </div>
    </div>
"""

        # Investigation Metrics
        if stats.get('investigation_metrics'):
            im = stats['investigation_metrics']
            html_content += f"""
    <div class="section">
        <h2>&#128200; Investigation Metrics</h2>
        <div class="stats">
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Investigation Duration</td><td>{im['duration_days']} day(s)</td></tr>
                <tr><td>Evidence Collection Rate</td><td>{im['evidence_per_day']:.2f} items/day</td></tr>
                <tr><td>Analysis Rate</td><td>{im['analysis_per_day']:.2f} analyses/day</td></tr>
                <tr><td>Team Size</td><td>{im['team_size']} member(s)</td></tr>
            </table>
        </div>
    </div>
"""

        # Conclusions
        html_content += f"""
    <div class="section">
        <h2>&#9989; Conclusions</h2>
        <p>This enhanced investigation followed the proposed digital forensics methodology
        with comprehensive analysis, visualization, and statistical reporting. All evidence
        was collected, analyzed, and documented according to forensic standards.</p>
        <div class="stats">
            <h3>Report Summary</h3>
            <ul>
                <li>&#10003; Evidence collection completed with proper chain of custody</li>
                <li>&#10003; Comprehensive analysis with IOC extraction</li>
                <li>&#10003; Statistical analysis and visualizations generated</li>
                <li>&#10003; All findings documented and ready for legal proceedings</li>
            </ul>
        </div>
    </div>

    <div class="footer">
        <p>
            <strong>Report Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Forensics System Version:</strong> 2.0<br>
            <em>This report is confidential and intended for authorised personnel only.</em>
        </p>
    </div>

</div>
</body>
</html>"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Enhanced investigation report generated: {report_path}")
        return str(report_path)

    # ── Public helpers ───────────────────────────────────────────────────────

    def export_statistics(self) -> Dict[str, Any]:
        return self.generate_statistical_report()

    def create_backup(self) -> str:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"investigation_{self.case_id}_backup_{timestamp}.zip"
        backup_path = self.investigation_path / "backups" / backup_filename

        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.investigation_path):
                if 'backups' in root:
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.investigation_path)
                    zipf.write(file_path, arcname)

        logger.info(f"Investigation backup created: {backup_path}")
        return str(backup_path)


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE DEMO
# ─────────────────────────────────────────────────────────────────────────────

def main():
    investigation = EnhancedDigitalForensicsInvestigation(
        case_id="CASE_2024_001",
        case_name="Enhanced Malware Attack Investigation",
        investigator="Detective Raj Smith"
    )

    investigation.plan_investigation(
        description="Comprehensive investigation of suspected malware attack on corporate network",
        jurisdiction="State of California",
        legal_requirements=["Search warrant", "Chain of custody", "Evidence preservation"],
        team_members=["Detective John Smith", "Digital Forensics Analyst",
                      "Legal Counsel", "IT Security Specialist"]
    )

    evidence1 = investigation.collect_evidence(
        EvidenceType.COMPUTER, "Employee workstation",
        "Office building, Floor 3, Room 301",
        "Desktop computer suspected of malware infection"
    )
    evidence2 = investigation.collect_evidence(
        EvidenceType.NETWORK_LOGS, "Corporate firewall",
        "IT server room", "Network traffic logs showing suspicious activity"
    )
    evidence3 = investigation.collect_evidence(
        EvidenceType.MOBILE_DEVICE, "Employee smartphone",
        "Employee's desk", "Mobile device used for work communications"
    )
    evidence4 = investigation.collect_evidence(
        EvidenceType.CLOUD_SERVICES, "Google Drive account",
        "Cloud storage", "Suspicious files uploaded to cloud storage"
    )

    investigation.analyze_digital_evidence(
        evidence1.evidence_id, "File System Analysis",
        ["FTK Imager", "Autopsy", "EnCase"],
        "Discovered suspicious executable files in Downloads folder"
    )
    investigation.analyze_digital_evidence(
        evidence2.evidence_id, "Network Traffic Analysis",
        ["Wireshark", "NetworkMiner", "tcpdump"],
        "Detected unusual outbound connections to known malicious IPs"
    )
    investigation.analyze_digital_evidence(
        evidence3.evidence_id, "Mobile Device Forensics",
        ["Cellebrite", "Oxygen Forensics", "Magnet AXIOM"],
        "Found suspicious SMS messages and app installations"
    )

    malware_samples = [
        ("trojan_sample.exe", "Trojan"),
        ("ransomware_sample.exe", "Ransomware"),
        ("spyware_sample.exe", "Spyware")
    ]
    for filename, threat_type in malware_samples:
        malware_sample_path = investigation.investigation_path / "malware_samples" / filename
        with open(malware_sample_path, 'w') as f:
            f.write(f"Simulated {threat_type.lower()} sample for demonstration")
        investigation.analyze_malware(str(malware_sample_path), threat_type)

    report_path = investigation.generate_enhanced_report()
    stats = investigation.export_statistics()
    backup_path = investigation.create_backup()

    print("=" * 80)
    print("ENHANCED DIGITAL FORENSICS INVESTIGATION COMPLETED")
    print("=" * 80)
    print(f"Case ID                : {investigation.case_id}")
    print(f"Evidence Collected     : {len(investigation.evidence_list)}")
    print(f"Analysis Results       : {len(investigation.analysis_results)}")
    print(f"Malware Samples        : {len(investigation.malware_samples)}")
    print(f"Report Path            : {report_path}")
    print(f"Backup Path            : {backup_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()