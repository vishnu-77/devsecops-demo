from flask import Flask, jsonify, render_template_string
import os
import json
import xml.etree.ElementTree as ET
import datetime
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Utility Functions ------------------------------------------------------

def load_bandit_results(path="bandit-report.json"):
    """Read Bandit scan results if file exists"""
    if not os.path.exists(path):
        return {"status": "N/A", "issues": 0, "severity": {}, "findings": []}

    try:
        with open(path, "r") as f:
            data = json.load(f)

        results = data.get("results", [])
        issues = len(results)
        severities = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        findings = []

        for result in results:
            sev = result.get("issue_severity", "LOW").upper()
            severities[sev] = severities.get(sev, 0) + 1

            findings.append({
                "severity": sev,
                "file": result.get("filename", "unknown"),
                "line": result.get("line_number", 0),
                "issue": result.get("issue_text", ""),
                "confidence": result.get("issue_confidence", ""),
                "test_id": result.get("test_id", ""),
                "cwe_link": result.get("issue_cwe", {}).get("link", ""),
                "more_info": result.get("more_info", "")
            })

        return {
            "status": "OK" if issues == 0 else ("WARN" if severities["HIGH"] == 0 and severities["MEDIUM"] == 0 else "FAIL"),
            "issues": issues,
            "severity": severities,
            "findings": findings
        }
    except Exception as e:
        return {"status": "ERROR", "issues": 0, "severity": {}, "findings": [], "error": str(e)}


def load_safety_results(path="safety.json"):
    """Read Safety vulnerability scan results"""
    if not os.path.exists(path):
        return {"status": "N/A", "vulns": 0, "vulnerabilities": []}
    try:
        with open(path, "r") as f:
            data = json.load(f)

        # Handle both old and new safety report formats
        if isinstance(data, list):
            vulns = len(data)
            vulnerabilities = data
        else:
            vulnerabilities = data.get("vulnerabilities", [])
            vulns = len(vulnerabilities)

        findings = []
        for vuln in vulnerabilities:
            findings.append({
                "package": vuln.get("package_name", "unknown"),
                "version": vuln.get("analyzed_version", ""),
                "cve": vuln.get("CVE", "N/A"),
                "advisory": vuln.get("advisory", "")[:200] + "..." if len(vuln.get("advisory", "")) > 200 else vuln.get("advisory", ""),
                "vulnerable_spec": vuln.get("vulnerable_spec", ""),
                "more_info": vuln.get("more_info_url", "")
            })

        return {
            "status": "OK" if vulns == 0 else "FAIL",
            "vulns": vulns,
            "vulnerabilities": findings
        }
    except Exception as e:
        return {"status": "ERROR", "vulns": 0, "vulnerabilities": [], "error": str(e)}


def load_coverage(path="coverage.xml"):
    """Parse test coverage from coverage.xml"""
    if not os.path.exists(path):
        return {"status": "N/A", "coverage": 0.0}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        coverage = float(root.attrib.get("line-rate", 0)) * 100
        return {"status": "OK" if coverage >= 80 else "WARN", "coverage": round(coverage, 2)}
    except Exception as e:
        return {"status": "ERROR", "coverage": 0.0, "error": str(e)}


def load_trivy_results(path="trivy.json"):
    """Parse Trivy scan results"""
    if not os.path.exists(path):
        return {"status": "N/A", "vulns": 0, "vulnerabilities": []}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        results = data.get("Results", [])
        total_vulns = 0
        findings = []

        for r in results:
            target = r.get("Target", "unknown")
            for vuln in r.get("Vulnerabilities", []):
                total_vulns += 1
                findings.append({
                    "target": target,
                    "vuln_id": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", "Not available"),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", "")[:100],
                    "description": vuln.get("Description", "")[:200] + "..." if len(vuln.get("Description", "")) > 200 else vuln.get("Description", "")
                })

        return {
            "status": "OK" if total_vulns == 0 else "FAIL",
            "vulns": total_vulns,
            "vulnerabilities": findings
        }
    except Exception as e:
        return {"status": "ERROR", "vulns": 0, "vulnerabilities": [], "error": str(e)}


def download_github_artifact(artifact_name, save_path):
    """Download artifact from latest GitHub Actions run"""
    github_token = os.environ.get("GITHUB_TOKEN", "")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "")

    if not github_token or not github_repo:
        return False

    try:
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        # Get latest run ID
        runs_url = f"https://api.github.com/repos/{github_repo}/actions/runs"
        runs_response = requests.get(runs_url, headers=headers, params={"per_page": 1}, timeout=10)

        if runs_response.status_code != 200:
            return False

        runs_data = runs_response.json()
        workflow_runs = runs_data.get("workflow_runs", [])

        if not workflow_runs:
            return False

        run_id = workflow_runs[0]["id"]

        # Get artifacts for this run
        artifacts_url = f"https://api.github.com/repos/{github_repo}/actions/runs/{run_id}/artifacts"
        artifacts_response = requests.get(artifacts_url, headers=headers, timeout=10)

        if artifacts_response.status_code != 200:
            return False

        artifacts = artifacts_response.json().get("artifacts", [])

        # Find the specific artifact
        for artifact in artifacts:
            if artifact["name"] == artifact_name:
                # Download artifact (returns a ZIP file)
                download_url = artifact["archive_download_url"]
                download_response = requests.get(download_url, headers=headers, timeout=30)

                if download_response.status_code == 200:
                    import zipfile
                    import io

                    # Extract the file from ZIP
                    zip_file = zipfile.ZipFile(io.BytesIO(download_response.content))
                    zip_file.extractall(os.path.dirname(save_path))
                    return True

        return False

    except Exception as e:
        print(f"Error downloading artifact {artifact_name}: {e}")
        return False


def get_github_actions_status():
    """Fetch latest GitHub Actions workflow run status and download artifacts"""
    github_token = os.environ.get("GITHUB_TOKEN", "")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "")  # format: owner/repo

    if not github_token or not github_repo:
        return {
            "status": "N/A",
            "jobs": {},
            "run_id": None,
            "run_url": None,
            "branch": None,
            "commit": None,
            "message": "GitHub credentials not configured"
        }

    try:
        # Get the latest workflow runs
        api_url = f"https://api.github.com/repos/{github_repo}/actions/runs"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        response = requests.get(
            api_url,
            headers=headers,
            params={"per_page": 1},
            timeout=10
        )

        if response.status_code != 200:
            return {
                "status": "ERROR",
                "error": f"API returned {response.status_code}",
                "jobs": {}
            }

        data = response.json()
        workflow_runs = data.get("workflow_runs", [])

        if not workflow_runs:
            return {
                "status": "N/A",
                "jobs": {},
                "message": "No workflow runs found"
            }

        latest_run = workflow_runs[0]
        run_id = latest_run["id"]

        # Download artifacts in background (non-blocking)
        # Try to download latest reports
        download_github_artifact("bandit-security-report", "bandit-report.json")
        download_github_artifact("safety-report", "safety.json")
        download_github_artifact("coverage-report", "coverage.xml")
        download_github_artifact("trivy-report", "trivy.json")

        # Get jobs for this workflow run
        jobs_url = f"https://api.github.com/repos/{github_repo}/actions/runs/{run_id}/jobs"
        jobs_response = requests.get(jobs_url, headers=headers, timeout=10)

        if jobs_response.status_code != 200:
            return {
                "status": "ERROR",
                "error": f"Jobs API returned {jobs_response.status_code}",
                "jobs": {}
            }

        jobs_data = jobs_response.json()
        jobs = {}

        for job in jobs_data.get("jobs", []):
            job_name = job["name"].lower().replace(" ", "-").replace("&", "").replace("(", "").replace(")", "").strip()
            jobs[job_name] = {
                "status": job.get("status", "unknown"),
                "conclusion": job.get("conclusion", "none"),
                "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"),
                "html_url": job.get("html_url")
            }

        overall_status = latest_run.get("conclusion", latest_run.get("status", "unknown")).upper()

        return {
            "status": overall_status,
            "jobs": jobs,
            "run_id": run_id,
            "run_url": latest_run.get("html_url"),
            "branch": latest_run.get("head_branch"),
            "commit": latest_run.get("head_sha", "")[:7],
            "created_at": latest_run.get("created_at"),
            "updated_at": latest_run.get("updated_at"),
            "event": latest_run.get("event"),
            "workflow_name": latest_run.get("name")
        }

    except requests.exceptions.RequestException as e:
        return {
            "status": "ERROR",
            "error": f"Request failed: {str(e)}",
            "jobs": {}
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
            "jobs": {}
        }

# --- Dashboard HTML Template ------------------------------------------------

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Dashboard - Live Pipeline Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .dashboard-header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .header-title h1 {
            font-size: 2em;
            color: #1a202c;
            margin-bottom: 5px;
        }

        .header-title p {
            color: #718096;
            font-size: 0.95em;
        }

        .live-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            background: #f7fafc;
            border-radius: 8px;
        }

        .live-dot {
            width: 12px;
            height: 12px;
            background: #48bb78;
            border-radius: 50%;
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pipeline-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-label {
            color: #718096;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #1a202c;
        }

        .stat-meta {
            margin-top: 10px;
            font-size: 0.9em;
            color: #a0aec0;
        }

        .main-content {
            display: grid;
            gap: 20px;
        }

        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e2e8f0;
        }

        .card-title {
            font-size: 1.4em;
            color: #1a202c;
            font-weight: 600;
        }

        .data-source {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: #edf2f7;
            border-radius: 6px;
            font-size: 0.85em;
            color: #4a5568;
        }

        .source-icon {
            width: 16px;
            height: 16px;
        }

        .pipeline-flow {
            display: flex;
            gap: 15px;
            margin: 20px 0;
            overflow-x: auto;
            padding: 10px 0;
        }

        .flow-step {
            flex: 1;
            min-width: 200px;
            padding: 20px;
            background: #f7fafc;
            border-radius: 8px;
            border-left: 4px solid #cbd5e0;
            position: relative;
        }

        .flow-step.success {
            border-left-color: #48bb78;
            background: #f0fff4;
        }

        .flow-step.failure {
            border-left-color: #f56565;
            background: #fff5f5;
        }

        .flow-step.in-progress {
            border-left-color: #4299e1;
            background: #ebf8ff;
        }

        .step-name {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 8px;
        }

        .step-status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .step-status.success {
            background: #c6f6d5;
            color: #22543d;
        }

        .step-status.failure {
            background: #fed7d7;
            color: #742a2a;
        }

        .step-status.in-progress {
            background: #bee3f8;
            color: #2c5282;
        }

        .step-status.na {
            background: #e2e8f0;
            color: #4a5568;
        }

        .step-meta {
            margin-top: 10px;
            font-size: 0.85em;
            color: #718096;
        }

        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .result-card {
            padding: 20px;
            background: #f7fafc;
            border-radius: 8px;
            border-left: 4px solid #cbd5e0;
        }

        .result-card.ok {
            border-left-color: #48bb78;
        }

        .result-card.warn {
            border-left-color: #ed8936;
        }

        .result-card.fail {
            border-left-color: #f56565;
        }

        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .result-tool {
            font-weight: 600;
            color: #2d3748;
            font-size: 1.1em;
        }

        .result-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }

        .result-badge.ok {
            background: #c6f6d5;
            color: #22543d;
        }

        .result-badge.warn {
            background: #feebc8;
            color: #7c2d12;
        }

        .result-badge.fail {
            background: #fed7d7;
            color: #742a2a;
        }

        .result-badge.na {
            background: #e2e8f0;
            color: #4a5568;
        }

        .result-summary {
            font-size: 1.8em;
            font-weight: bold;
            color: #1a202c;
            margin: 10px 0;
        }

        .result-description {
            color: #718096;
            font-size: 0.9em;
        }

        .controls {
            display: flex;
            gap: 15px;
            align-items: center;
            padding: 15px;
            background: #edf2f7;
            border-radius: 8px;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5a67d8;
        }

        .btn-primary:disabled {
            background: #cbd5e0;
            cursor: not-allowed;
        }

        select {
            padding: 8px 12px;
            border: 1px solid #cbd5e0;
            border-radius: 6px;
            background: white;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: none;
        }

        .spinner.active {
            display: inline-block;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .link {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }

        .link:hover {
            text-decoration: underline;
        }

        .timestamp {
            color: #a0aec0;
            font-size: 0.9em;
        }

        /* Details section styles */
        .details-toggle {
            margin-top: 15px;
            padding: 8px 16px;
            background: white;
            border: 1px solid #cbd5e0;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            color: #667eea;
            transition: all 0.2s;
            width: 100%;
            text-align: left;
        }

        .details-toggle:hover {
            background: #f7fafc;
            border-color: #667eea;
        }

        .details-toggle::after {
            content: "▼";
            float: right;
            transition: transform 0.2s;
        }

        .details-toggle.active::after {
            transform: rotate(180deg);
        }

        .findings-details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .findings-details.active {
            max-height: 2000px;
            transition: max-height 0.5s ease-in;
        }

        .findings-list {
            margin-top: 15px;
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            background: white;
        }

        .finding-item {
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
        }

        .finding-item:last-child {
            border-bottom: none;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }

        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.high {
            background: #fed7d7;
            color: #742a2a;
        }

        .severity-badge.medium {
            background: #feebc8;
            color: #7c2d12;
        }

        .severity-badge.low {
            background: #fef5e7;
            color: #7c6d1e;
        }

        .severity-badge.critical {
            background: #feb2b2;
            color: #63171b;
        }

        .finding-file {
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #4a5568;
            margin-bottom: 5px;
        }

        .finding-description {
            color: #2d3748;
            font-size: 0.9em;
            line-height: 1.5;
            margin-bottom: 8px;
        }

        .finding-meta {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            font-size: 0.8em;
            color: #718096;
            margin-top: 8px;
        }

        .finding-meta span {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .finding-link {
            color: #667eea;
            text-decoration: none;
            font-size: 0.85em;
            font-weight: 500;
        }

        .finding-link:hover {
            text-decoration: underline;
        }

        .severity-breakdown {
            display: flex;
            gap: 15px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e2e8f0;
            font-size: 0.85em;
        }

        .severity-count {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .severity-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .severity-dot.high { background: #f56565; }
        .severity-dot.medium { background: #ed8936; }
        .severity-dot.low { background: #ecc94b; }

        .no-findings {
            padding: 20px;
            text-align: center;
            color: #a0aec0;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <div class="header-top">
            <div class="header-title">
                <h1>DevSecOps Pipeline Monitor</h1>
                <p>Real-time CI/CD Security & Quality Dashboard</p>
            </div>
            <div class="live-indicator">
                <div class="live-dot"></div>
                <span>Live from GitHub Actions</span>
            </div>
        </div>

        <div class="controls">
            <label>
                <input type="checkbox" id="auto-refresh-toggle" checked>
                Auto-refresh every
            </label>
            <select id="refresh-interval">
                <option value="10">10 seconds</option>
                <option value="30" selected>30 seconds</option>
                <option value="60">1 minute</option>
                <option value="120">2 minutes</option>
            </select>
            <button class="btn btn-primary" id="manual-refresh">
                <span class="spinner" id="spinner"></span>
                Refresh Now
            </button>
            <span class="timestamp">Last updated: <span id="timestamp">{{ timestamp }}</span></span>
        </div>
    </div>

    <div class="pipeline-overview">
        <div class="stat-card">
            <div class="stat-label">Pipeline Status</div>
            <div class="stat-value" style="color: {% if github_actions['status'] == 'SUCCESS' %}#48bb78{% elif github_actions['status'] == 'FAILURE' %}#f56565{% else %}#cbd5e0{% endif %}">
                {{ github_actions.get('status', 'N/A') }}
            </div>
            <div class="stat-meta">
                {% if github_actions.get('workflow_name') %}
                {{ github_actions['workflow_name'] }}
                {% endif %}
            </div>
        </div>

        <div class="stat-card">
            <div class="stat-label">Latest Run</div>
            <div class="stat-value" style="font-size: 1.5em;">
                {% if github_actions.get('run_id') %}
                <a href="{{ github_actions['run_url'] }}" class="link" target="_blank">#{{ github_actions['run_id'] }}</a>
                {% else %}
                N/A
                {% endif %}
            </div>
            <div class="stat-meta">
                {% if github_actions.get('branch') %}
                {{ github_actions['branch'] }} · {{ github_actions.get('commit', '') }}
                {% endif %}
            </div>
        </div>

        <div class="stat-card">
            <div class="stat-label">Security Issues</div>
            <div class="stat-value" id="total-issues" style="color: {% if bandit['issues'] + safety['vulns'] + trivy['vulns'] == 0 %}#48bb78{% else %}#f56565{% endif %}">
                {{ bandit['issues'] + safety['vulns'] + trivy['vulns'] }}
            </div>
            <div class="stat-meta">Total vulnerabilities detected</div>
        </div>

        <div class="stat-card">
            <div class="stat-label">Test Coverage</div>
            <div class="stat-value" id="coverage-stat" style="color: {% if coverage['coverage'] >= 80 %}#48bb78{% elif coverage['coverage'] >= 60 %}#ed8936{% else %}#f56565{% endif %}">
                {{ coverage['coverage'] }}%
            </div>
            <div class="stat-meta">Code coverage threshold: 80%</div>
        </div>
    </div>

    <div class="main-content">
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">CI/CD Pipeline Execution</h2>
                <div class="data-source">
                    <svg class="source-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 0a10 10 0 1 0 10 10A10 10 0 0 0 10 0zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/>
                        <path d="M10 5a1 1 0 0 0-1 1v4a1 1 0 0 0 2 0V6a1 1 0 0 0-1-1zm0 8a1 1 0 1 0 1 1 1 1 0 0 0-1-1z"/>
                    </svg>
                    GitHub Actions API
                </div>
            </div>

            <div class="pipeline-flow">
                {% set job_names = ['security-scanning', 'unit-tests', 'build-scan-docker-image', 'deploy-simulation'] %}
                {% set job_labels = ['Security Scan', 'Unit Tests', 'Build & Scan', 'Deploy'] %}
                {% for i in range(4) %}
                <div class="flow-step {{ job_status(job_names[i]) }}">
                    <div class="step-name">{{ job_labels[i] }}</div>
                    <span class="step-status {{ job_status(job_names[i]) }}">
                        {{ job_conclusion(job_names[i]) }}
                    </span>
                    <div class="step-meta">
                        {% set job_data = github_actions.get('jobs', {}).get(job_names[i], {}) %}
                        {% if job_data.get('html_url') %}
                        <a href="{{ job_data['html_url'] }}" class="link" target="_blank">View logs →</a>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Security & Quality Scan Results</h2>
                <div class="data-source">
                    <svg class="source-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M3 3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3z"/>
                    </svg>
                    Artifacts from Run #{{ github_actions.get('run_id', 'N/A') }}
                </div>
            </div>

            <div class="results-grid">
                <div class="result-card {{ bandit_status }}">
                    <div class="result-header">
                        <span class="result-tool">Bandit (SAST)</span>
                        <span class="result-badge {{ bandit_status }}" id="bandit-status">{{ bandit['status'] }}</span>
                    </div>
                    <div class="result-summary" id="bandit-summary">{{ bandit['issues'] }}</div>
                    <div class="result-description">Security issues in Python code</div>

                    {% if bandit.get('severity') %}
                    <div class="severity-breakdown">
                        <div class="severity-count">
                            <span class="severity-dot high"></span>
                            <span>HIGH: {{ bandit['severity'].get('HIGH', 0) }}</span>
                        </div>
                        <div class="severity-count">
                            <span class="severity-dot medium"></span>
                            <span>MEDIUM: {{ bandit['severity'].get('MEDIUM', 0) }}</span>
                        </div>
                        <div class="severity-count">
                            <span class="severity-dot low"></span>
                            <span>LOW: {{ bandit['severity'].get('LOW', 0) }}</span>
                        </div>
                    </div>
                    {% endif %}

                    {% if bandit.get('findings') and bandit['findings']|length > 0 %}
                    <button class="details-toggle" onclick="toggleDetails('bandit-details')">
                        View {{ bandit['findings']|length }} Detailed Findings
                    </button>
                    <div class="findings-details" id="bandit-details">
                        <div class="findings-list">
                            {% for finding in bandit['findings'] %}
                            <div class="finding-item">
                                <div class="finding-header">
                                    <div>
                                        <div class="finding-file">{{ finding['file'] }}:{{ finding['line'] }}</div>
                                        <div class="finding-description">{{ finding['issue'] }}</div>
                                    </div>
                                    <span class="severity-badge {{ finding['severity']|lower }}">{{ finding['severity'] }}</span>
                                </div>
                                <div class="finding-meta">
                                    <span>Test ID: {{ finding['test_id'] }}</span>
                                    <span>Confidence: {{ finding['confidence'] }}</span>
                                    {% if finding.get('cwe_link') %}
                                    <a href="{{ finding['cwe_link'] }}" target="_blank" class="finding-link">CWE Reference →</a>
                                    {% endif %}
                                    {% if finding.get('more_info') %}
                                    <a href="{{ finding['more_info'] }}" target="_blank" class="finding-link">More Info →</a>
                                    {% endif %}
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <div class="result-card {{ safety_status }}">
                    <div class="result-header">
                        <span class="result-tool">Safety (SCA)</span>
                        <span class="result-badge {{ safety_status }}" id="safety-status">{{ safety['status'] }}</span>
                    </div>
                    <div class="result-summary" id="safety-summary">{{ safety['vulns'] }}</div>
                    <div class="result-description">Vulnerable dependencies detected</div>

                    {% if safety.get('vulnerabilities') and safety['vulnerabilities']|length > 0 %}
                    <button class="details-toggle" onclick="toggleDetails('safety-details')">
                        View {{ safety['vulnerabilities']|length }} Vulnerable Packages
                    </button>
                    <div class="findings-details" id="safety-details">
                        <div class="findings-list">
                            {% for vuln in safety['vulnerabilities'] %}
                            <div class="finding-item">
                                <div class="finding-header">
                                    <div>
                                        <div class="finding-file">{{ vuln['package'] }} {{ vuln['version'] }}</div>
                                        <div class="finding-description">{{ vuln['advisory'] }}</div>
                                    </div>
                                    <span class="severity-badge high">{{ vuln['cve'] }}</span>
                                </div>
                                <div class="finding-meta">
                                    {% if vuln.get('vulnerable_spec') %}
                                    <span>Affected: {{ vuln['vulnerable_spec'] }}</span>
                                    {% endif %}
                                    {% if vuln.get('more_info') %}
                                    <a href="{{ vuln['more_info'] }}" target="_blank" class="finding-link">Full Advisory →</a>
                                    {% endif %}
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <div class="result-card {{ coverage_status }}">
                    <div class="result-header">
                        <span class="result-tool">Coverage</span>
                        <span class="result-badge {{ coverage_status }}" id="coverage-status">{{ coverage['status'] }}</span>
                    </div>
                    <div class="result-summary" id="coverage-summary">{{ coverage['coverage'] }}%</div>
                    <div class="result-description">Unit test code coverage</div>
                </div>

                <div class="result-card {{ trivy_status }}">
                    <div class="result-header">
                        <span class="result-tool">Trivy</span>
                        <span class="result-badge {{ trivy_status }}" id="trivy-status">{{ trivy['status'] }}</span>
                    </div>
                    <div class="result-summary" id="trivy-summary">{{ trivy['vulns'] }}</div>
                    <div class="result-description">Container vulnerabilities found</div>

                    {% if trivy.get('vulnerabilities') and trivy['vulnerabilities']|length > 0 %}
                    <button class="details-toggle" onclick="toggleDetails('trivy-details')">
                        View {{ trivy['vulnerabilities']|length }} Container Vulnerabilities
                    </button>
                    <div class="findings-details" id="trivy-details">
                        <div class="findings-list">
                            {% for vuln in trivy['vulnerabilities'] %}
                            <div class="finding-item">
                                <div class="finding-header">
                                    <div>
                                        <div class="finding-file">{{ vuln['target'] }} - {{ vuln['package'] }}</div>
                                        <div class="finding-description">
                                            <strong>{{ vuln['vuln_id'] }}:</strong> {{ vuln.get('title', vuln.get('description', '')) }}
                                        </div>
                                    </div>
                                    <span class="severity-badge {{ vuln['severity']|lower }}">{{ vuln['severity'] }}</span>
                                </div>
                                <div class="finding-meta">
                                    <span>Installed: {{ vuln['installed_version'] }}</span>
                                    <span>Fixed: {{ vuln['fixed_version'] }}</span>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    <script>
        let refreshTimer = null;
        let refreshInterval = 30000; // 30 seconds default

        const spinner = document.getElementById('spinner');
        const refreshStatus = document.getElementById('refresh-status');
        const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
        const intervalSelect = document.getElementById('refresh-interval');
        const manualRefreshBtn = document.getElementById('manual-refresh');

        // Toggle details section
        function toggleDetails(detailsId) {
            const detailsElement = document.getElementById(detailsId);
            const toggleButton = event.target;

            if (detailsElement.classList.contains('active')) {
                detailsElement.classList.remove('active');
                toggleButton.classList.remove('active');
            } else {
                detailsElement.classList.add('active');
                toggleButton.classList.add('active');
            }
        }

        function updateStatusClass(element, oldClasses, newClass) {
            const classes = ['ok', 'success', 'warn', 'fail', 'failure', 'na', 'error', 'in-progress', 'queued', 'skipped', 'cancelled'];
            classes.forEach(c => element.classList.remove(c));
            element.classList.add(newClass);
        }

        function getStatusClass(status) {
            const s = status.toLowerCase();
            if (s.startsWith('ok') || s === 'success') return 'ok';
            if (s.startsWith('warn')) return 'warn';
            if (s.startsWith('fail') || s === 'failure') return 'fail';
            if (s === 'error') return 'error';
            if (s.includes('progress') || s === 'queued') return 'in-progress';
            if (s === 'skipped' || s === 'cancelled') return 'skipped';
            return 'na';
        }

        async function refreshData() {
            spinner.classList.add('active');
            manualRefreshBtn.disabled = true;

            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                // Update timestamp
                const timestamp = new Date(data.timestamp);
                document.getElementById('timestamp').textContent =
                    timestamp.toLocaleString('en-US', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        timeZone: 'UTC',
                        timeZoneName: 'short'
                    });

                // Update tool results
                if (data.bandit) {
                    document.getElementById('bandit-summary').textContent = data.bandit.issues + ' issues found';
                    const banditStatus = document.getElementById('bandit-status');
                    banditStatus.textContent = data.bandit.status;
                    updateStatusClass(banditStatus, null, getStatusClass(data.bandit.status));
                }

                if (data.safety) {
                    document.getElementById('safety-summary').textContent = data.safety.vulns + ' vulnerabilities';
                    const safetyStatus = document.getElementById('safety-status');
                    safetyStatus.textContent = data.safety.status;
                    updateStatusClass(safetyStatus, null, getStatusClass(data.safety.status));
                }

                if (data.coverage) {
                    document.getElementById('coverage-summary').textContent = data.coverage.coverage + '%';
                    const coverageStatus = document.getElementById('coverage-status');
                    coverageStatus.textContent = data.coverage.status;
                    updateStatusClass(coverageStatus, null, getStatusClass(data.coverage.status));
                }

                if (data.trivy) {
                    document.getElementById('trivy-summary').textContent = data.trivy.vulns + ' vulnerabilities';
                    const trivyStatus = document.getElementById('trivy-status');
                    trivyStatus.textContent = data.trivy.status;
                    updateStatusClass(trivyStatus, null, getStatusClass(data.trivy.status));
                }

                // Reload GitHub Actions section (full page reload for complex template logic)
                // This ensures job statuses are properly updated
                const githubSection = document.getElementById('github-section');
                githubSection.classList.add('updating');
                setTimeout(() => githubSection.classList.remove('updating'), 500);

            } catch (error) {
                console.error('Failed to refresh data:', error);
                refreshStatus.textContent = 'Auto-refresh: ERROR';
            } finally {
                spinner.classList.remove('active');
                manualRefreshBtn.disabled = false;
            }
        }

        function startAutoRefresh() {
            if (refreshTimer) clearInterval(refreshTimer);
            if (autoRefreshToggle.checked) {
                refreshTimer = setInterval(refreshData, refreshInterval);
                const seconds = refreshInterval / 1000;
                refreshStatus.textContent = `Auto-refresh: ON (${seconds}s)`;
            } else {
                refreshStatus.textContent = 'Auto-refresh: OFF';
            }
        }

        // Event listeners
        autoRefreshToggle.addEventListener('change', startAutoRefresh);

        intervalSelect.addEventListener('change', (e) => {
            refreshInterval = parseInt(e.target.value) * 1000;
            startAutoRefresh();
        });

        manualRefreshBtn.addEventListener('click', refreshData);

        // Start auto-refresh on load
        startAutoRefresh();
    </script>
</body>
</html>
"""

# --- Routes -----------------------------------------------------------------

@app.route('/')
def dashboard():
    """Dynamic dashboard view"""
    bandit = load_bandit_results()
    safety = load_safety_results()
    coverage = load_coverage()
    trivy = load_trivy_results()
    github_actions = get_github_actions_status()

    def status_class(status):
        s = status.lower()
        if s.startswith("ok") or s == "success": return "ok"
        if s.startswith("warn"): return "warn"
        if s.startswith("fail") or s == "failure": return "fail"
        if s == "error": return "error"
        if "progress" in s or s == "queued": return "in-progress"
        if s == "skipped" or s == "cancelled": return "skipped"
        return "na"

    def normalize_job_name(name):
        """Normalize job name for matching"""
        return name.lower().replace(" ", "-").replace("&", "").replace("(", "").replace(")", "").replace("--", "-").strip()

    def get_job_status(job_name):
        """Get status class for a specific GitHub Actions job"""
        jobs = github_actions.get("jobs", {})
        normalized_search = normalize_job_name(job_name)

        for key, job in jobs.items():
            normalized_key = normalize_job_name(key)
            # Check if the search term is in the key or vice versa
            if normalized_search in normalized_key or normalized_key in normalized_search:
                conclusion = job.get("conclusion", "none")
                if conclusion == "success":
                    return "success"
                elif conclusion == "failure":
                    return "failure"
                elif conclusion == "skipped":
                    return "skipped"
                elif conclusion == "cancelled":
                    return "cancelled"
                elif job.get("status") == "in_progress":
                    return "in-progress"
        return "na"

    def get_job_conclusion(job_name):
        """Get conclusion text for a specific GitHub Actions job"""
        jobs = github_actions.get("jobs", {})
        normalized_search = normalize_job_name(job_name)

        for key, job in jobs.items():
            normalized_key = normalize_job_name(key)
            # Check if the search term is in the key or vice versa
            if normalized_search in normalized_key or normalized_key in normalized_search:
                conclusion = job.get("conclusion", "none")
                if conclusion and conclusion != "none":
                    return conclusion.upper()
                status = job.get("status", "unknown")
                return status.upper()
        return "N/A"

    return render_template_string(
        HTML_TEMPLATE,
        timestamp=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        bandit=bandit,
        safety=safety,
        coverage=coverage,
        trivy=trivy,
        github_actions=github_actions,
        bandit_status=status_class(bandit["status"]),
        safety_status=status_class(safety["status"]),
        coverage_status=status_class(coverage["status"]),
        trivy_status=status_class(trivy["status"]),
        pipeline_status=status_class(github_actions.get("status", "N/A")),
        job_status=get_job_status,
        job_conclusion=get_job_conclusion
    )


@app.route('/api/status')
def api_status():
    """Return JSON summary for external monitoring"""
    return jsonify({
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
        "bandit": load_bandit_results(),
        "safety": load_safety_results(),
        "coverage": load_coverage(),
        "trivy": load_trivy_results(),
        "github_actions": get_github_actions_status()
    }), 200
    
@app.route('/api/update', methods=['POST'])
def update_results():
    from flask import request, jsonify
    import json, os
    AUTH_TOKEN = os.environ.get("API_TOKEN", "")
    token = request.headers.get("Authorization")
    if token != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    os.makedirs("reports", exist_ok=True)
    with open("reports/latest_status.json", "w") as f:
        json.dump(data, f, indent=2)
    return jsonify({"message": "Results updated successfully"}), 200

@app.route('/health')
def health():
    """Basic health endpoint"""
    return jsonify({"status": "healthy", "version": "1.0.0"}), 200

@app.route('/api/echo', methods=['POST'])
def echo():
    """Echo endpoint for testing"""
    from flask import request

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    message = data.get('message', '')

    if len(message) > 1000:
        return jsonify({"error": "Message exceeds maximum length of 1000 characters"}), 400

    return jsonify({
        "echo": message,
        "length": len(message)
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
