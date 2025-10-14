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
        return {"status": "N/A", "issues": 0, "severity": {}}

    try:
        with open(path, "r") as f:
            data = json.load(f)
        issues = len(data.get("results", []))
        severities = {}
        for result in data.get("results", []):
            sev = result.get("issue_severity", "LOW").upper()
            severities[sev] = severities.get(sev, 0) + 1
        return {"status": "OK" if issues == 0 else "FAIL", "issues": issues, "severity": severities}
    except Exception as e:
        return {"status": "ERROR", "issues": 0, "error": str(e)}


def load_safety_results(path="safety.json"):
    """Read Safety vulnerability scan results"""
    if not os.path.exists(path):
        return {"status": "N/A", "vulns": 0}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        vulns = len(data) if isinstance(data, list) else 0
        return {"status": "OK" if vulns == 0 else "FAIL", "vulns": vulns}
    except Exception as e:
        return {"status": "ERROR", "vulns": 0, "error": str(e)}


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
        return {"status": "N/A", "vulns": 0}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        results = data.get("Results", [])
        total_vulns = 0
        for r in results:
            total_vulns += len(r.get("Vulnerabilities", []))
        return {"status": "OK" if total_vulns == 0 else "FAIL", "vulns": total_vulns}
    except Exception as e:
        return {"status": "ERROR", "vulns": 0, "error": str(e)}


def get_github_actions_status():
    """Fetch latest GitHub Actions workflow run status"""
    github_token = os.environ.get("GITHUB_TOKEN", "")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "")  # format: owner/repo

    if not github_token or not github_repo:
        return {
            "status": "N/A",
            "jobs": {
                "security-scan": {"status": "N/A", "conclusion": "N/A"},
                "test": {"status": "N/A", "conclusion": "N/A"},
                "build": {"status": "N/A", "conclusion": "N/A"},
                "deploy": {"status": "N/A", "conclusion": "N/A"}
            },
            "run_id": None,
            "run_url": None,
            "branch": None,
            "commit": None
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
            params={"per_page": 1, "status": "completed"},
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
                "completed_at": job.get("completed_at")
            }

        overall_status = latest_run.get("conclusion", "unknown").upper()

        return {
            "status": overall_status,
            "jobs": jobs,
            "run_id": run_id,
            "run_url": latest_run.get("html_url"),
            "branch": latest_run.get("head_branch"),
            "commit": latest_run.get("head_sha", "")[:7],
            "created_at": latest_run.get("created_at"),
            "updated_at": latest_run.get("updated_at")
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
    <title>DevSecOps Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: "Segoe UI", Arial, sans-serif; background-color: #f4f6f8; margin: 0; }
        header { background-color: #0078d4; color: white; padding: 20px; text-align: center; position: relative; }
        .container { max-width: 1100px; margin: 30px auto; background: white; padding: 25px 40px;
                     border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #ddd; }
        th { background-color: #f0f0f0; }
        .status { padding: 6px 12px; border-radius: 5px; color: white; font-weight: bold; display: inline-block; min-width: 60px; text-align: center; }
        .ok, .success { background-color: #28a745; }
        .warn { background-color: #ffc107; color: #333; }
        .fail, .failure { background-color: #dc3545; }
        .na { background-color: #6c757d; }
        .error { background-color: #dc3545; }
        .in-progress, .queued { background-color: #17a2b8; }
        .skipped, .cancelled { background-color: #6c757d; }
        .pipeline-info { margin-top: 10px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
        .pipeline-info p { margin: 5px 0; }
        .pipeline-link { color: #0078d4; text-decoration: none; font-weight: bold; }
        .pipeline-link:hover { text-decoration: underline; }
        .section { margin-top: 30px; }
        footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }
        .refresh-indicator {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.2);
            padding: 8px 15px;
            border-radius: 5px;
            font-size: 0.9em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .spinner {
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            display: none;
        }
        .spinner.active { display: block; }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .updating { animation: pulse 1s ease-in-out infinite; }
        .auto-refresh-controls {
            margin-top: 10px;
            padding: 10px;
            background: #e9ecef;
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .refresh-btn {
            background: #0078d4;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .refresh-btn:hover { background: #005a9e; }
        .refresh-btn:disabled { background: #6c757d; cursor: not-allowed; }
    </style>
</head>
<body>
    <header>
        <h1>DevSecOps Dashboard</h1>
        <p>Security · Testing · CI/CD Monitoring</p>
        <div class="refresh-indicator">
            <div class="spinner" id="spinner"></div>
            <span id="refresh-status">Auto-refresh: ON (30s)</span>
        </div>
    </header>

    <div class="container">
        <h2>System Overview</h2>
        <p><strong>Status:</strong> <span class="status ok">Running</span></p>
        <p><strong>Version:</strong> 1.0.0</p>
        <p><strong>Last Updated:</strong> <span id="timestamp">{{ timestamp }}</span></p>

        <div class="auto-refresh-controls">
            <div>
                <label>
                    <input type="checkbox" id="auto-refresh-toggle" checked>
                    Enable Auto-Refresh (every <select id="refresh-interval">
                        <option value="10">10s</option>
                        <option value="30" selected>30s</option>
                        <option value="60">60s</option>
                        <option value="120">2min</option>
                    </select>)
                </label>
            </div>
            <button class="refresh-btn" id="manual-refresh">Refresh Now</button>
        </div>

        <div class="section" id="github-section">
            <h2>GitHub Actions Pipeline Status</h2>
            {% if github_actions['status'] != 'N/A' and github_actions['status'] != 'ERROR' %}
            <div class="pipeline-info">
                <p><strong>Overall Status:</strong> <span class="status {{ pipeline_status }}">{{ github_actions['status'] }}</span></p>
                {% if github_actions.get('run_url') %}
                <p><strong>Latest Run:</strong> <a href="{{ github_actions['run_url'] }}" class="pipeline-link" target="_blank">#{{ github_actions['run_id'] }}</a></p>
                {% endif %}
                {% if github_actions.get('branch') %}
                <p><strong>Branch:</strong> {{ github_actions['branch'] }} | <strong>Commit:</strong> {{ github_actions.get('commit', 'N/A') }}</p>
                {% endif %}
            </div>
            {% else %}
            <div class="pipeline-info">
                <p><strong>Status:</strong> {{ github_actions.get('status', 'N/A') }}</p>
                {% if github_actions.get('error') %}
                <p><strong>Error:</strong> {{ github_actions['error'] }}</p>
                {% endif %}
                {% if github_actions.get('message') %}
                <p>{{ github_actions['message'] }}</p>
                {% endif %}
            </div>
            {% endif %}

            <table id="pipeline-jobs">
                <tr><th>Job</th><th>Description</th><th>Status</th></tr>
                <tr>
                    <td>Security Scanning</td>
                    <td>Run Bandit & Safety checks</td>
                    <td><span class="status {{ job_status('security-scanning') }}">{{ job_conclusion('security-scanning') }}</span></td>
                </tr>
                <tr>
                    <td>Unit Tests</td>
                    <td>Run pytest with coverage</td>
                    <td><span class="status {{ job_status('unit-tests') }}">{{ job_conclusion('unit-tests') }}</span></td>
                </tr>
                <tr>
                    <td>Build & Scan Docker</td>
                    <td>Build image & run Trivy scan</td>
                    <td><span class="status {{ job_status('build-scan-docker-image') }}">{{ job_conclusion('build-scan-docker-image') }}</span></td>
                </tr>
                <tr>
                    <td>Deploy</td>
                    <td>Deployment (Simulation)</td>
                    <td><span class="status {{ job_status('deploy-simulation') }}">{{ job_conclusion('deploy-simulation') }}</span></td>
                </tr>
            </table>
        </div>

        <div class="section" id="tools-section">
            <h2>Security & Testing Tool Results</h2>
            <table id="tools-table">
                <tr><th>Tool</th><th>Purpose</th><th>Summary</th><th>Status</th></tr>
                <tr>
                    <td>Bandit</td><td>Static code analysis (SAST)</td>
                    <td id="bandit-summary">{{ bandit['issues'] }} issues found</td>
                    <td><span class="status {{ bandit_status }}" id="bandit-status">{{ bandit['status'] }}</span></td>
                </tr>
                <tr>
                    <td>Safety</td><td>Dependency vulnerability scan</td>
                    <td id="safety-summary">{{ safety['vulns'] }} vulnerabilities</td>
                    <td><span class="status {{ safety_status }}" id="safety-status">{{ safety['status'] }}</span></td>
                </tr>
                <tr>
                    <td>Coverage</td><td>Unit test coverage</td>
                    <td id="coverage-summary">{{ coverage['coverage'] }}%</td>
                    <td><span class="status {{ coverage_status }}" id="coverage-status">{{ coverage['status'] }}</span></td>
                </tr>
                <tr>
                    <td>Trivy</td><td>Container image scan</td>
                    <td id="trivy-summary">{{ trivy['vulns'] }} vulnerabilities</td>
                    <td><span class="status {{ trivy_status }}" id="trivy-status">{{ trivy['status'] }}</span></td>
                </tr>
            </table>
        </div>
    </div>

    <footer>© 2025 DevSecOps Demo · Flask Monitoring Dashboard</footer>

    <script>
        let refreshTimer = null;
        let refreshInterval = 30000; // 30 seconds default

        const spinner = document.getElementById('spinner');
        const refreshStatus = document.getElementById('refresh-status');
        const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
        const intervalSelect = document.getElementById('refresh-interval');
        const manualRefreshBtn = document.getElementById('manual-refresh');

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
