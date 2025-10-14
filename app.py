from flask import Flask, jsonify, render_template_string
import os
import json
import xml.etree.ElementTree as ET
import datetime

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

# --- Dashboard HTML Template ------------------------------------------------

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Dashboard</title>
    <style>
        body { font-family: "Segoe UI", Arial, sans-serif; background-color: #f4f6f8; margin: 0; }
        header { background-color: #0078d4; color: white; padding: 20px; text-align: center; }
        .container { max-width: 900px; margin: 30px auto; background: white; padding: 25px 40px;
                     border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #ddd; }
        th { background-color: #f0f0f0; }
        .status { padding: 6px 12px; border-radius: 5px; color: white; font-weight: bold; }
        .ok { background-color: #28a745; }
        .warn { background-color: #ffc107; color: #333; }
        .fail { background-color: #dc3545; }
        .na { background-color: #6c757d; }
        footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <header>
        <h1>DevSecOps Dashboard</h1>
        <p>Security · Testing · CI/CD Monitoring</p>
    </header>

    <div class="container">
        <h2>System Overview</h2>
        <p><strong>Status:</strong> <span class="status ok">Running</span></p>
        <p><strong>Version:</strong> 1.0.0</p>
        <p><strong>Last Updated:</strong> {{ timestamp }}</p>

        <h2>Tool Results</h2>
        <table>
            <tr><th>Tool</th><th>Purpose</th><th>Summary</th><th>Status</th></tr>
            <tr>
                <td>Bandit</td><td>Static code analysis (SAST)</td>
                <td>{{ bandit['issues'] }} issues found</td>
                <td><span class="status {{ bandit_status }}">{{ bandit['status'] }}</span></td>
            </tr>
            <tr>
                <td>Safety</td><td>Dependency vulnerability scan</td>
                <td>{{ safety['vulns'] }} vulnerabilities</td>
                <td><span class="status {{ safety_status }}">{{ safety['status'] }}</span></td>
            </tr>
            <tr>
                <td>Coverage</td><td>Unit test coverage</td>
                <td>{{ coverage['coverage'] }}%</td>
                <td><span class="status {{ coverage_status }}">{{ coverage['status'] }}</span></td>
            </tr>
            <tr>
                <td>Trivy</td><td>Container image scan</td>
                <td>{{ trivy['vulns'] }} vulnerabilities</td>
                <td><span class="status {{ trivy_status }}">{{ trivy['status'] }}</span></td>
            </tr>
        </table>
    </div>

    <footer>© 2025 DevSecOps Demo · Flask Monitoring Dashboard</footer>
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

    def status_class(status):
        s = status.lower()
        if s.startswith("ok"): return "ok"
        if s.startswith("warn"): return "warn"
        if s.startswith("fail"): return "fail"
        return "na"

    return render_template_string(
        HTML_TEMPLATE,
        timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        bandit=bandit,
        safety=safety,
        coverage=coverage,
        trivy=trivy,
        bandit_status=status_class(bandit["status"]),
        safety_status=status_class(safety["status"]),
        coverage_status=status_class(coverage["status"]),
        trivy_status=status_class(trivy["status"])
    )


@app.route('/api/status')
def api_status():
    """Return JSON summary for external monitoring"""
    return jsonify({
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "bandit": load_bandit_results(),
        "safety": load_safety_results(),
        "coverage": load_coverage(),
        "trivy": load_trivy_results()
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
