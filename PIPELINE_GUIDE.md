# Complete DevSecOps Pipeline Guide

This document provides a comprehensive guide to implementing a full DevSecOps pipeline with all recommended tools and practices.

## Table of Contents
1. [Pipeline Stages](#pipeline-stages)
2. [Tool Integration Guide](#tool-integration-guide)
3. [Security Gates](#security-gates)
4. [Metrics and KPIs](#metrics-and-kpis)
5. [Best Practices](#best-practices)

## Pipeline Stages

### Stage 1: Pre-Commit (Developer Workstation)

**Goal**: Catch issues before code is committed

```yaml
Tools to Install Locally:
├── IDE Security Extensions
│   ├── SonarLint (Real-time SAST)
│   ├── Snyk Plugin (Dependency checking)
│   └── GitLens (Code review assistance)
│
├── Pre-commit Hooks
│   ├── detect-secrets (Prevent secret commits)
│   ├── black (Code formatting)
│   ├── flake8 (Linting)
│   └── bandit (Quick security scan)
│
└── Local Testing
    ├── pytest (Unit tests)
    └── docker-compose (Local deployment)
```

**Setup Pre-commit Hooks**:
```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml <<EOF
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-ll']
EOF

# Install hooks
pre-commit install
```

---

### Stage 2: Code Commit & Pull Request

**Goal**: Automated code review and security checks

```yaml
GitHub/GitLab Actions:
├── Branch Protection Rules
│   ├── Require PR reviews (2+ approvers)
│   ├── Require status checks to pass
│   ├── Require signed commits
│   └── No force pushes to main
│
├── Automated Checks
│   ├── Code review (GitHub Code Scanning)
│   ├── Security review (Dependabot)
│   └── License compliance check
│
└── PR Templates
    └── Security checklist included
```

**Sample GitHub Branch Protection**:
```yaml
# .github/settings.yml
branches:
  - name: main
    protection:
      required_pull_request_reviews:
        required_approving_review_count: 2
      required_status_checks:
        strict: true
        contexts:
          - security-scan
          - unit-tests
          - container-scan
      enforce_admins: true
      required_signatures: true
```

---

### Stage 3: CI Pipeline - Security Scanning

**Goal**: Comprehensive automated security analysis

#### 3.1 SAST (Static Application Security Testing)

**Multiple Tool Comparison**:

```yaml
# Option 1: Bandit (Python-specific, Fast)
- name: Bandit Scan
  run: |
    bandit -r . -f json -o bandit-report.json
    bandit -r . -ll  # Only show medium+ severity

# Option 2: SonarQube (Multi-language, Comprehensive)
- name: SonarQube Scan
  uses: sonarsource/sonarqube-scan-action@master
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

# Option 3: Semgrep (Fast, Customizable)
- name: Semgrep Scan
  run: |
    pip install semgrep
    semgrep --config=auto --json -o semgrep.json

# Option 4: CodeQL (GitHub native, Deep analysis)
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: python
```

**Recommended**: Start with Bandit, add SonarQube for comprehensive analysis

#### 3.2 SCA (Software Composition Analysis)

```yaml
# Option 1: Safety (Python dependencies)
- name: Safety Check
  run: |
    pip install safety
    safety check --json --output safety-report.json

# Option 2: Snyk (Multi-language, Comprehensive DB)
- name: Snyk Test
  uses: snyk/actions/python@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

# Option 3: OWASP Dependency-Check
- name: OWASP Dependency Check
  uses: dependency-check/Dependency-Check_Action@main
  with:
    project: 'devsecops-demo'
    path: '.'
    format: 'HTML'

# Option 4: Trivy (Filesystem scan)
- name: Trivy FS Scan
  run: |
    trivy fs --security-checks vuln,config .
```

#### 3.3 Secrets Scanning

```yaml
# Option 1: GitLeaks
- name: GitLeaks Scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

# Option 2: TruffleHog
- name: TruffleHog Scan
  run: |
    pip install truffleHog
    trufflehog --regex --entropy=True .

# Option 3: Detect Secrets
- name: Detect Secrets
  run: |
    pip install detect-secrets
    detect-secrets scan --baseline .secrets.baseline
```

---

### Stage 4: CI Pipeline - Testing

**Goal**: Ensure functionality and quality

```yaml
Testing Strategy:
├── Unit Tests (pytest)
│   ├── Code coverage > 80%
│   ├── Security-focused tests
│   └── Mock external dependencies
│
├── Integration Tests
│   ├── API endpoint testing
│   ├── Database integration
│   └── External service mocking
│
├── Security Tests
│   ├── Authentication tests
│   ├── Authorization tests
│   ├── Input validation tests
│   └── OWASP Top 10 tests
│
└── Performance Tests (Optional)
    ├── Load testing (Locust)
    └── Stress testing (JMeter)
```

**Implementation**:
```yaml
- name: Run Tests
  run: |
    pytest \
      --cov=app \
      --cov-report=xml \
      --cov-report=html \
      --cov-fail-under=80 \
      --junitxml=junit.xml

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
    fail_ci_if_error: true
```

---

### Stage 5: Container Security

**Goal**: Secure container images

#### 5.1 Dockerfile Linting

```yaml
- name: Hadolint
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: Dockerfile
    failure-threshold: warning
```

#### 5.2 Image Scanning

```yaml
# Option 1: Trivy (Fast, Accurate, Free)
- name: Trivy Image Scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'devsecops-demo:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'  # Fail on findings

# Option 2: Clair
- name: Clair Scan
  run: |
    docker run --rm arminc/clair-scanner \
      --ip $(hostname -I | awk '{print $1}') \
      devsecops-demo:latest

# Option 3: Anchore
- name: Anchore Scan
  uses: anchore/scan-action@v3
  with:
    image: "devsecops-demo:${{ github.sha }}"
    fail-build: true
    severity-cutoff: high
```

#### 5.3 Image Signing

```yaml
- name: Sign Container Image
  run: |
    # Install Cosign
    curl -sL https://github.com/sigstore/cosign/releases/download/v2.0.0/cosign-linux-amd64 -o cosign
    chmod +x cosign

    # Sign image
    ./cosign sign --key cosign.key devsecops-demo:${{ github.sha }}
```

---

### Stage 6: Infrastructure as Code (IaC) Security

**Goal**: Secure infrastructure configuration

```yaml
# Checkov (Multi-cloud IaC scanner)
- name: Checkov Scan
  uses: bridgecrewio/checkov-action@master
  with:
    directory: ./terraform
    framework: terraform
    soft_fail: false

# tfsec (Terraform-specific)
- name: tfsec
  uses: aquasecurity/tfsec-action@v1.0.0
  with:
    working_directory: ./terraform

# Terrascan (Multi-IaC)
- name: Terrascan
  uses: tenable/terrascan-action@main
  with:
    iac_type: 'terraform'
    iac_dir: './terraform'
    policy_type: 'aws'
```

---

### Stage 7: DAST (Dynamic Application Security Testing)

**Goal**: Test running application for vulnerabilities

```yaml
# OWASP ZAP
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.7.0
  with:
    target: 'http://localhost:5000'
    rules_file_name: '.zap/rules.tsv'
    fail_action: true

# Or full scan
- name: ZAP Full Scan
  uses: zaproxy/action-full-scan@v0.4.0
  with:
    target: 'http://localhost:5000'
    artifact_name: 'zap_report'
```

**For API Testing**:
```yaml
- name: Start Application
  run: |
    docker-compose up -d
    sleep 10  # Wait for app to start

- name: Run API Security Tests
  run: |
    # Using OWASP ZAP API scan
    docker run -t owasp/zap2docker-stable zap-api-scan.py \
      -t http://host.docker.internal:5000/openapi.json \
      -f openapi -r api-scan-report.html
```

---

### Stage 8: Deployment

**Goal**: Secure deployment to production

```yaml
deployment:
├── Environment Separation
│   ├── Development
│   ├── Staging (Production-like)
│   └── Production
│
├── Deployment Strategies
│   ├── Blue/Green
│   ├── Canary
│   └── Rolling Updates
│
├── Security Checks
│   ├── Image signature verification
│   ├── Policy enforcement (OPA)
│   └── Runtime security setup
│
└── Post-Deployment
    ├── Smoke tests
    ├── Security regression tests
    └── Monitoring setup
```

**Example Deployment with Security**:
```yaml
deploy:
  needs: [security-scan, test, build]
  runs-on: ubuntu-latest
  environment: production

  steps:
    - name: Verify Image Signature
      run: |
        cosign verify --key cosign.pub \
          devsecops-demo:${{ github.sha }}

    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/devsecops-demo \
          app=devsecops-demo:${{ github.sha }}

    - name: Run Smoke Tests
      run: |
        curl -f http://production-url/health || exit 1

    - name: Setup Monitoring
      run: |
        # Configure Prometheus alerts
        kubectl apply -f monitoring/alerts.yaml
```

---

### Stage 9: Runtime Security & Monitoring

**Goal**: Continuous security monitoring in production

```yaml
Runtime Protection:
├── Web Application Firewall (WAF)
│   ├── AWS WAF / Azure WAF
│   ├── Cloudflare WAF
│   └── ModSecurity
│
├── Runtime Security
│   ├── Falco (Container runtime security)
│   ├── Aqua Runtime Protection
│   └── Sysdig Secure
│
├── Monitoring
│   ├── Prometheus + Grafana
│   ├── ELK Stack (Logs)
│   └── Datadog / New Relic
│
└── Incident Response
    ├── PagerDuty / Opsgenie
    ├── Security Information and Event Management (SIEM)
    └── Automated incident response playbooks
```

---

## Security Gates

Security gates are checkpoints that can stop the pipeline if critical issues are found.

### Gate Configuration

```yaml
security_gates:
  sast:
    fail_on:
      - severity: CRITICAL
        count: 1
      - severity: HIGH
        count: 5

  sca:
    fail_on:
      - cvss_score: '>= 9.0'  # Critical
      - cvss_score: '>= 7.0'   # High, max 3
        count: 3

  container_scan:
    fail_on:
      - severity: CRITICAL
      - severity: HIGH
        count: 10

  code_coverage:
    minimum: 80
    fail_below: true
```

### Implementation Example

```yaml
- name: Evaluate Security Gate
  run: |
    python scripts/security_gate.py \
      --bandit bandit-report.json \
      --safety safety-report.json \
      --trivy trivy-report.json \
      --config security-gate-config.yaml
```

---

## Metrics and KPIs

### Security Metrics to Track

```yaml
Metrics:
  ├── Vulnerability Metrics
  │   ├── Mean Time to Detect (MTTD)
  │   ├── Mean Time to Remediate (MTTR)
  │   ├── Vulnerability Density (vulns per KLOC)
  │   └── Critical/High vuln trend
  │
  ├── Pipeline Metrics
  │   ├── Pipeline success rate
  │   ├── Pipeline duration
  │   ├── Security scan duration
  │   └── Failed builds due to security
  │
  ├── Code Quality
  │   ├── Code coverage %
  │   ├── Technical debt ratio
  │   └── Security hotspots
  │
  └── Compliance
      ├── Policy violations
      ├── Compliance score
      └── Audit findings
```

### Dashboard Example (Grafana)

```yaml
# Sample Prometheus queries for Grafana

# Security findings by severity
sum by (severity) (security_findings_total)

# MTTR for critical vulnerabilities
avg(security_vulnerability_resolution_time{severity="critical"})

# Pipeline security gate failures
rate(pipeline_security_gate_failures_total[1h])

# Deployment frequency
rate(deployments_total[1d])
```

---

## Best Practices

### 1. Shift Left Security

```
✓ DO:
  - Run security checks in IDE
  - Use pre-commit hooks
  - Automate security in CI/CD
  - Train developers on secure coding

✗ DON'T:
  - Wait until production for security testing
  - Make security someone else's problem
  - Ignore security tool findings
```

### 2. Tool Selection

```
Start Simple:
1. SAST: Bandit (Python) or language-specific tool
2. SCA: Safety / npm audit / bundler-audit
3. Secrets: GitLeaks
4. Container: Trivy

Add Later:
5. SonarQube for comprehensive SAST
6. Snyk for better SCA
7. OWASP ZAP for DAST
8. Runtime protection (Falco)
```

### 3. False Positive Management

```yaml
Strategy:
  1. Review all findings
  2. Document false positives
  3. Suppress with justification
  4. Regular review of suppressions
  5. Tune tool configurations

Example Suppression:
  # .bandit
  [bandit]
  exclude = /tests

  # In code
  import pickle
  data = pickle.loads(trusted_data)  # nosec - B301: Data from trusted source
```

### 4. Security Gate Strategy

```
Recommended Approach:
├── Week 1-2: Warning only (don't fail builds)
├── Week 3-4: Fail on CRITICAL only
├── Week 5-6: Fail on CRITICAL + HIGH (with count limit)
└── Week 7+: Full enforcement with approved exceptions
```

### 5. Secrets Management

```yaml
✓ DO:
  - Use secret management tools (HashiCorp Vault, AWS Secrets Manager)
  - Rotate secrets regularly
  - Use environment variables
  - Scan for committed secrets

✗ DON'T:
  - Hardcode secrets in code
  - Commit .env files
  - Share secrets in chat/email
  - Use same secrets across environments
```

### 6. Container Security Hardening

```dockerfile
# Best practices Dockerfile
FROM python:3.11-slim AS builder  # Use minimal base

# Create non-root user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim
RUN useradd -m -u 1000 appuser

# Copy from builder
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --chown=appuser:appuser . /app

# Security hardening
USER appuser
WORKDIR /app

# Health check
HEALTHCHECK CMD curl -f http://localhost:5000/health || exit 1

# Run
CMD ["python", "app.py"]
```

### 7. Incident Response

```yaml
When Security Issue Found in Production:
  1. Assess severity (CVSS score, exploitability)
  2. Contain (block traffic if needed)
  3. Create hotfix branch
  4. Deploy fix through pipeline
  5. Verify fix
  6. Post-mortem
  7. Update security tests to prevent recurrence
```

---

## Complete Pipeline YAML Example

```yaml
name: Complete DevSecOps Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly security scan

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: GitLeaks Scan
        uses: gitleaks/gitleaks-action@v2

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install bandit semgrep

      - name: Bandit Scan
        run: bandit -r . -f json -o bandit-report.json || true

      - name: Semgrep Scan
        run: semgrep --config=auto --json -o semgrep.json || true

      - name: Upload SAST Results
        uses: actions/upload-artifact@v3
        with:
          name: sast-reports
          path: |
            bandit-report.json
            semgrep.json

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Safety Check
        run: |
          pip install safety
          safety check --json || true

      - name: Trivy FS Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'

  test:
    runs-on: ubuntu-latest
    needs: [secrets-scan, sast, sca]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Run tests
        run: pytest --cov=app --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t devsecops-demo:${{ github.sha }} .

      - name: Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile

      - name: Trivy Image Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'devsecops-demo:${{ github.sha }}'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'

  dast:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4

      - name: Start Application
        run: docker-compose up -d

      - name: Wait for app
        run: sleep 10

      - name: OWASP ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:5000'

  deploy:
    runs-on: ubuntu-latest
    needs: [build, dast]
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - name: Deploy to Production
        run: echo "Deploying to production..."
```

---

## Additional Resources

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [DevSecOps Maturity Model](https://dsomm.timo-pagel.de/)
- [NIST DevSecOps Guide](https://csrc.nist.gov/publications)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
