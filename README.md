# DevSecOps Demo Project

A simple demonstration project showcasing DevSecOps practices and tools for educational purposes.

## Overview

This project demonstrates key DevSecOps concepts through a simple Flask web application with integrated security scanning, automated testing, and CI/CD pipeline.

## What is DevSecOps?

**DevSecOps** = Development + Security + Operations

It's the practice of integrating security practices into the DevOps process, making security a shared responsibility throughout the entire software development lifecycle.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DevSecOps Pipeline                           │
└─────────────────────────────────────────────────────────────────────┘

┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   Code   │───▶│ Security │───▶│   Test   │───▶│  Build   │───▶│  Deploy  │
│  Commit  │    │   Scan   │    │          │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                     │                │               │               │
                     ├─ Bandit        ├─ pytest       ├─ Docker       └─ Production
                     ├─ Safety        └─ Coverage     └─ Trivy
                     └─ GitLeaks

┌─────────────────────────────────────────────────────────────────────┐
│                      Application Architecture                        │
└─────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │   Browser   │
    └──────┬──────┘
           │ HTTP
           ▼
    ┌─────────────┐
    │   Docker    │
    │  Container  │
    ├─────────────┤
    │ Non-root    │
    │   User      │
    │             │
    │ ┌─────────┐ │
    │ │  Flask  │ │ ◀─── Health Check
    │ │   App   │ │
    │ └─────────┘ │
    │             │
    │ Port: 5000  │
    └─────────────┘
```

## Complete DevSecOps Pipeline Flow

```
┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: PLAN & DEVELOP                                                   │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ IDE Security Plugins (SonarLint, Snyk)
    ├─▶ Pre-commit Hooks (git-secrets, detect-secrets)
    └─▶ Code Review (Pull Request)

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: SOURCE CODE MANAGEMENT                                           │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ Git Push Triggers Pipeline
    └─▶ Branch Protection Rules

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: BUILD (CI)                                                       │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ 🔒 SECURITY SCANNING
    │   ├─ SAST (Bandit, SonarQube, Semgrep)
    │   ├─ SCA - Software Composition Analysis (Safety, Snyk, WhiteSource)
    │   ├─ Secrets Scanning (GitLeaks, TruffleHog, git-secrets)
    │   └─ License Compliance (FOSSA, Black Duck)
    │
    ├─▶ 🧪 TESTING
    │   ├─ Unit Tests (pytest, unittest)
    │   ├─ Integration Tests
    │   ├─ Code Coverage (coverage.py, pytest-cov)
    │   └─ Linting (flake8, pylint, black)
    │
    └─▶ 📦 BUILD ARTIFACTS
        ├─ Docker Image Build
        └─ Artifact Repository (Harbor, Artifactory)

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: SECURITY TESTING                                                 │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ 🐳 CONTAINER SECURITY
    │   ├─ Image Scanning (Trivy, Clair, Anchore)
    │   ├─ Dockerfile Linting (hadolint)
    │   └─ Image Signing (Notary, Cosign)
    │
    ├─▶ 🌐 DAST (Dynamic Application Security Testing)
    │   ├─ OWASP ZAP
    │   ├─ Burp Suite
    │   └─ Nikto
    │
    └─▶ 🏗️ INFRASTRUCTURE SECURITY
        ├─ IaC Scanning (Checkov, tfsec, Terrascan)
        ├─ Kubernetes Security (kubesec, kube-bench)
        └─ Cloud Security (Prowler, ScoutSuite)

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: DEPLOY (CD)                                                      │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ 🎯 STAGING DEPLOYMENT
    │   ├─ Smoke Tests
    │   ├─ Security Regression Tests
    │   └─ Performance Tests (JMeter, Locust)
    │
    └─▶ 🚀 PRODUCTION DEPLOYMENT
        ├─ Blue/Green Deployment
        ├─ Canary Deployment
        └─ Rolling Updates

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 6: OPERATE & MONITOR                                                │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ 📊 MONITORING
    │   ├─ Application Monitoring (Prometheus, Grafana, Datadog)
    │   ├─ Log Analysis (ELK Stack, Splunk)
    │   └─ Uptime Monitoring (Pingdom, UptimeRobot)
    │
    ├─▶ 🛡️ RUNTIME SECURITY
    │   ├─ Runtime Application Self-Protection (RASP)
    │   ├─ Web Application Firewall (WAF)
    │   ├─ Intrusion Detection (Falco, OSSEC)
    │   └─ API Security (API Gateway, Rate Limiting)
    │
    └─▶ 🔄 CONTINUOUS COMPLIANCE
        ├─ Vulnerability Management (Nessus, Qualys)
        ├─ Compliance Scanning (OpenSCAP, InSpec)
        ├─ Security Auditing
        └─ Incident Response

                            ↓

┌───────────────────────────────────────────────────────────────────────────┐
│ PHASE 7: FEEDBACK LOOP                                                    │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ├─▶ Security Metrics & KPIs
    ├─▶ Vulnerability Tracking & Remediation
    ├─▶ Security Training & Awareness
    └─▶ Process Improvement

        └──────────────▶ Back to PHASE 1
```

## DevSecOps Tools Comparison

### 1. SAST (Static Application Security Testing)

| Tool | Language Support | Pros | Cons | Cost |
|------|-----------------|------|------|------|
| **Bandit** | Python | Fast, easy to integrate | Python only | Free |
| **SonarQube** | 25+ languages | Comprehensive, great UI | Resource intensive | Free/Paid |
| **Semgrep** | 20+ languages | Fast, customizable rules | Newer tool | Free/Paid |
| **Checkmarx** | 25+ languages | Enterprise features | Expensive | Paid |
| **Veracode** | 20+ languages | Cloud-based, accurate | Costly | Paid |

### 2. SCA (Software Composition Analysis)

| Tool | Features | Database | Integration | Cost |
|------|----------|----------|-------------|------|
| **Safety** | Python deps | CVE database | CLI, CI/CD | Free/Paid |
| **Snyk** | Multi-language | Comprehensive | Excellent | Free/Paid |
| **WhiteSource** | License compliance | Large DB | Enterprise | Paid |
| **OWASP Dependency-Check** | Multi-language | NVD database | Maven, Gradle | Free |
| **npm audit** | JavaScript/Node | npm registry | Built-in npm | Free |

### 3. Container Security

| Tool | Speed | Accuracy | Registries | Cost |
|------|-------|----------|------------|------|
| **Trivy** | Very Fast | High | All major | Free |
| **Clair** | Fast | Good | Docker, Quay | Free |
| **Anchore** | Medium | High | Multi-registry | Free/Paid |
| **Aqua Security** | Fast | Very High | Enterprise | Paid |
| **Prisma Cloud** | Fast | High | Cloud-native | Paid |

### 4. DAST (Dynamic Application Security Testing)

| Tool | Automation | Coverage | Reporting | Cost |
|------|-----------|----------|-----------|------|
| **OWASP ZAP** | Good | Comprehensive | Detailed | Free |
| **Burp Suite** | Excellent | Extensive | Professional | Free/Paid |
| **Nikto** | Basic | Web servers | Simple | Free |
| **Acunetix** | Advanced | Deep | Rich | Paid |
| **Netsparker** | Excellent | Comprehensive | Detailed | Paid |

### 5. Secrets Scanning

| Tool | Detection | Integration | False Positives | Cost |
|------|-----------|-------------|-----------------|------|
| **GitLeaks** | Regex-based | Git hooks, CI/CD | Medium | Free |
| **TruffleHog** | Entropy analysis | Git history | Low | Free |
| **git-secrets** | AWS-focused | Pre-commit | Low | Free |
| **Detect-secrets** | Multiple methods | Pre-commit | Low | Free |
| **GitGuardian** | ML-based | Comprehensive | Very Low | Paid |

## Project Components

### 1. Application ([app.py](app.py))
- Simple Flask web application
- RESTful API endpoints
- Input validation and security best practices
- Health check endpoint for monitoring

### 2. Security Scanning

#### SAST (Static Application Security Testing)
- **Bandit**: Python security linter
- Scans code for common security issues
- Configuration: [.bandit](.bandit)

#### Dependency Scanning
- **Safety**: Checks Python dependencies for known vulnerabilities
- Uses vulnerability database
- Configuration: [.safety-policy.yml](.safety-policy.yml)

### 3. Testing ([test_app.py](test_app.py))
- Unit tests with pytest
- Code coverage reporting
- Automated test execution in CI/CD

### 4. CI/CD Pipeline ([.github/workflows/devsecops-pipeline.yml](.github/workflows/devsecops-pipeline.yml))

Pipeline stages:
1. **Security Scan**: SAST and dependency checking
2. **Test**: Unit tests with coverage
3. **Build**: Docker image creation
4. **Deploy**: Simulated deployment

### 5. Container Security ([Dockerfile](Dockerfile))

Security features:
- Multi-stage build (smaller attack surface)
- Non-root user
- Read-only filesystem where possible
- Health checks
- Minimal base image

## Getting Started

### Prerequisites
- Python 3.11+
- Docker (optional)
- Git

### Local Development

1. **Clone the repository**
   ```bash
   cd devsecops-demo
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

   Visit: http://localhost:5000

### Running Security Scans

**Bandit (SAST)**
```bash
bandit -r . -f txt
```

**Safety (Dependency Check)**
```bash
safety check
```

### Running Tests

**Run all tests**
```bash
pytest
```

**With coverage**
```bash
pytest --cov=app --cov-report=html
```

### Docker Deployment

**Build and run with Docker**
```bash
docker build -t devsecops-demo .
docker run -p 5000:5000 devsecops-demo
```

**Or use Docker Compose**
```bash
docker-compose up
```

**Scan Docker image with Trivy**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image devsecops-demo:latest
```

## Lecture Demonstration Points

### 1. Security Shift-Left
- Security integrated from the start
- Automated security checks in pipeline
- Fast feedback on security issues

### 2. Automation
- Automated testing
- Automated security scanning
- Automated deployment

### 3. Continuous Monitoring
- Health checks
- Security vulnerability scanning
- Code coverage metrics

### 4. Container Security Best Practices
- Non-root user execution
- Minimal base images
- Multi-stage builds
- Security scanning with Trivy

### 5. Pipeline Stages
- Each stage validates different aspects
- Fast failure for quick feedback
- Artifacts preserved for analysis

## Key DevSecOps Principles Demonstrated

1. **Security as Code**: Security configurations in version control
2. **Automation**: Automated security and quality checks
3. **Continuous Security**: Security checks at every stage
4. **Visibility**: Reports and artifacts for analysis
5. **Collaboration**: Security integrated into development workflow

## Common Security Issues to Discuss

1. **Input Validation**: Protecting against injection attacks
2. **Dependency Vulnerabilities**: Outdated libraries
3. **Container Security**: Running as root, exposed secrets
4. **Authentication/Authorization**: Proper access controls
5. **Secrets Management**: Never commit credentials

## Extending the Demo

Ideas for further exploration:
- Add secrets scanning (e.g., TruffleHog, GitLeaks)
- Integrate DAST tools (e.g., OWASP ZAP)
- Add infrastructure scanning (e.g., Checkov for IaC)
- Implement security gates (fail on HIGH/CRITICAL)
- Add monitoring and logging (e.g., ELK stack)
- Implement SBOM (Software Bill of Materials)

## Tools Used

| Tool | Purpose | Type |
|------|---------|------|
| Bandit | Code security scanning | SAST |
| Safety | Dependency vulnerability check | SCA |
| Trivy | Container vulnerability scanning | Container Security |
| pytest | Unit testing | Testing |
| GitHub Actions | CI/CD pipeline | Automation |
| Docker | Containerization | Deployment |

## Resources

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

## License

This project is for educational purposes only.

## Discussion Questions for Students

1. Why is it important to integrate security early in the development process?
2. What are the benefits of automating security checks?
3. How does DevSecOps differ from traditional security approaches?
4. What security issues might Bandit detect in Python code?
5. Why should containers run as non-root users?
6. What happens if a security scan finds a critical vulnerability?
7. How can we balance security with development speed?

---

**Note**: This is a simplified demonstration. Production systems require additional security measures including secrets management, comprehensive monitoring, incident response procedures, and compliance controls.
